defmodule SSL.Protocol.FragmentedFuzzTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.{
    ClientOffer,
    HandshakeFramer,
    RecordFramer,
    Resumption,
    TLS12Codec,
    TLS12Record
  }

  alias SSL.SessionTicket

  @client_hello Base.decode16!(
                  "0100008c03030000000000000000000000000000000000000000000000000000000000000000000002130101000061002b0003020304000a00040002001d000d000400020804003300070005001d000107002d00020101002900350010000a7469636b65742d6f6e65000000110021200000000000000000000000000000000000000000000000000000000000000000",
                  case: :lower
                )

  test "all bounded chunkings preserve a mixed TLS 1.2 handshake stream and suffix" do
    random = :binary.copy(<<42>>, 32)
    hello = frame(2, <<3, 3, random::binary, 0, 0xC02F::16, 0, 0::16>>)
    ske = frame(12, <<3, 0x0017::16, 3, 4, 5, 6, 0x0403::16, 2::16, 9, 10>>)
    done = frame(14, <<>>)
    finished = frame(20, :binary.copy(<<7>>, 12))
    expected = [hello, ske, done, finished]
    suffix = <<11, 0, 0>>
    stream = IO.iodata_to_binary(expected) <> suffix

    for chunk_size <- 1..37 do
      {actual, framer} =
        stream
        |> chunks(chunk_size)
        |> Enum.reduce({[], HandshakeFramer.new()}, fn chunk, {messages, framer} ->
          assert {:ok, produced, framer} = HandshakeFramer.feed(framer, chunk)
          assert HandshakeFramer.buffered_size(framer) <= byte_size(stream)
          {messages ++ produced, framer}
        end)

      assert actual == expected
      assert HandshakeFramer.buffered_bytes(framer) == suffix

      assert Enum.map(actual, fn encoded ->
               {:ok, message} = TLS12Codec.decode(encoded)
               message.type
             end) ==
               [:server_hello, :server_key_exchange, :server_hello_done, :finished]
    end
  end

  test "bounded record chunkings preserve TLS 1.2 AEAD sequence and incomplete header" do
    {:ok, state} = TLS12Record.new(:aes_128_gcm, <<1::128>>, <<2::32>>)
    {:ok, first, state_1} = TLS12Record.encrypt(state, :handshake, "first")
    {:ok, second, _state_2} = TLS12Record.encrypt(state_1, :application_data, "second")
    suffix = <<23, 3, 3, 0>>
    stream = first <> second <> suffix

    for chunk_size <- 1..31 do
      {records, framer} =
        stream
        |> chunks(chunk_size)
        |> Enum.reduce({[], RecordFramer.new()}, fn chunk, {records, framer} ->
          assert {:ok, produced, framer} = RecordFramer.feed(framer, chunk)
          assert RecordFramer.buffered_size(framer) <= byte_size(stream)
          {records ++ produced, framer}
        end)

      assert records == [first, second]
      assert RecordFramer.buffered_bytes(framer) == suffix
      assert {:ok, :handshake, "first", state_1} = TLS12Record.decrypt(state, first)

      assert {:ok, :application_data, "second", %{sequence: 2}} =
               TLS12Record.decrypt(state_1, second)
    end
  end

  property "200 bounded mutations of valid TLS 1.2 messages remain tagged and exact" do
    hello = frame(2, <<3, 3, 0::256, 0, 0xC02F::16, 0, 0::16>>)
    request = frame(13, <<1, 1, 2::16, 0x0403::16, 0::16>>)
    finished = frame(20, :binary.copy(<<5>>, 12))
    corpus = [hello, request, finished]

    check all(
            sample <- member_of(corpus),
            index <- integer(0..(byte_size(sample) - 1)),
            delta <- integer(1..255),
            suffix <- binary(max_length: 4),
            max_runs: 200
          ) do
      changed = flip(sample, index, delta)

      for input <- [changed, binary_part(sample, 0, index), sample <> suffix] do
        case TLS12Codec.decode(input) do
          {:ok, %{encoded: ^input}} -> :ok
          {:error, _reason} -> :ok
          other -> flunk("unexpected codec result: #{inspect(other)}")
        end
      end
    end
  end

  property "200 bounded TLS 1.2 record mutations never authenticate" do
    {:ok, state} = TLS12Record.new(:aes_128_gcm, <<3::128>>, <<4::32>>)
    {:ok, wire, _} = TLS12Record.encrypt(state, :application_data, "authenticated")

    check all(
            index <- integer(0..(byte_size(wire) - 1)),
            delta <- integer(1..255),
            max_runs: 200
          ) do
      assert {:error, _reason} = TLS12Record.decrypt(state, flip(wire, index, delta))
    end
  end

  property "200 malformed or mutated binder ClientHellos return structured results" do
    ticket = ticket()
    assert {:ok, original} = Resumption.bind(@client_hello, ticket)
    assert {:ok, _} = ClientOffer.from_client_hello(original)

    check all(
            index <- integer(0..(byte_size(@client_hello) - 1)),
            delta <- integer(1..255),
            prefix <- binary(max_length: 16),
            max_runs: 200
          ) do
      for input <- [
            flip(@client_hello, index, delta),
            binary_part(@client_hello, 0, index),
            @client_hello <> <<delta>>
          ] do
        case Resumption.bind(input, ticket, prefix) do
          {:ok, bound} ->
            assert byte_size(bound) == byte_size(input)
            assert {:ok, _offer} = ClientOffer.from_client_hello(bound)

          {:error, _reason} ->
            :ok
        end
      end
    end
  end

  defp ticket do
    now = System.monotonic_time(:millisecond)

    %SessionTicket{
      ticket: "ticket-one",
      psk: :binary.list_to_bin(Enum.to_list(0..31)),
      hash: :sha256,
      age_add: 7,
      issued_at: now - 10,
      expires_at: now + 60_000,
      peer: %{chain: [<<1, 2, 3>>]},
      alpn: "h2"
    }
  end

  defp frame(type, body), do: <<type, byte_size(body)::24, body::binary>>

  defp flip(bytes, index, delta) do
    <<prefix::binary-size(^index), byte, suffix::binary>> = bytes
    <<prefix::binary, Bitwise.bxor(byte, delta), suffix::binary>>
  end

  defp chunks(bytes, size),
    do: for(<<chunk::binary-size(^size) <- bytes>>, do: chunk) ++ tail(bytes, size)

  defp tail(bytes, size) do
    remainder = rem(byte_size(bytes), size)
    if remainder == 0, do: [], else: [binary_part(bytes, byte_size(bytes) - remainder, remainder)]
  end
end
