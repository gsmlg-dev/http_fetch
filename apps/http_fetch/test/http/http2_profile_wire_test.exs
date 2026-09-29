defmodule HTTP.HTTP2ProfileWireTest do
  use ExUnit.Case, async: false

  alias HTTP.HTTP2.HPACK

  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  test "native_v1 cold and warm public wire keeps input order without legacy priority" do
    assert_profile(
      :native_v1,
      <<2::16, 0::32>>,
      [{"x-second", "two"}, {"x-first", "one"}],
      ["x-second", "x-first"],
      :none
    )
  end

  test "synthetic_test_v1 cold and warm wire sorts headers and sends legacy priority" do
    assert_profile(
      :synthetic_test_v1,
      <<4::16, 131_072::32, 1::16, 8192::32, 2::16, 0::32>>,
      [{"x-second", "two"}, {"x-first", "one"}],
      ["x-first", "x-second"],
      :legacy
    )
  end

  test "synthetic_test_v2 cold and warm wire reverses input once and sends RFC 9218 header" do
    assert_profile(
      :synthetic_test_v2,
      <<5::16, 32_768::32, 4::16, 65_535::32, 2::16, 0::32>>,
      [{"x-first", "one"}, {"x-second", "two"}],
      ["x-second", "x-first"],
      :rfc9218
    )
  end

  defp assert_profile(profile, expected_settings, request_headers, ordered_names, priority) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)
    parent = self()

    server =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), 2_000)
        send(parent, {:client_settings, recv_frame(socket)})
        :ok = :gen_tcp.send(socket, <<0::24, 4, 0, 0::32>>)

        for number <- 1..2 do
          {headers, preceding} = receive_headers(socket, [])
          send(parent, {:request_wire, number, headers, preceding})
          {1, _flags, id, _block} = headers
          :ok = :gen_tcp.send(socket, <<1::24, 1, 5, id::32, 0x88>>)
        end

        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :kill)
      :gen_tcp.close(listener)
    end)

    url = "http://127.0.0.1:#{port}/profile"

    for number <- 1..2, reduce: HPACK.new_decoder() do
      decoder ->
        response =
          url
          |> HTTP.fetch(
            http_version: :h2c,
            http2_profile: profile,
            headers: request_headers,
            timeout: 2_000
          )
          |> HTTP.Promise.await()

        assert response.status == 200
        assert_receive {:request_wire, ^number, {1, flags, id, block}, preceding}, 2_000
        assert id == number * 2 - 1
        assert Bitwise.band(flags, 0x5) == 0x5
        assert_priority_frames(preceding, id, priority)
        assert_window_update(preceding, number, profile)
        assert_raw_regular_order(block, ordered_names, profile)

        assert {:ok, decoder, headers} = HPACK.decode(decoder, block)
        names = Enum.map(headers, &elem(&1, 0))
        assert Enum.take(names, 4) == pseudo_order(profile)
        assert Enum.filter(names, &(&1 in ["x-first", "x-second"])) == ordered_names

        if priority == :rfc9218 do
          assert length(:binary.matches(block, "priority")) == 1

          assert Enum.count(headers, fn {name, value} ->
                   name == "priority" and value == "u=3"
                 end) == 1
        else
          refute Enum.any?(headers, fn {name, _} -> name == "priority" end)
        end

        decoder
    end

    assert_receive {:client_settings, {4, 0, 0, ^expected_settings}}
    assert :binary.match(expected_settings, <<2::16, 0::32>>) != :nomatch
  end

  defp assert_priority_frames(preceding, id, :legacy) do
    priorities = Enum.filter(preceding, fn {type, _, _, _} -> type == 2 end)
    assert priorities == [{2, 0, id, <<0::1, 0::31, 15>>}]
  end

  defp assert_priority_frames(preceding, _id, _priority) do
    refute Enum.any?(preceding, fn {type, _, _, _} -> type == 2 end)
  end

  defp assert_window_update(preceding, 1, :synthetic_test_v1) do
    assert Enum.filter(preceding, fn {type, _, _, _} -> type == 8 end) ==
             [{8, 0, 0, <<65_536::32>>}]
  end

  defp assert_window_update(preceding, _number, _profile) do
    refute Enum.any?(preceding, fn {type, _, _, _} -> type == 8 end)
  end

  defp assert_raw_regular_order(block, [first, second], profile) do
    [{first_at, _}] = :binary.matches(block, encoded_name(first, profile))
    [{second_at, _}] = :binary.matches(block, encoded_name(second, profile))
    assert first_at < second_at
  end

  # Huffman name bytes independently checked with Python hpack 4.1.0.
  defp encoded_name("x-first", :synthetic_test_v1), do: <<0xF2, 0xB4, 0xA6, 0xB1, 0x09>>
  defp encoded_name("x-second", :synthetic_test_v1), do: <<0xF2, 0xB2, 0x0A, 0x43, 0xD5, 0x27>>
  defp encoded_name(name, _profile), do: name

  defp pseudo_order(:native_v1), do: [":method", ":scheme", ":authority", ":path"]
  defp pseudo_order(:synthetic_test_v1), do: [":method", ":path", ":scheme", ":authority"]
  defp pseudo_order(:synthetic_test_v2), do: [":method", ":authority", ":scheme", ":path"]

  defp receive_headers(socket, preceding) do
    case recv_frame(socket) do
      {1, _flags, _id, _block} = headers -> {headers, Enum.reverse(preceding)}
      other -> receive_headers(socket, [other | preceding])
    end
  end

  defp recv_frame(socket) do
    {:ok, <<length::24, type, flags, id::32>>} = :gen_tcp.recv(socket, 9, 2_000)

    payload =
      if length == 0 do
        <<>>
      else
        {:ok, data} = :gen_tcp.recv(socket, length, 2_000)
        data
      end

    {type, flags, id, payload}
  end
end
