defmodule SSL.ResumptionTest do
  use ExUnit.Case, async: true

  alias SSL.{SessionTicket, TicketCache}
  alias SSL.Protocol.Resumption

  @client_hello Base.decode16!(
                  "0100008c03030000000000000000000000000000000000000000000000000000000000000000000002130101000061002b0003020304000a00040002001d000d000400020804003300070005001d000107002d00020101002900350010000a7469636b65742d6f6e65000000110021200000000000000000000000000000000000000000000000000000000000000000",
                  case: :lower
                )
  @binder Base.decode16!("7eb0018a83608b1e9cc57a70955913ba03779fbd932fd3a0f2383ad3386a2663",
            case: :lower
          )
  @hrr_prefix Base.decode16!(
                "fe000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0200000103",
                case: :lower
              )
  @hrr_binder Base.decode16!("e8c8223111ca8fa0ba1b5c0dfb12ee836ad83529d91416bd65d8d521bb9a9650",
                case: :lower
              )
  # Independently calculated with Python 3 stdlib hashlib/hmac RFC 8446 HKDF-Expand-Label;
  # CH2 changes its key_share byte from 07 to 08 while retaining the HRR prefix.
  @changed_ch2_binder Base.decode16!(
                        "e720cce6b62c400f9a624c7a52516f91f563ca49390b6fa1405bff0144da14f5",
                        case: :lower
                      )

  defp ticket(overrides \\ %{}) do
    now = System.monotonic_time(:millisecond)

    struct!(
      SessionTicket,
      Map.merge(
        %{
          ticket: "ticket-one",
          psk: :binary.list_to_bin(Enum.to_list(0..31)),
          hash: :sha256,
          age_add: 7,
          issued_at: now - 10,
          expires_at: now + 60_000,
          peer: %{chain: [<<1, 2, 3>>]},
          alpn: "h2"
        },
        overrides
      )
    )
  end

  test "single-ticket binder matches independently computed Python HMAC/HKDF vectors" do
    assert {:ok, bound} = Resumption.bind(@client_hello, ticket())
    assert binary_part(bound, byte_size(bound) - 32, 32) == @binder

    assert {:ok, bound_hrr} = Resumption.bind(@client_hello, ticket(), @hrr_prefix)
    assert binary_part(bound_hrr, byte_size(bound_hrr) - 32, 32) == @hrr_binder
    refute bound == bound_hrr
  end

  test "HRR binder binds changed second ClientHello key share" do
    original = Base.decode16!("003300070005001d000107", case: :lower)
    changed = Base.decode16!("003300070005001d000108", case: :lower)
    assert :binary.matches(@client_hello, original) |> length() == 1
    client_hello_2 = :binary.replace(@client_hello, original, changed)

    assert :crypto.hash(:sha256, client_hello_2) ==
             Base.decode16!("746522d89a41ec7c6ec0a0a0506a7aff19379780518c20fe2db20143036c9d38",
               case: :lower
             )

    assert {:ok, bound} = Resumption.bind(client_hello_2, ticket(), @hrr_prefix)
    assert binary_part(bound, byte_size(bound) - 32, 32) == @changed_ch2_binder
    refute @changed_ch2_binder == @hrr_binder
  end

  test "ticket age wraps and expired tickets are rejected" do
    t = ticket(%{issued_at: 100, expires_at: 10_000, age_add: 0xFFFFFFFF})
    assert {:ok, payload} = Resumption.psk_extension(t, 102)
    assert <<_::16, 10::16, _::binary-size(10), 1::32, _::binary>> = payload
    assert {:error, :expired} = Resumption.psk_extension(t, 10_000)
    assert {:error, :expired} = Resumption.psk_extension(t, 99)
  end

  test "malformed or mismatched binder input is rejected" do
    assert {:error, _} = Resumption.bind(@client_hello <> <<0>>, ticket())

    assert {:error, :ticket_identity_mismatch} =
             Resumption.bind(@client_hello, ticket(%{ticket: "other"}))

    assert {:error, :invalid_binder_placeholder} =
             Resumption.bind(
               binary_part(@client_hello, 0, byte_size(@client_hello) - 1) <> <<1>>,
               ticket()
             )
  end

  test "ticket validation rejects malformed bounds and redacts secrets" do
    t = ticket()
    assert :ok = SessionTicket.validate(t)
    refute inspect(t) =~ "ticket-one"
    assert {:error, :invalid_psk} = SessionTicket.validate(%{t | psk: <<1>>})

    assert {:error, :invalid_lifetime} =
             SessionTicket.validate(%{t | expires_at: t.issued_at + 604_800_001})

    assert {:error, :invalid_peer} = SessionTicket.validate(%{t | peer: %{chain: []}})

    assert {:error, :ticket_too_large} =
             SessionTicket.validate(%{t | peer: %{chain: [:binary.copy(<<1>>, 263_000)]}})
  end

  test "one-use checkout is atomic under contention and partitions are isolated" do
    {:ok, cache} = TicketCache.start_link(name: nil)
    on_exit(fn -> if Process.alive?(cache), do: GenServer.stop(cache) end)
    key = :binary.copy(<<1>>, 32)
    other = :binary.copy(<<2>>, 32)
    assert :ok = TicketCache.put(key, ticket(), cache)
    assert :miss = TicketCache.checkout(other, cache)

    results =
      1..20
      |> Task.async_stream(fn _ -> TicketCache.checkout(key, cache) end)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Enum.count(results, &(&1 == :miss)) == 19
  end

  test "replacement, expiry, and 128-entry bound" do
    {:ok, cache} = TicketCache.start_link(name: nil)
    on_exit(fn -> if Process.alive?(cache), do: GenServer.stop(cache) end)
    key = :binary.copy(<<0>>, 32)
    assert :ok = TicketCache.put(key, ticket(), cache)
    assert :ok = TicketCache.put(key, ticket(%{ticket: "replacement"}), cache)
    assert %{count: 1} = TicketCache.stats(cache)
    assert {:ok, %{ticket: "replacement"}} = TicketCache.checkout(key, cache)

    now = System.monotonic_time(:millisecond)

    assert {:error, :expired} =
             TicketCache.put(key, ticket(%{issued_at: now - 2, expires_at: now - 1}), cache)

    for i <- 1..129 do
      assert :ok = TicketCache.put(<<i::256>>, ticket(), cache)
    end

    assert %{count: 128, bytes: bytes} = TicketCache.stats(cache)
    assert bytes <= 4_194_304
    assert :miss = TicketCache.checkout(<<1::256>>, cache)
  end

  test "retained serialized bytes stay within four MiB" do
    {:ok, cache} = TicketCache.start_link(name: nil)
    on_exit(fn -> if Process.alive?(cache), do: GenServer.stop(cache) end)
    large_peer = %{chain: [:binary.copy(<<8>>, 100_000)]}

    for i <- 1..50 do
      assert :ok = TicketCache.put(<<i::256>>, ticket(%{peer: large_peer}), cache)
    end

    assert %{count: count, bytes: bytes} = TicketCache.stats(cache)
    assert count < 50
    assert bytes <= 4_194_304
  end
end
