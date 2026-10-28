defmodule SSL.TLS12SessionCacheTest do
  use ExUnit.Case, async: true

  alias SSL.{SessionCache, TLS12Session}

  test "automatic lookup excludes save-only entries while explicit IDs remain reusable" do
    cache = start_supervised!({SessionCache, name: nil})
    key = <<1::256>>
    saved = session(<<1>>, false)
    automatic = session(<<2>>, true)
    assert :ok = SessionCache.put(key, saved, cache)
    assert :miss = SessionCache.lookup(key, :auto, cache)
    assert {:ok, ^saved} = SessionCache.lookup(key, <<1>>, cache)
    assert :ok = SessionCache.put(key, automatic, cache)
    assert {:ok, ^automatic} = SessionCache.lookup(key, :auto, cache)
    assert {:ok, ^saved} = SessionCache.lookup(key, <<1>>, cache)
    assert {:ok, ^saved} = SessionCache.lookup(key, <<1>>, cache)
    assert :miss = SessionCache.lookup(<<2::256>>, <<1>>, cache)
    assert %{count: 2} = SessionCache.stats(cache)
  end

  test "retained material is owned and status, master and session IDs are redacted" do
    cache = start_supervised!({SessionCache, name: nil})
    key = :crypto.hash(:sha256, "partition-secret-marker")
    backing = :binary.copy(<<8>>, 1_048_576)
    slice = binary_part(backing, 64, 16_000)
    candidate = %{session("id-secret-marker", true) | peer: %{chain: [slice], decoded: slice}}
    assert :ok = SessionCache.put(key, candidate, cache)
    {:ok, retained} = SessionCache.lookup(key, :auto, cache)
    assert Map.keys(retained.peer) == [:chain]
    assert :binary.referenced_byte_size(hd(retained.peer.chain)) == 16_000
    refute inspect(candidate) =~ "id-secret-marker"
    status = inspect(:sys.get_status(cache), limit: :infinity, printable_limit: :infinity)
    refute status =~ "id-secret-marker"
    refute status =~ inspect(key)
    refute status =~ "master-secret-marker"
  end

  test "absolute expiry, bounded count/bytes and a single tokened cleanup timer" do
    cache = start_supervised!({SessionCache, name: nil})
    key = <<3::256>>
    for n <- 1..129, do: assert(:ok = SessionCache.put(key, session(<<n::16>>, true), cache))
    assert %{count: 128, bytes: bytes} = SessionCache.stats(cache)
    assert bytes <= 4_194_304
    assert :miss = SessionCache.lookup(key, <<1::16>>, cache)
    first = :sys.get_state(cache)
    assert is_integer(Process.read_timer(first.timer_ref))

    :sys.replace_state(cache, fn state ->
      entries =
        Map.new(state.entries, fn {k, {session, size, order}} ->
          {k, {%{session | expires_at: System.monotonic_time(:millisecond) - 1}, size, order}}
        end)

      %{state | entries: entries}
    end)

    send(cache, {:cleanup, first.timer_token})
    assert %{count: 0, bytes: 0} = SessionCache.stats(cache)
    next = :sys.get_state(cache)
    assert Process.read_timer(first.timer_ref) == false
    refute next.timer_token == first.timer_token
    send(cache, {:cleanup, first.timer_token})
    send(cache, :cleanup)
    assert SessionCache.stats(cache) == %{count: 0, bytes: 0}
    assert :sys.get_state(cache).timer_token == next.timer_token

    large = %{session(<<0>>, true) | peer: %{chain: [:binary.copy(<<7>>, 100_000)]}}
    for n <- 1..50, do: assert(:ok = SessionCache.put(key, %{large | id: <<n>>}, cache))
    assert %{count: count, bytes: retained} = SessionCache.stats(cache)
    assert count < 50
    assert retained <= 4_194_304
  end

  test "unavailable caches take a bounded miss and invalid material is rejected" do
    cache = start_supervised!({SessionCache, name: nil})
    key = <<4::256>>
    candidate = session(<<1>>, true)

    assert {:error, :invalid_session} =
             SessionCache.put(key, %{candidate | master_secret: <<>>}, cache)

    assert {:error, :invalid_session} =
             SessionCache.put(
               key,
               %{candidate | expires_at: candidate.issued_at + 600_001},
               cache
             )

    assert :ok = :sys.suspend(cache)

    try do
      start = System.monotonic_time(:millisecond)
      assert :miss = SessionCache.lookup(key, :auto, cache)
      assert System.monotonic_time(:millisecond) - start < 2000
    after
      :sys.resume(cache)
    end

    assert :miss = SessionCache.lookup(key, :auto, :missing_tls12_cache)
    assert {:error, :cache_unavailable} = SessionCache.put(key, candidate, :missing_tls12_cache)
  end

  test "capability references are context/id bound and stale tokens cannot select an entry" do
    cache = start_supervised!({SessionCache, name: nil})
    key = <<6::256>>
    data = <<"EXSSL12", 1, 1::256>>
    candidate = %{session(<<7>>, false) | data: data}
    assert :ok = SessionCache.put(key, candidate, cache)
    assert {:ok, _} = SessionCache.lookup(key, {candidate.id, data}, cache)
    assert :miss = SessionCache.lookup(<<8::256>>, {candidate.id, data}, cache)
    assert :miss = SessionCache.lookup(key, {<<9>>, data}, cache)
    assert :miss = SessionCache.lookup(key, {candidate.id, <<"EXSSL12", 1, 2::256>>}, cache)
    refute inspect(candidate) =~ "EXSSL12"
    replacement = %{candidate | data: <<"EXSSL12", 1, 3::256>>}
    assert :ok = SessionCache.put(key, replacement, cache)
    assert :miss = SessionCache.lookup(key, {candidate.id, data}, cache)
    assert {:ok, _} = SessionCache.lookup(key, {candidate.id, replacement.data}, cache)
  end

  defp session(id, auto) do
    now = System.monotonic_time(:millisecond)

    %TLS12Session{
      id: id,
      master_secret: :binary.copy("master-secret-marker", 3) |> binary_part(0, 48),
      suite: 0xC02F,
      peer: %{chain: [<<1, 2, 3>>]},
      alpn: nil,
      issued_at: now,
      expires_at: now + 60_000,
      auto: auto
    }
  end
end
