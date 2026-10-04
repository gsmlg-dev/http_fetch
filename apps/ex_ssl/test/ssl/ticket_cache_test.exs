defmodule SSL.TicketCacheTest do
  use ExUnit.Case, async: true

  alias SSL.{SessionTicket, TicketCache}

  defp ticket(overrides \\ %{}) do
    now = System.monotonic_time(:millisecond)

    struct!(
      SessionTicket,
      Map.merge(
        %{
          ticket: "secret-ticket-marker",
          psk: :binary.copy(<<73>>, 32),
          hash: :sha256,
          age_add: 7,
          issued_at: now - 1,
          expires_at: now + 60_000,
          peer: %{chain: [<<1, 2, 3>>]},
          alpn: "h2"
        },
        overrides
      )
    )
  end

  defp cache do
    {:ok, pid} = TicketCache.start_link(name: nil)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  test "small cached slices cannot retain oversized wire backing binaries" do
    {:ok, cache} = TicketCache.start_link(name: nil)
    backing = :binary.copy(<<9>>, 1_048_576)
    slice = binary_part(backing, 100, 16_000)
    assert :binary.referenced_byte_size(slice) == byte_size(backing)
    now = System.monotonic_time(:millisecond)

    ticket = %SessionTicket{
      ticket: slice,
      psk: :binary.copy(<<1>>, 32),
      hash: :sha256,
      age_add: 0,
      issued_at: now,
      expires_at: now + 60_000,
      alpn: "h2",
      peer: %{chain: [slice], decoded_reference: slice}
    }

    # Model the real cached VerifiedPeer carrying decoded certificate fields.
    # The input itself must still satisfy the entry-size limit.
    assert :ok = TicketCache.put(<<1::256>>, ticket, cache)
    assert {:ok, owned} = TicketCache.checkout(<<1::256>>, cache)
    assert Map.keys(owned.peer) == [:chain]
    assert :binary.referenced_byte_size(owned.ticket) == byte_size(owned.ticket)
    for der <- owned.peer.chain, do: assert(:binary.referenced_byte_size(der) == byte_size(der))
  end

  test "expiry removes entries on checkout and the sole cleanup timer" do
    pid = cache()
    key = <<1::256>>
    assert :ok = TicketCache.put(key, ticket(), pid)
    first = :sys.get_state(pid)
    assert is_reference(first.timer_ref)
    assert is_reference(first.timer_token)
    assert is_integer(Process.read_timer(first.timer_ref))

    expire_entry(pid, key)
    send(pid, {:cleanup, first.timer_token})
    assert %{count: 0, bytes: 0} = TicketCache.stats(pid)
    second = :sys.get_state(pid)
    refute second.timer_ref == first.timer_ref
    assert Process.read_timer(first.timer_ref) == false
    assert is_integer(Process.read_timer(second.timer_ref))

    send(pid, {:cleanup, first.timer_token})
    send(pid, :cleanup)
    assert %{count: 0, bytes: 0} = TicketCache.stats(pid)
    assert %{timer_ref: timer_ref, timer_token: timer_token} = :sys.get_state(pid)
    assert timer_ref == second.timer_ref
    assert timer_token == second.timer_token

    assert :ok = TicketCache.put(key, ticket(), pid)
    expire_entry(pid, key)
    assert :miss = TicketCache.checkout(key, pid)
    assert %{count: 0, bytes: 0} = TicketCache.stats(pid)
  end

  test "one-use checkout is atomic and replacement returns only the newer ticket" do
    pid = cache()
    key = <<2::256>>
    assert :ok = TicketCache.put(key, ticket(), pid)
    replacement = ticket(%{ticket: "replacement-ticket"})
    assert :ok = TicketCache.put(key, replacement, pid)
    assert %{count: 1} = TicketCache.stats(pid)

    results =
      1..64
      |> Task.async_stream(fn _ -> TicketCache.checkout(key, pid) end, max_concurrency: 64)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == {:ok, replacement})) == 1
    assert Enum.count(results, &(&1 == :miss)) == 63
    assert %{count: 0, bytes: 0} = TicketCache.stats(pid)
  end

  test "entry-count and retained-byte limits evict oldest entries" do
    pid = cache()

    for index <- 1..129 do
      assert :ok = TicketCache.put(<<index::256>>, ticket(), pid)
    end

    assert %{count: 128, bytes: bytes} = TicketCache.stats(pid)
    assert bytes <= 4_194_304
    assert :miss = TicketCache.checkout(<<1::256>>, pid)
    assert {:ok, _} = TicketCache.checkout(<<129::256>>, pid)

    large_peer = %{chain: [:binary.copy(<<8>>, 100_000)]}

    for index <- 1..50 do
      assert :ok = TicketCache.put(<<index::256>>, ticket(%{peer: large_peer}), pid)
    end

    assert %{count: count, bytes: retained} = TicketCache.stats(pid)
    assert count < 50
    assert retained <= 4_194_304
  end

  test "status and ticket inspection redact identity keys and ticket material" do
    pid = cache()
    key = :crypto.hash(:sha256, "secret-partition-marker")
    assert :ok = TicketCache.put(key, ticket(), pid)
    status = inspect(:sys.get_status(pid), limit: :infinity, printable_limit: :infinity)
    refute status =~ "secret-ticket-marker"
    refute status =~ Base.encode16(key)
    refute status =~ inspect(key)
    refute inspect(ticket()) =~ "secret-ticket-marker"
    refute inspect(ticket()) =~ inspect(:binary.copy(<<73>>, 32))
  end

  test "calls fail closed within a bounded time when cache is unavailable" do
    pid = cache()
    assert :ok = :sys.suspend(pid)

    try do
      started = System.monotonic_time(:millisecond)
      assert :miss = TicketCache.checkout(<<3::256>>, pid)
      assert System.monotonic_time(:millisecond) - started < 2_000
    after
      assert :ok = :sys.resume(pid)
    end

    assert :miss = TicketCache.checkout(<<3::256>>, :no_such_cache)
    assert {:error, :cache_unavailable} = TicketCache.put(<<3::256>>, ticket(), :no_such_cache)
  end

  defp expire_entry(pid, key) do
    :sys.replace_state(pid, fn state ->
      %{
        state
        | entries:
            Map.update!(state.entries, key, fn {entry, size, order} ->
              {%{entry | expires_at: System.monotonic_time(:millisecond) - 1}, size, order}
            end)
      }
    end)
  end
end
