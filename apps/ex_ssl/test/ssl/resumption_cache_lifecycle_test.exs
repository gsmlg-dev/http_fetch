defmodule SSL.ResumptionCacheLifecycleTest do
  use ExUnit.Case, async: false

  alias SSL.{SessionTicket, TicketCache}

  @tag capture_log: true

  test "ticket cache restart discards in-memory ticket material" do
    assert {:ok, _} = Application.ensure_all_started(:ex_ssl)
    key = :crypto.hash(:sha256, :erlang.term_to_binary({__MODULE__, make_ref()}))
    assert :ok = TicketCache.put(key, ticket())

    cache = Process.whereis(TicketCache)
    monitor = Process.monitor(cache)
    Process.exit(cache, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^cache, :killed}, 1_000

    restarted = ticket_cache_child()
    assert restarted != cache
    assert :miss = TicketCache.checkout(key)
  end

  test "application restart discards in-memory ticket material" do
    assert {:ok, _} = Application.ensure_all_started(:ex_ssl)
    on_exit(fn -> assert {:ok, _} = Application.ensure_all_started(:ex_ssl) end)

    key = :crypto.hash(:sha256, :erlang.term_to_binary({__MODULE__, :application, make_ref()}))
    assert :ok = TicketCache.put(key, ticket())
    assert :ok = Application.stop(:ex_ssl)
    assert {:ok, _} = Application.ensure_all_started(:ex_ssl)
    assert :miss = TicketCache.checkout(key)
  end

  defp ticket_cache_child do
    {TicketCache, pid, :worker, [TicketCache]} =
      Supervisor.which_children(SSL.Supervisor)
      |> Enum.find(fn {id, _pid, _type, _modules} -> id == TicketCache end)

    assert is_pid(pid)
    pid
  end

  defp ticket do
    now = System.monotonic_time(:millisecond)

    %SessionTicket{
      ticket: "restart-ticket",
      psk: :binary.copy(<<1>>, 32),
      hash: :sha256,
      age_add: 1,
      issued_at: now,
      expires_at: now + 60_000,
      peer: %{chain: [<<1, 2, 3>>]},
      alpn: "http/1.1"
    }
  end
end
