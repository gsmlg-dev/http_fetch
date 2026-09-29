defmodule HTTP.HTTP2PoolTelemetryTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.Pool

  def handle_event(_, measurements, metadata, parent),
    do: send(parent, {:pool_event, measurements, metadata})

  test "reports bounded counts and queued reservation outcome without key metadata" do
    parent = self()
    handler = "pool-telemetry-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(handler, [:http_fetch, :http2, :pool], &__MODULE__.handle_event/4, parent)

    on_exit(fn -> :telemetry.detach(handler) end)
    {:ok, pool} = start_supervised({Pool, max_connections: 1, max_streams: 1})
    key = "https://secret.example/private?token=hidden"

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)

    assert :ok = Pool.register(pool, key, owner)
    assert {:ok, ^owner, first} = Pool.reserve(pool, key)
    assert_receive {:pool_event, _, %{event: :reservation, outcome: :granted}}

    waiter =
      spawn(fn ->
        send(parent, {:waiter_result, Pool.reserve(pool, key)})

        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(waiter, :stop) end)

    assert_receive {:pool_event, %{waiters: 1}, %{event: :queued, outcome: :waiting}}
    assert :ok = Pool.release(pool, key, first)
    assert_receive {:waiter_result, {:ok, ^owner, second}}

    assert_receive {:pool_event, %{queue_wait_us: wait_us},
                    %{event: :reservation, outcome: :granted}}

    assert is_integer(wait_us) and wait_us >= 0
    assert :ok = Pool.cancel(pool, second)
    send(waiter, :stop)
    assert :ok = Pool.mark_draining(pool, key, owner)
    assert_receive {:pool_event, %{draining: 1}, %{event: :connection, outcome: :draining}}

    assert :start = Pool.claim_connect(pool, key)
    assert_receive {:pool_event, %{connecting: 1}, %{event: :connection, outcome: :connecting}}

    events = drain_events([])

    assert Enum.any?(events, fn {_m, meta} ->
             meta == %{event: :reservation, outcome: :cancelled}
           end)

    assert Enum.all?(events, fn {measurements, metadata} ->
             metadata == Map.take(metadata, [:event, :outcome]) and
               Enum.all?(measurements, fn {_, value} -> is_integer(value) and value >= 0 end)
           end)
  end

  defp drain_events(acc) do
    receive do
      {:pool_event, measurements, metadata} -> drain_events([{measurements, metadata} | acc])
    after
      0 -> acc
    end
  end
end
