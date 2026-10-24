defmodule HTTP.EventSource.ClientCompletionTest do
  use ExUnit.Case, async: true

  alias HTTP.{ClientCompletion, EventSource, RequestLifecycle}
  alias HTTP.EventSource.{Connection, Options}
  alias HTTP.EventSource.Event.Open

  test "event target and public handle carry the identical receipt without a connection call" do
    {:ok, options} = Options.new("https://example.test/events", ref: make_ref())
    receipt = ClientCompletion.new(:client)
    {:ok, state, {:continue, :connect}} = Connection.init({options, receipt})
    target = state.target
    assert receipt == EventSource.completion(target)
    generation = make_ref()

    state = %{
      state
      | generation: generation,
        stream: self(),
        connect_started_at: System.monotonic_time(:microsecond)
    }

    assert {:noreply, state} =
             Connection.handle_info(
               {:http_runtime, generation, self(),
                {:headers, [{":status", "200"}, {"content-type", "text/event-stream"}], 0}},
               state
             )

    assert_receive {EventSource, ^target, %Open{target: ^target}}
    assert receipt == EventSource.completion(%{target | pid: nil})
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    :ok = Connection.terminate(:normal, state)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "stale generation and timer messages preserve the current attempt and receipt" do
    {:ok, options} = Options.new("https://example.test/events")
    receipt = ClientCompletion.new(:client)
    {:ok, state, {:continue, :connect}} = Connection.init({options, receipt})

    {:ok, permit} =
      RequestLifecycle.reserve_attempt(
        receipt.tracker,
        System.monotonic_time(:millisecond) + 1_000
      )

    child = ClientCompletion.new()

    :ok =
      RequestLifecycle.retain_attempt(
        receipt.tracker,
        permit,
        child,
        System.monotonic_time(:millisecond) + 1_000
      )

    generation = make_ref()
    state = %{state | generation: generation, stream: self(), attempt_tracker: child.tracker}
    children = :sys.get_state(receipt.tracker).children
    stale = make_ref()

    for message <- [
          {:opening_timeout, stale},
          {:idle_timeout, stale},
          {:reconnect, stale},
          {:http_runtime, stale, self(), {:error, :closed}}
        ] do
      assert {:noreply, ^state} = Connection.handle_info(message, state)
      assert :sys.get_state(receipt.tracker).children == children
    end

    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    RequestLifecycle.retire_owner(child.tracker)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "invalid constructor options retain existing error behavior" do
    assert {:error, _} = EventSource.new("not a URL")
  end
end
