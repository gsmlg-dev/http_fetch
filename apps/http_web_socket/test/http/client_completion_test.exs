defmodule HTTP.WebSocket.ClientCompletionTest do
  use ExUnit.Case, async: true

  alias HTTP.{ClientCompletion, RequestLifecycle, WebSocket}
  alias HTTP.WebSocket.{Connection, Options}
  alias HTTP.WebSocket.Event.Open

  test "event target carries the identical caller-surviving public receipt" do
    {:ok, options} = Options.new("wss://example.test/socket", [], ref: make_ref())
    receipt = ClientCompletion.new(:client)
    {:ok, state, {:continue, :connect}} = Connection.init({options, receipt})
    target = state.target
    assert receipt == WebSocket.completion(target)
    generation = make_ref()

    state = %{
      state
      | generation: generation,
        stream: self(),
        connect_started_at: System.monotonic_time(:microsecond)
    }

    assert {:noreply, state} =
             Connection.handle_info(
               {:http_runtime, generation, self(), {:headers, [{":status", "200"}], 0}},
               state
             )

    assert_receive {WebSocket, ^target, %Open{target: ^target}}
    assert receipt == WebSocket.completion(%{target | pid: nil})
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    :ok = Connection.terminate(:normal, state)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "stale generation and timer messages preserve the current attempt and receipt" do
    {:ok, options} = Options.new("wss://example.test/socket", [])
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

  for reason <- [:http1_negotiated, :extended_connect_not_supported] do
    test "a consumed fallback rejects another #{reason} attempt" do
      {:ok, options} = Options.new("wss://example.test/socket", [], http_version: :auto)
      receipt = ClientCompletion.new(:client)
      {:ok, state, {:continue, :connect}} = Connection.init({options, receipt})
      generation = make_ref()

      state = %{
        state
        | generation: generation,
          stream: self(),
          fallback?: true,
          connect_started_at: System.monotonic_time(:microsecond)
      }

      target = state.target

      assert {:stop, :normal, state} =
               Connection.handle_info(
                 {:http_runtime, generation, self(), {:error, unquote(reason)}},
                 state
               )

      assert_receive {WebSocket, ^target, %HTTP.WebSocket.Event.Error{reason: unquote(reason)}}
      :ok = Connection.terminate(:normal, state)
      RequestLifecycle.retire_owner(receipt.tracker)
      assert :ok = ClientCompletion.await(receipt, 1_000)
    end
  end

  test "invalid protocols retain existing constructor error" do
    assert {:error, _} = WebSocket.new("wss://example.test", ["duplicate", "duplicate"])
  end
end
