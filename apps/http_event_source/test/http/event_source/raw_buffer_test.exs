defmodule HTTP.EventSource.RawBufferTest do
  use ExUnit.Case, async: true

  alias HTTP.EventSource
  alias HTTP.EventSource.{Connection, Options, Parser}
  alias HTTP.EventSource.Event.Message
  alias HTTP.Runtime.Delivery

  test "fragmented unused receive credit stays bounded and drains in order after application ACK" do
    state = paused_source()
    target = state.target
    assert_receive {EventSource, ^target, %Message{data: "first"}, first}

    state = fill_raw(state)
    assert state.raw_bytes == 1_048_576

    {state, refs} =
      Enum.reduce(1..128, {state, []}, fn number, {state, refs} ->
        {state, ref} = data(state, "data: #{number}\n\n")
        assert state.terminal_reason == nil
        assert :queue.len(state.raw_queue) <= 128
        refute_receive {:acknowledge, ^ref}, 0
        {state, [ref | refs]}
      end)

    assert state.raw_bytes < 1_048_576 + 65_535
    assert state.raw_refs == 128
    assert {:reply, :ok, state} = Connection.handle_call({:acknowledge, first}, nil, state)
    assert_receive {EventSource, ^target, %Message{data: "second"}, second}

    assert {:reply, :ok, state} = Connection.handle_call({:acknowledge, second}, nil, state)

    state =
      Enum.reduce(1..128, state, fn number, state ->
        expected = Integer.to_string(number)
        assert_receive {EventSource, ^target, %Message{data: ^expected}, ref}
        assert {:reply, :ok, state} = Connection.handle_call({:acknowledge, ref}, nil, state)
        state
      end)

    assert state.raw_bytes == 0
    assert state.raw_refs == 0
    assert :queue.is_empty(state.raw_queue)
    assert %{queued_events: 0, queued_bytes: 0} = Delivery.status(state.delivery)

    for ref <- Enum.reverse(refs), do: assert_receive({:acknowledge, ^ref})
    refute_receive {:acknowledge, _}, 0
    refute_receive :abort, 0
  end

  test "coalescing preserves the finite transport reference bound" do
    state = paused_source() |> fill_raw()

    state =
      Enum.reduce(1..128, state, fn _, state ->
        {state, _ref} = data(state, ":")
        assert state.terminal_reason == nil
        state
      end)

    {state, ref} = data(state, ":")
    assert state.terminal_reason == {:fatal, :consumer_overloaded}
    assert state.raw_bytes == 0
    assert state.raw_refs == 0
    assert :queue.is_empty(state.raw_queue)
    assert_receive :abort
    refute_receive {:acknowledge, ^ref}, 0
    refute_receive {:acknowledge, _}, 0
  end

  test "coalescing preserves the receive byte limit without granting excess credit" do
    state = paused_source() |> fill_raw()
    {state, ref} = data(state, String.duplicate(":", 65_536))
    assert state.terminal_reason == {:fatal, :consumer_overloaded}
    assert state.raw_bytes == 0
    assert state.raw_refs == 0
    assert :queue.is_empty(state.raw_queue)
    assert_receive :abort
    refute_receive {:acknowledge, ^ref}, 0
  end

  test "closing discards grouped credit without acknowledging unconsumed bytes" do
    state = paused_source() |> fill_raw()
    {state, first} = data(state, "first")
    {state, second} = data(state, "second")
    assert state.raw_refs == 2

    assert {:stop, :normal, :ok, state} = Connection.handle_call(:close, nil, state)
    assert state.raw_bytes == 0
    assert state.raw_refs == 0
    assert :queue.is_empty(state.raw_queue)
    assert_receive :abort
    refute_receive {:acknowledge, ^first}, 0
    refute_receive {:acknowledge, ^second}, 0
  end

  defp fill_raw(state) do
    Enum.reduce(1..16, state, fn _, state ->
      {state, ref} = data(state, String.duplicate(":\n", 32_768))
      assert_receive {:acknowledge, ^ref}
      state
    end)
  end

  defp paused_source do
    {:ok, options} =
      Options.new("https://example.test/events",
        http_version: :http2,
        delivery: :ack,
        max_event_size: 32,
        max_queue_bytes: 80,
        max_queue_events: 2
      )

    state = %Connection{
      options: options,
      owner: self(),
      target: %EventSource{ref: options.ref},
      uri: options.uri,
      generation: make_ref(),
      stream: self(),
      ready_state: EventSource.open(),
      http_version: :http2,
      parser: Parser.new(max_event_size: options.max_event_size),
      delivery: Delivery.new(options)
    }

    {state, ref} = data(state, "data: first\n\ndata: second\n\n")
    assert_receive {:acknowledge, ^ref}
    assert %{queued_events: 2} = Delivery.status(state.delivery)
    state
  end

  defp data(state, bytes) do
    ref = make_ref()

    assert {:noreply, state} =
             Connection.handle_info(
               {:http_runtime, state.generation, self(), {:data, bytes, 0, ref}},
               state
             )

    {state, ref}
  end
end
