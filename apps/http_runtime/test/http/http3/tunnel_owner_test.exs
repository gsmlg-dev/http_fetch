defmodule HTTP.HTTP3.TunnelOwnerTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP3.ConnectionOwner
  alias QuicHttp3.{Control, Frame, Qpack}

  defmodule Transport do
    def open_stream(_, :bidi, _), do: {:ok, {:stream, make_ref()}}
    def send_stream(_, _, _, _), do: :ok
    def events(_, _, _), do: {:ok, Process.delete(:events) || []}
    def read(_, _, _), do: {:ok, Process.delete(:items) || []}
    def reset_stream(_, _, _), do: :ok
    def stop_stream(_, _, _), do: :ok
  end

  @fields [
    {":method", "CONNECT"},
    {":scheme", "https"},
    {":authority", "example.test"},
    {":path", "/ws"}
  ]

  defp state do
    {:ok, state} =
      ConnectionOwner.init(inert: true, creator: self(), session_options: [transport: Transport])

    {:ok, control} = Control.new(:client)
    session = %{state.session | open?: true, connection: %{endpoint: nil}, control: control}
    %{state | lifecycle: :ready, watchdog: self(), session: session}
  end

  test "pending peer SETTINGS leaves CONNECT unallocated while control polling progresses" do
    state = state()
    tag = make_ref()
    generation = make_ref()
    opts = [purpose: :extended_connect, protocol: "websocket", deadline_at: now() + 1000]

    assert {:noreply, state} =
             ConnectionOwner.handle_call(
               {:open, @fields, :stream, self(), generation, opts},
               {self(), tag},
               state
             )

    assert length(state.queue) == 1
    assert state.session.requests == %{}
    Process.put(:events, [{:stream_open, :control, :uni}, {:readable, :control}])

    Process.put(:items, [
      {:data, <<0>> <> Frame.encode!(:settings, QuicHttp3.Settings.encode!([{8, 1}]))}
    ])

    assert {:noreply, state} = ConnectionOwner.handle_info(:tick, state)
    assert_receive {^tag, {:ok, ref}}
    assert state.requests[ref].purpose == :extended_connect
    assert state.session.requests[ref].upload == :open
    assert state.queue == []
  end

  test "waiting for SETTINGS respects original deadline without admitting CONNECT" do
    state = state()
    tag = make_ref()
    opts = [purpose: :extended_connect, protocol: "websocket", deadline_at: now() - 1]

    assert {:noreply, state} =
             ConnectionOwner.handle_call(
               {:open, @fields, :stream, self(), make_ref(), opts},
               {self(), tag},
               state
             )

    assert_receive {^tag, {:error, :opening_timeout}}
    assert state.session.requests == %{}
    assert state.queue == []
  end

  test "accepted tunnel headers preserve writes and DATA bytes stay charged until acknowledgement" do
    state = state()
    control = %{state.session.control | received_settings?: true, peer_settings: [{8, 1}]}
    state = put_in(state.session.control, control)
    tag = make_ref()
    generation = make_ref()
    opts = [purpose: :extended_connect, protocol: "websocket", deadline_at: now() + 1000]

    {:noreply, state} =
      ConnectionOwner.handle_call(
        {:open, @fields, :stream, self(), generation, opts},
        {self(), tag},
        state
      )

    assert_receive {^tag, {:ok, ref}}
    stream = state.session.requests[ref].stream
    {:ok, block} = Qpack.encode_header_block([{":status", "200"}])
    Process.put(:events, [{:readable, stream}])
    Process.put(:items, [{:data, Frame.encode!(:headers, block) <> Frame.encode!(:data, "abc")}])
    assert {:noreply, state} = ConnectionOwner.handle_info(:tick, state)
    assert_receive {:http3, ^generation, ^ref, {:headers, 200, []}}
    assert_receive {:http3, ^generation, ^ref, {:data, "abc"}}
    assert state.session.requests[ref].upload == :open
    assert state.extension_bytes == 3
    assert state.requests[ref].paused
    assert {:noreply, state} = ConnectionOwner.handle_cast({:ack, ref}, state)
    assert state.extension_bytes == 0
    refute state.requests[ref].paused

    assert {:reply, :ok, state} =
             ConnectionOwner.handle_call({:cancel, ref}, {self(), make_ref()}, state)

    assert state.requests == %{}
    assert state.extension_bytes == 0
  end

  test "aggregate extension delivery is capped and unknown write refs cannot affect siblings" do
    state = state()

    state =
      put_in(state.session.control, %{
        state.session.control
        | received_settings?: true,
          peer_settings: [{8, 1}]
      })

    {:ok, block} = Qpack.encode_header_block([{":status", "200"}])
    data = :binary.copy("x", 16_384)

    {state, refs} =
      Enum.reduce(1..17, {state, []}, fn index, {state, refs} ->
        tag = make_ref()
        opts = [purpose: :extended_connect, protocol: "websocket", deadline_at: now() + 1000]

        {:noreply, state} =
          ConnectionOwner.handle_call(
            {:open, @fields, :stream, self(), make_ref(), opts},
            {self(), tag},
            state
          )

        assert_receive {^tag, {:ok, ref}}
        stream = state.session.requests[ref].stream
        Process.put(:events, [{:readable, stream}])
        # One native read is at most 16KiB including HTTP/3 frame overhead.
        Process.put(:items, [{:data, Frame.encode!(:headers, block)}])
        {:noreply, state} = ConnectionOwner.handle_info(:tick, state)
        Process.put(:events, [{:readable, stream}])
        # Use 16,380 payload bytes so the DATA frame fits its native read batch.
        bytes = binary_part(data, 0, 16_380)
        Process.put(:items, [{:data, Frame.encode!(:data, bytes)}])
        {:noreply, state} = ConnectionOwner.handle_info(:tick, state)
        assert state.extension_bytes <= 262_144
        if index == 17, do: assert_receive({:http3, _, ^ref, {:error, :consumer_overloaded}})
        {state, refs ++ [ref]}
      end)

    assert map_size(state.requests) == 16
    native = make_ref()
    unknown = make_ref()

    assert {:noreply, next} =
             ConnectionOwner.handle_cast({:write, unknown, "x", false, self(), native}, state)

    assert_receive {:http3_write, ^native, {:error, :unknown_request}}
    assert next.requests == state.requests

    state =
      Enum.reduce(refs, next, fn ref, state ->
        {:noreply, state} = ConnectionOwner.handle_cast({:ack, ref}, state)
        state
      end)

    assert state.extension_bytes == 0
  end

  test "settle retires only the subscriber's tunnel and confirms after native cancellation" do
    state = state()
    control = %{state.session.control | received_settings?: true, peer_settings: [{8, 1}]}
    state = put_in(state.session.control, control)
    opts = [purpose: :extended_connect, protocol: "websocket", deadline_at: now() + 1000]
    sibling = spawn(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> send(sibling, :stop) end)

    {state, [ref, other]} =
      Enum.reduce([self(), sibling], {state, []}, fn subscriber, {state, refs} ->
        tag = make_ref()

        {:noreply, state} =
          ConnectionOwner.handle_call(
            {:open, @fields, :stream, subscriber, make_ref(), opts},
            {self(), tag},
            state
          )

        assert_receive {^tag, {:ok, ref}}
        {state, refs ++ [ref]}
      end)

    assert {:reply, {:pending, [^ref]}, state} =
             ConnectionOwner.handle_call({:settle, self(), []}, {self(), make_ref()}, state)

    refute Map.has_key?(state.requests, ref)
    refute Map.has_key?(state.session.requests, ref)
    assert Map.has_key?(state.requests, other)
    assert Map.has_key?(state.session.requests, other)

    assert {:reply, :settled, _state} =
             ConnectionOwner.handle_call({:settle, self(), [ref]}, {self(), make_ref()}, state)
  end

  test "settle rejects queued opens and stays pending while a native action references the stream" do
    state = state()
    tag = make_ref()
    opts = [purpose: :extended_connect, protocol: "websocket", deadline_at: now() + 1000]

    {:noreply, state} =
      ConnectionOwner.handle_call(
        {:open, @fields, :stream, self(), make_ref(), opts},
        {self(), tag},
        state
      )

    assert length(state.queue) == 1

    assert {:reply, :settled, state} =
             ConnectionOwner.handle_call({:settle, self(), []}, {self(), make_ref()}, state)

    assert_receive {^tag, {:error, :aborted}}
    assert state.queue == []

    ref = make_ref()
    pending = %{state | pending: {:write, ref, "x", true, self(), make_ref()}}

    assert {:reply, {:pending, [^ref]}, _} =
             ConnectionOwner.handle_call({:settle, self(), [ref]}, {self(), make_ref()}, pending)

    opening = %{state | pending: {:open, {self(), make_ref()}, self(), make_ref(), [], "", []}}

    assert {:reply, {:pending, []}, _} =
             ConnectionOwner.handle_call({:settle, self(), []}, {self(), make_ref()}, opening)
  end

  defp now, do: System.monotonic_time(:millisecond)
end
