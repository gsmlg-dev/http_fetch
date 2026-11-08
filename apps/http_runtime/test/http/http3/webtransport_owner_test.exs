defmodule HTTP.HTTP3.WebTransportOwnerTest do
  use ExUnit.Case, async: true
  alias HTTP.H3.WebTransport.Draft17
  alias HTTP.HTTP3.{ConnectionOwner, ReceiveBudget}
  alias QuicHttp3.{Control, Frame, Qpack}
  alias QuicHttp3.Transport.Quic.Stream, as: TStream

  defmodule Transport do
    alias QuicHttp3.Transport.Quic.Stream, as: TStream

    def open_stream(_, kind, _) do
      id = Process.get({:next, kind}, if(kind == :bidi, do: 0, else: 2))
      Process.put({:next, kind}, id + 4)
      {:ok, %TStream{handle: %{id: id}}}
    end

    def send_stream(stream, bytes, fin, _),
      do: send(self(), {:wire, stream.handle.id, bytes, fin}) && :ok

    def events(_, _, _), do: {:ok, Process.delete(:events) || []}
    def read_datagrams(_, _, _), do: {:ok, []}

    def info(_),
      do:
        {:ok,
         %{
           reliable_reset: %{draft: 11, local: true, peer: true, negotiated: true},
           datagram: %{send_max_bytes: 1197}
         }}

    def read(stream, _, _) do
      items = Process.get({:items, stream.handle.id}, [])
      Process.delete({:items, stream.handle.id})
      {:ok, items}
    end
  end

  @fields [
    {":method", "CONNECT"},
    {":scheme", "https"},
    {":authority", "example.test"},
    {":path", "/wt"}
  ]

  test "WebTransport owners reserve receive windows for peer WT streams" do
    assert {:ok, options} = ReceiveBudget.normalize(webtransport: true, max_streams: 1)
    assert options[:streams][:max_streams_bidi] == 16
    assert options[:streams][:max_streams_uni] == 19
    assert options[:streams][:max_data] == (1 + 19 + 16) * 65_536

    assert {:ok, plain} = ReceiveBudget.normalize([])
    assert plain[:streams][:max_streams_bidi] == 0

    assert {:error, :invalid_http3_receive_budget} =
             ReceiveBudget.normalize(streams: [max_streams_bidi: 4])

    assert {:error, :invalid_http3_receive_budget} =
             ReceiveBudget.normalize(webtransport: true, streams: [max_streams_bidi: 65])
  end

  test "only the CONNECT subscriber operates the session and receives credited events" do
    {:ok, state} =
      ConnectionOwner.init(
        inert: true,
        creator: self(),
        session_options: [transport: Transport, webtransport: true]
      )

    {:ok, control} = Control.new(:client)

    control = %{
      control
      | received_settings?: true,
        peer_settings: [{8, 1}, {0x33, 1}, {0x20B8933B, 1}]
    }

    session = %{state.session | open?: true, connection: %{endpoint: nil}, control: control}
    state = %{state | lifecycle: :ready, watchdog: self(), session: session}
    tag = make_ref()
    generation = make_ref()
    opts = [purpose: :extended_connect, protocol: "webtransport-h3", deadline_at: now() + 1_000]

    {:noreply, state} =
      ConnectionOwner.handle_call(
        {:open, @fields, :stream, self(), generation, opts},
        {self(), tag},
        state
      )

    assert_receive {^tag, {:ok, ref}}

    other = spawn(fn -> :ok end)

    assert {:reply, {:error, :unknown_webtransport_session}, _} =
             ConnectionOwner.handle_call(
               {:webtransport, ref, :info, now() + 100},
               {other, make_ref()},
               state
             )

    {:ok, block} = Qpack.encode_header_block([{":status", "200"}])
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    Process.put({:items, 0}, [{:data, 0, Frame.encode!(:headers, block)}])
    Process.put({:items, 3}, [{:data, 3, prefix <> "hey"}])
    peer = %TStream{handle: %{id: 3}}

    Process.put(:events, [
      {:readable, %TStream{handle: %{id: 0}}},
      {:stream_open, peer, :uni},
      {:readable, peer}
    ])

    {:noreply, state} = ConnectionOwner.handle_info(:tick, state)
    {:noreply, state} = ConnectionOwner.handle_info(:tick, state)
    assert_receive {:http3, ^generation, ^ref, {:headers, 200, []}}
    assert_receive {:http3, ^generation, ^ref, {:wt, {:stream, 3, :uni, "hey", false, receipt}}}
    assert state.session.wt.router.retained_bytes == 3

    assert {:reply, {:ok, %{session_id: 0}}, _} =
             ConnectionOwner.handle_call(
               {:webtransport, ref, :info, now() + 100},
               {self(), make_ref()},
               state
             )

    {:noreply, state} = ConnectionOwner.handle_cast({:webtransport_ack, ref, receipt}, state)
    assert state.session.wt.router.retained_bytes == 0

    op = make_ref()

    {:noreply, state} =
      ConnectionOwner.handle_call(
        {:webtransport, ref, {:open, :uni}, now() + 1_000},
        {self(), op},
        state
      )

    assert_receive {^op, {:ok, 2}}
    assert_receive {:wire, 2, ^prefix, false}

    expired = make_ref()

    {:noreply, _state} =
      ConnectionOwner.handle_call(
        {:webtransport, ref, {:datagram, "x"}, now() - 1},
        {self(), expired},
        state
      )

    assert_receive {^expired, {:error, :operation_timeout}}
  end

  defp now, do: System.monotonic_time(:millisecond)
end
