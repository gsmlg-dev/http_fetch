defmodule HTTP.WebTransport.SessionBoundsTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport
  alias HTTP.WebTransport.{DatagramDuplexStream, FakeBackend, ReceiveStream, SendStream}

  defp transport(options \\ []) do
    transport = WebTransport.new("https://example.com/wt", [backend: FakeBackend] ++ options)
    assert :ok = WebTransport.await_ready(transport, 1_000)

    transport
  end

  test "owner death terminates its session" do
    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    transport = transport(owner: owner)
    monitor = Process.monitor(transport.pid)
    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
  end

  test "finite lifecycle waits are removed in the session" do
    transport = transport()
    assert {:error, :timeout} = WebTransport.await_closed(transport, 1)
    assert :sys.get_state(transport.pid).closed_waiters == []
  end

  test "draining rejects new streams while existing streams remain writable" do
    transport = transport()
    assert {:ok, stream} = WebTransport.create_bidirectional_stream(transport)
    send(transport.pid, {:webtransport_draining, transport.ref})
    assert :ok = WebTransport.await_draining(transport, 1_000)
    assert {:error, :invalid_state} = WebTransport.create_unidirectional_stream(transport)
    assert :ok = SendStream.write(stream.writable, "live")
  end

  test "send FIN and receive FIN are sticky and duplicate input is ignored" do
    transport = transport()
    assert {:ok, stream} = WebTransport.create_bidirectional_stream(transport)
    assert :ok = SendStream.close(stream.writable)
    assert {:error, :invalid_state} = SendStream.write(stream.writable, "late")
    send(transport.pid, {:webtransport_stream_data, stream.readable.ref, "a"})
    send(transport.pid, {:webtransport_stream_fin, stream.readable.ref})
    send(transport.pid, {:webtransport_stream_fin, stream.readable.ref})
    send(transport.pid, {:webtransport_stream_data, stream.readable.ref, "late"})
    assert {:ok, "a"} = ReceiveStream.read(stream.readable, timeout: 0)
    assert :fin = ReceiveStream.read(stream.readable, timeout: 0)
    assert :fin = ReceiveStream.read(stream.readable, timeout: 0)
  end

  test "unknown stream input cannot allocate stream state" do
    transport = transport()
    send(transport.pid, {:webtransport_stream_data, :unknown, "payload"})
    assert :sys.get_state(transport.pid).streams == %{}
  end

  test "stream admission and retained bytes are bounded" do
    transport = transport(max_streams: 1, max_buffered_bytes: 3)
    assert {:ok, stream} = WebTransport.create_bidirectional_stream(transport)
    assert {:error, :backpressure} = WebTransport.create_unidirectional_stream(transport)
    send(transport.pid, {:webtransport_stream_data, stream.readable.ref, "four"})
    assert WebTransport.state(transport) == :failed
    assert :sys.get_state(transport.pid).streams == %{}
  end

  test "terminal session ignores late events and releases queues" do
    transport = transport()
    send(transport.pid, {:webtransport_datagram, transport.ref, "before"})
    assert :ok = WebTransport.close(transport)
    send(transport.pid, {:webtransport_datagram, transport.ref, "after"})
    send(transport.pid, {:webtransport_incoming_bidi_stream, transport.ref, :late})
    state = :sys.get_state(transport.pid)
    assert state.datagram_queue == []
    assert state.streams == %{}

    assert {:error, :closed} =
             DatagramDuplexStream.read(WebTransport.datagrams(transport), timeout: 0)
  end

  test "waiter capacity applies across lifecycle and data reads and releases on timeout" do
    transport = transport(max_pending_waiters: 1)
    request = :gen_server.send_request(transport.pid, {:read_datagram, :infinity})
    assert length(:sys.get_state(transport.pid).datagram_waiters) == 1
    assert {:error, :backpressure} = WebTransport.await_closed(transport, 10)

    assert {:error, :backpressure} =
             DatagramDuplexStream.read(WebTransport.datagrams(transport), timeout: 10)

    assert :ok = WebTransport.close(transport)
    assert {:reply, {:error, :closed}} = :gen_server.wait_response(request, 1_000)
    assert :sys.get_state(transport.pid).datagram_waiters == []
  end

  test "empty datagrams retain item capacity and oversize datagrams are dropped whole" do
    transport = transport(max_buffered_items: 2, max_datagram_size: 3)
    send(transport.pid, {:webtransport_datagram, transport.ref, ""})
    send(transport.pid, {:webtransport_datagram, transport.ref, ""})
    send(transport.pid, {:webtransport_datagram, transport.ref, ""})
    send(transport.pid, {:webtransport_datagram, transport.ref, "four"})
    assert length(:sys.get_state(transport.pid).datagram_queue) == 2
    datagrams = WebTransport.datagrams(transport)
    assert {:ok, ""} = DatagramDuplexStream.read(datagrams, timeout: 0)
    assert {:ok, ""} = DatagramDuplexStream.read(datagrams, timeout: 0)
    assert {:error, :timeout} = DatagramDuplexStream.read(datagrams, timeout: 0)
  end

  test "zero or invalid resource limits are rejected" do
    for key <- [:max_streams, :max_pending_waiters, :max_buffered_bytes, :max_buffered_items],
        value <- [0, -1, :infinity, "1"] do
      assert_invalid({:invalid_limit, key}, fn ->
        WebTransport.new("https://example.com/wt", [{key, value}])
      end)
    end
  end

  test "incoming stream direction and duplicate announcement remain bounded" do
    transport = transport(max_streams: 1)
    send(transport.pid, {:webtransport_incoming_uni_stream, transport.ref, :incoming})
    send(transport.pid, {:webtransport_incoming_uni_stream, transport.ref, :incoming})
    state = :sys.get_state(transport.pid)
    assert length(state.incoming_uni_queue) == 1

    assert {:error, :invalid_state} =
             SendStream.write(%SendStream{transport: transport, ref: :incoming}, "x")

    send(transport.pid, {:webtransport_incoming_uni_stream, transport.ref, :overflow})
    assert WebTransport.state(transport) == :failed
  end

  test "invalid waiter timeouts cannot crash session or reserve capacity" do
    transport = transport()
    assert {:ok, stream} = WebTransport.create_bidirectional_stream(transport)

    for timeout <- [-1, :bad, "1"] do
      assert {:error, :invalid_timeout} = WebTransport.await_closed(transport, timeout)
      assert {:error, :invalid_timeout} = ReceiveStream.read(stream.readable, timeout: timeout)

      assert {:error, :invalid_timeout} =
               DatagramDuplexStream.read(WebTransport.datagrams(transport), timeout: timeout)
    end

    assert WebTransport.state(transport) == :connected
  end

  test "dead read caller releases capacity and its timer" do
    transport = transport(max_pending_waiters: 1)
    test = self()

    caller =
      spawn(fn ->
        :gen_server.send_request(transport.pid, {:read_datagram, 60_000})
        GenServer.call(transport.pid, :state)
        send(test, :registered)

        receive do
          :stop -> :ok
        end
      end)

    assert_receive :registered
    [waiter] = :sys.get_state(transport.pid).datagram_waiters
    monitor = Process.monitor(caller)
    send(caller, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}
    # The DOWN from the same caller monitor is already queued; a subsequent
    # server barrier observes its cleanup without a sleep.
    assert :sys.get_state(transport.pid).datagram_waiters == []
    assert Process.read_timer(waiter.timer) == false
  end

  test "FIN retains control progress when reliable data fills the item budget" do
    transport = transport(max_buffered_items: 1, max_buffered_bytes: 1)
    assert {:ok, stream} = WebTransport.create_bidirectional_stream(transport)
    send(transport.pid, {:webtransport_stream_data, stream.readable.ref, "a"})
    send(transport.pid, {:webtransport_stream_fin, stream.readable.ref})
    assert WebTransport.state(transport) == :connected
    assert {:ok, "a"} = ReceiveStream.read(stream.readable, timeout: 0)
    assert :fin = ReceiveStream.read(stream.readable, timeout: 0)
  end

  test "receive cancellation releases bytes and sticks without exposing queued data" do
    transport = transport()
    assert {:ok, stream} = WebTransport.create_bidirectional_stream(transport)
    send(transport.pid, {:webtransport_stream_data, stream.readable.ref, "discard"})
    assert :ok = ReceiveStream.cancel(stream.readable)
    assert {:error, :cancelled} = ReceiveStream.read(stream.readable, timeout: 0)
    assert {:error, :invalid_state} = ReceiveStream.cancel(stream.readable)
    assert :ok = WebTransport.close(transport)
    assert {:error, :closed} = ReceiveStream.read(stream.readable, timeout: 0)
  end

  test "draining promise and event settle once even when failure follows" do
    transport = transport()
    assert_receive {WebTransport, ^transport, {:state, :connected}}
    send(transport.pid, {:webtransport_draining, transport.ref})
    send(transport.pid, {:webtransport_draining, transport.ref})
    assert :ok = WebTransport.await_draining(transport, 1_000)
    assert_receive {WebTransport, ^transport, {:state, :draining}}
    refute_received {WebTransport, ^transport, {:state, :draining}}
    send(transport.pid, {:webtransport_failed, transport.ref, :peer_reset})
    assert {:error, :peer_reset} = WebTransport.await_closed(transport, 1_000)
    assert :ok = WebTransport.await_draining(transport, 0)
  end

  defp assert_invalid(reason, fun),
    do: assert_raise(ArgumentError, "invalid HTTP.WebTransport options: #{inspect(reason)}", fun)
end
