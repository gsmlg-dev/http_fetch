defmodule HTTP.WebTransportTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport
  alias HTTP.WebTransport.BidirectionalStream
  alias HTTP.WebTransport.CloseInfo
  alias HTTP.WebTransport.DatagramDuplexStream
  alias HTTP.WebTransport.DatagramsWritable
  alias HTTP.WebTransport.FakeBackend
  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.ReceiveStream
  alias HTTP.WebTransport.SendStream
  alias HTTP.WebTransport.StreamQueue

  test "connects with a fake backend and exposes negotiated properties" do
    transport =
      WebTransport.new("https://example.com/transport",
        backend: FakeBackend,
        protocols: ["chat.v1"]
      )

    assert %WebTransport{} = transport
    assert WebTransport.url(transport) == "https://example.com/transport"
    assert :ok = WebTransport.await_ready(transport, 1_000)
    assert WebTransport.state(transport) == :connected
    assert WebTransport.reliability(transport) == "supports-unreliable"
    assert WebTransport.congestion_control(transport) == :default
    assert WebTransport.protocol(transport) == "chat.v1"
    assert {"X-Fake-WebTransport", "ok"} in WebTransport.response_headers(transport)

    assert_receive {WebTransport, ^transport, {:state, :connected}}, 1_000
  end

  test "default backend is the QUIC transport" do
    assert {:ok, %Options{backend: HTTP.WebTransport.Transport.QUIC}} =
             Options.new("https://example.com/transport")
  end

  test "sends and receives datagrams" do
    transport = connected_transport()
    datagrams = WebTransport.datagrams(transport)
    writable = DatagramDuplexStream.create_writable(datagrams)

    assert %DatagramsWritable{} = writable
    assert DatagramDuplexStream.max_datagram_size(datagrams) == 65_536
    assert :ok = DatagramsWritable.write(writable, <<1, 2, 3>>)

    send(transport.pid, {:webtransport_datagram, transport.ref, "pong"})

    assert {:ok, "pong"} = DatagramDuplexStream.read(datagrams, timeout: 1_000)
    assert {:error, :timeout} = DatagramDuplexStream.read(datagrams, timeout: 10)
  end

  test "bounds the incoming datagram queue" do
    transport =
      WebTransport.new("https://example.com/transport",
        backend: FakeBackend,
        max_incoming_datagrams: 1
      )

    assert %WebTransport{} = transport
    assert :ok = WebTransport.await_ready(transport, 1_000)
    datagrams = WebTransport.datagrams(transport)

    send(transport.pid, {:webtransport_datagram, transport.ref, "first"})
    send(transport.pid, {:webtransport_datagram, transport.ref, "second"})

    assert {:ok, "second"} = DatagramDuplexStream.read(datagrams, timeout: 1_000)
    assert {:error, :timeout} = DatagramDuplexStream.read(datagrams, timeout: 10)
  end

  test "configures datagram max age settings" do
    transport = connected_transport()
    datagrams = WebTransport.datagrams(transport)

    assert DatagramDuplexStream.incoming_max_age(datagrams) == nil
    assert :ok = DatagramDuplexStream.set_incoming_max_age(datagrams, 1_000)
    assert DatagramDuplexStream.incoming_max_age(datagrams) == 1_000

    assert {:error, :invalid_datagram_age} =
             DatagramDuplexStream.set_outgoing_max_age(datagrams, -1)
  end

  test "opens bidirectional streams and reads stream data" do
    transport = connected_transport()

    assert {:ok, %BidirectionalStream{} = stream} =
             WebTransport.create_bidirectional_stream(transport)

    assert %ReceiveStream{} = stream.readable
    assert %SendStream{} = stream.writable

    assert :ok = SendStream.write(stream.writable, ["hel", "lo"])
    send(transport.pid, {:webtransport_stream_data, stream.readable.ref, "echo"})
    assert {:ok, "echo"} = ReceiveStream.read(stream.readable, timeout: 1_000)

    send(transport.pid, {:webtransport_stream_fin, stream.readable.ref})
    assert :fin = ReceiveStream.read(stream.readable, timeout: 1_000)

    assert :ok = SendStream.close(stream.writable)
  end

  test "receive stream read times out while no data is available" do
    transport = connected_transport()

    assert {:ok, %BidirectionalStream{} = stream} =
             WebTransport.create_bidirectional_stream(transport)

    assert {:error, :timeout} = ReceiveStream.read(stream.readable, timeout: 10)
  end

  test "opens unidirectional send streams" do
    transport = connected_transport()

    assert {:ok, %SendStream{} = stream} = WebTransport.create_unidirectional_stream(transport)
    assert :ok = SendStream.write(stream, "hello")
    assert :ok = SendStream.abort(stream, code: 42)
  end

  test "queues incoming streams" do
    transport = connected_transport()
    bidi_queue = WebTransport.incoming_bidirectional_streams(transport)
    uni_queue = WebTransport.incoming_unidirectional_streams(transport)

    assert %StreamQueue{} = bidi_queue
    assert {:error, :timeout} = StreamQueue.read(bidi_queue, timeout: 10)

    send(transport.pid, {:webtransport_incoming_bidi_stream, transport.ref, :server_bidi})
    send(transport.pid, {:webtransport_incoming_uni_stream, transport.ref, :server_uni})

    assert {:ok, %BidirectionalStream{readable: %{ref: :server_bidi}}} =
             StreamQueue.read(bidi_queue, timeout: 1_000)

    assert {:ok, %ReceiveStream{ref: :server_uni}} = StreamQueue.read(uni_queue, timeout: 1_000)
  end

  test "closes and resolves close promise" do
    transport = connected_transport()

    assert :ok = WebTransport.close(transport, close_code: 7, reason: "done")

    assert {:ok, %CloseInfo{close_code: 7, reason: "done"}} =
             WebTransport.await_closed(transport, 1_000)

    assert WebTransport.state(transport) == :closed

    datagrams = WebTransport.datagrams(transport)
    writable = DatagramDuplexStream.create_writable(datagrams)
    assert {:error, :invalid_state} = DatagramsWritable.write(writable, "late")
  end

  test "backend draining and close messages resolve lifecycle promises" do
    transport = connected_transport()

    send(transport.pid, {:webtransport_draining, transport.ref})

    assert :ok = WebTransport.await_draining(transport, 1_000)
    assert WebTransport.state(transport) == :draining
    assert_receive {WebTransport, ^transport, {:state, :draining}}, 1_000

    send(
      transport.pid,
      {:webtransport_closed, transport.ref, %{close_code: 19, reason: "remote"}}
    )

    assert {:ok, %CloseInfo{close_code: 19, reason: "remote"}} =
             WebTransport.await_closed(transport, 1_000)

    assert WebTransport.state(transport) == :closed
  end

  test "validates close input" do
    transport = connected_transport()

    assert {:error, :invalid_close_code} = WebTransport.close(transport, close_code: -1)
    assert {:error, :invalid_close_reason} = WebTransport.close(transport, reason: :bad)

    assert {:error, :close_reason_too_long} =
             WebTransport.close(transport, reason: :binary.copy("a", 1_025))
  end

  test "get_stats reports session byte and datagram counters" do
    transport = connected_transport()
    datagrams = WebTransport.datagrams(transport)
    writable = DatagramDuplexStream.create_writable(datagrams)

    assert {:ok, %{bytes_sent: 0, bytes_received: 0}} = WebTransport.get_stats(transport)
    assert :ok = DatagramsWritable.write(writable, <<1, 2, 3>>)
    send(transport.pid, {:webtransport_datagram, transport.ref, "pong"})
    assert {:ok, "pong"} = DatagramDuplexStream.read(datagrams, timeout: 1_000)

    assert {:ok, stats} = WebTransport.get_stats(transport)
    assert stats.bytes_sent == 3
    assert stats.bytes_received == 4
    assert stats.datagrams == %{sent: 1, received: 1, dropped: 0}
  end

  test "incoming datagram max age drops stale datagrams and counts them" do
    transport = connected_transport()
    datagrams = WebTransport.datagrams(transport)
    assert :ok = DatagramDuplexStream.set_incoming_max_age(datagrams, 20)

    send(transport.pid, {:webtransport_datagram, transport.ref, "stale"})
    Process.sleep(60)
    assert {:error, :timeout} = DatagramDuplexStream.read(datagrams, timeout: 10)

    send(transport.pid, {:webtransport_datagram, transport.ref, "fresh"})
    assert {:ok, "fresh"} = DatagramDuplexStream.read(datagrams, timeout: 1_000)
    assert {:ok, %{datagrams: %{dropped: 1}}} = WebTransport.get_stats(transport)
  end

  test "send order and send groups are rejected instead of ignored" do
    transport = connected_transport()
    datagrams = WebTransport.datagrams(transport)

    writable = DatagramDuplexStream.create_writable(datagrams, send_order: 5)
    assert {:error, :send_order_unsupported} = DatagramsWritable.write(writable, "x")

    assert {:error, :send_group_unsupported} =
             WebTransport.create_unidirectional_stream(transport,
               send_group: WebTransport.create_send_group(transport)
             )

    assert {:error, :send_order_unsupported} =
             WebTransport.create_bidirectional_stream(transport, send_order: 1)
  end

  test "close rejects out-of-range codes and invalid UTF-8 reasons" do
    transport = connected_transport()

    assert {:error, :invalid_close_code} =
             WebTransport.close(transport, close_code: 0x1_0000_0000)

    assert {:error, :invalid_close_reason} = WebTransport.close(transport, reason: <<0xFF>>)
    assert :ok = WebTransport.close(transport, close_code: 0xFFFFFFFF)
  end

  test "require_unreliable fails a session whose backend is reliable-only" do
    defmodule ReliableOnlyBackend do
      @moduledoc false
      def connect(uri, options) do
        with {:ok, ref, info} <- HTTP.WebTransport.FakeBackend.connect(uri, options),
             do: {:ok, ref, %{info | reliability: "reliable-only"}}
      end

      defdelegate close(ref, info), to: HTTP.WebTransport.FakeBackend
    end

    transport =
      WebTransport.new("https://example.com/transport",
        backend: ReliableOnlyBackend,
        require_unreliable: true
      )

    assert {:error, :unreliable_transport_required} = WebTransport.await_ready(transport, 1_000)
    assert WebTransport.state(transport) == :failed
  end

  defp connected_transport do
    transport = WebTransport.new("https://example.com/transport", backend: FakeBackend)
    assert %WebTransport{} = transport
    assert :ok = WebTransport.await_ready(transport, 1_000)
    transport
  end
end
