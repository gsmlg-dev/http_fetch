defmodule E2E.WebTransportLifecycleTest do
  @moduledoc """
  WebTransport public API lifecycle exercised through the backend boundary.

  This is intentionally backed by `HTTP.WebTransport.FakeBackend`. Wire-level
  coverage of the live draft-17 backend against an in-repo QUIC peer lives in
  `test/http/web_transport/quic_integration_test.exs` (integration tier).
  """

  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias HTTP.WebTransport
  alias HTTP.WebTransport.BidirectionalStream
  alias HTTP.WebTransport.CloseInfo
  alias HTTP.WebTransport.DatagramDuplexStream
  alias HTTP.WebTransport.DatagramsWritable
  alias HTTP.WebTransport.FakeBackend
  alias HTTP.WebTransport.ReceiveStream
  alias HTTP.WebTransport.SendStream
  alias HTTP.WebTransport.StreamQueue

  test "round-trips datagrams, streams, and lifecycle through the backend boundary" do
    transport =
      WebTransport.new("https://example.com/transport",
        backend: FakeBackend,
        protocols: ["chat.v1"],
        require_unreliable: true
      )

    assert %WebTransport{} = transport
    assert :ok = WebTransport.await_ready(transport, 1_000)
    assert WebTransport.state(transport) == :connected
    assert WebTransport.protocol(transport) == "chat.v1"
    assert WebTransport.reliability(transport) == "supports-unreliable"

    datagrams = WebTransport.datagrams(transport)
    writable = DatagramDuplexStream.create_writable(datagrams)

    assert %DatagramsWritable{} = writable
    assert :ok = DatagramsWritable.write(writable, "client-datagram")

    send(transport.pid, {:webtransport_datagram, transport.ref, "server-datagram"})
    assert {:ok, "server-datagram"} = DatagramDuplexStream.read(datagrams, timeout: 1_000)

    assert {:ok, %BidirectionalStream{} = bidi} =
             WebTransport.create_bidirectional_stream(transport)

    assert :ok = SendStream.write(bidi.writable, "client-stream")
    send(transport.pid, {:webtransport_stream_data, bidi.readable.ref, "server-stream"})
    assert {:ok, "server-stream"} = ReceiveStream.read(bidi.readable, timeout: 1_000)

    assert {:ok, %SendStream{} = uni} =
             WebTransport.create_unidirectional_stream(transport)

    assert :ok = SendStream.write(uni, "client-uni")

    incoming_bidi = WebTransport.incoming_bidirectional_streams(transport)
    incoming_uni = WebTransport.incoming_unidirectional_streams(transport)

    assert %StreamQueue{} = incoming_bidi
    assert %StreamQueue{} = incoming_uni

    send(transport.pid, {:webtransport_incoming_bidi_stream, transport.ref, :server_bidi})
    send(transport.pid, {:webtransport_incoming_uni_stream, transport.ref, :server_uni})

    assert {:ok, %BidirectionalStream{readable: %{ref: :server_bidi}}} =
             StreamQueue.read(incoming_bidi, timeout: 1_000)

    assert {:ok, %ReceiveStream{ref: :server_uni}} =
             StreamQueue.read(incoming_uni, timeout: 1_000)

    send(transport.pid, {:webtransport_draining, transport.ref})
    assert :ok = WebTransport.await_draining(transport, 1_000)
    assert WebTransport.state(transport) == :draining

    send(
      transport.pid,
      {:webtransport_closed, transport.ref, %{close_code: 0, reason: "complete"}}
    )

    assert {:ok, %CloseInfo{close_code: 0, reason: "complete"}} =
             WebTransport.await_closed(transport, 1_000)

    assert WebTransport.state(transport) == :closed
  end
end
