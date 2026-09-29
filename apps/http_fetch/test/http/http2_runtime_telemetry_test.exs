defmodule HTTP.HTTP2RuntimeTelemetryTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{BodyBridge, ConnectionOwner, Frame}

  def handle_event(name, measurements, metadata, parent),
    do: send(parent, {:telemetry, name, measurements, metadata})

  setup do
    handler = "http2-runtime-#{System.unique_integer([:positive])}"

    events = [
      [:http_fetch, :http2, :runtime],
      [:http_fetch, :http2, :body_bridge],
      [:http_fetch, :http2, :connection]
    ]

    :ok = :telemetry.attach_many(handler, events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler) end)
    :ok
  end

  defp owner do
    transport = %{send: fn _, _ -> :ok end, close: fn _ -> :ok end}
    {:ok, pid} = ConnectionOwner.start_link(transport: transport, socket: :socket)
    :ok = ConnectionOwner.receive_bytes(pid, Frame.encode(:settings, 0, 0, <<>>))
    pid
  end

  defp headers do
    [
      {":method", "POST"},
      {":scheme", "http"},
      {":authority", "example.test"},
      {":path", "/secret"}
    ]
  end

  test "peer codes stay numeric measurements and close causes are finite" do
    pid = owner()
    assert {:ok, %{id: id}} = ConnectionOwner.open_stream(pid, headers(), subscriber: self())
    assert %{active_streams: 1, protocol_streams: 1} = ConnectionOwner.status(pid)

    assert :ok = ConnectionOwner.receive_bytes(pid, Frame.encode(:rst_stream, 0, id, <<123::32>>))

    assert_receive {:telemetry, [:http_fetch, :http2, :runtime], %{error_code: 123},
                    %{event: :peer_reset, outcome: :received}}

    assert :ok =
             ConnectionOwner.receive_bytes(
               pid,
               Frame.encode(:goaway, 0, 0, <<0::1, id::31, 456::32>>)
             )

    assert_receive {:telemetry, [:http_fetch, :http2, :runtime], %{error_code: 456},
                    %{event: :peer_goaway, outcome: :received}}

    monitor = Process.monitor(pid)
    assert :ok = ConnectionOwner.release_stream(pid, id)

    assert_receive {:telemetry, [:http_fetch, :http2, :connection],
                    %{active_streams: 0, protocol_streams: 0},
                    %{event: :released, lifecycle: :draining}}

    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}

    assert_receive {:telemetry, [:http_fetch, :http2, :runtime], %{},
                    %{event: :connection_close, outcome: :normal}}
  end

  test "upload stall emits one count and elapsed duration after credit arrives" do
    pid = owner()

    assert :ok =
             ConnectionOwner.receive_bytes(pid, Frame.encode(:settings, 0, 0, <<4::16, 0::32>>))

    assert {:ok, %{id: id}} = ConnectionOwner.open_stream(pid, headers(), body_bridge: self())
    ref = make_ref()
    assert :ok = ConnectionOwner.send_event(pid, {:body_chunk, self(), "x", ref})

    assert :ok =
             ConnectionOwner.receive_bytes(
               pid,
               Frame.encode(:window_update, 0, id, <<0::1, 1::31>>)
             )

    assert_receive {:body_ack, ^ref}

    assert_receive {:telemetry, [:http_fetch, :http2, :runtime],
                    %{count: 1, duration_us: duration},
                    %{event: :flow_control_stall, outcome: :resumed}}

    assert is_integer(duration) and duration >= 0
  end

  test "bridge emits one bounded lifetime result on cancellation" do
    source =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    {:ok, bridge} = BodyBridge.start_link(source, self())
    assert :ok = BodyBridge.cancel(bridge)
    assert :ok = BodyBridge.cancel(bridge)

    assert_receive {:telemetry, [:http_fetch, :http2, :body_bridge],
                    %{bytes: 0, peak_buffered_bytes: 0, duration_us: duration},
                    %{outcome: :cancelled}}

    assert is_integer(duration) and duration >= 0
    refute_receive {:telemetry, [:http_fetch, :http2, :body_bridge], _, _}, 20
    send(source, :stop)
  end
end
