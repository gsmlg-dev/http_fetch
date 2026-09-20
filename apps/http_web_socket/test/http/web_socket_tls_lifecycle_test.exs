defmodule HTTP.WebSocketTLSLifecycleTest do
  use ExUnit.Case, async: false

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.Close
  alias HTTP.WebSocket.Event.Message
  alias HTTP.WebSocket.Event.Open

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "delivers upgrade-buffered frames after the TLS peer has closed" do
    parent = self()
    existing_connections = tls_connections()

    {:ok, server, port} =
      HTTPWebSocket.TestServer.start_link(
        tls: true,
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        # A complete text frame and close frame share the upgrade's TLS record.
        upgrade_frames: <<0x81, 3, "bye", 0x88, 2, 1000::16>>,
        close_after_upgrade: true
      )

    handler = {__MODULE__, make_ref()}

    :ok =
      :telemetry.attach(
        handler,
        [:http_web_socket, :connect, :stop],
        &__MODULE__.pause_after_upgrade/4,
        {port, parent}
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    socket =
      WebSocket.new("wss://127.0.0.1:#{port}/socket", [],
        tls_backend: :ex_ssl,
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
      )

    assert_receive {:upgrade_received, consumer}, 5_000
    [tls_pid] = tls_connections() -- existing_connections
    monitor = Process.monitor(tls_pid)

    try do
      send(server, :close_tls)
      assert_receive {:DOWN, ^monitor, :process, ^tls_pid, _}, 5_000
    after
      send(consumer, :continue_upgrade)
    end

    assert_receive {WebSocket, ^socket, %Open{}}, 5_000
    assert_receive {WebSocket, ^socket, %Message{data: "bye"}}, 5_000
    assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 5_000
  end

  def pause_after_upgrade(_event, _measurements, %{port: port}, {port, parent}) do
    send(parent, {:upgrade_received, self()})

    receive do
      :continue_upgrade -> :ok
    after
      5_000 -> :ok
    end
  end

  def pause_after_upgrade(_event, _measurements, _metadata, _config), do: :ok

  defp tls_connections do
    for {_, pid, _, _} <- DynamicSupervisor.which_children(SSL.ConnectionSupervisor), do: pid
  end
end
