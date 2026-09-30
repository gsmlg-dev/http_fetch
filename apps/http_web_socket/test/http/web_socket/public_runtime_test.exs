defmodule HTTP.WebSocket.PublicRuntimeTest do
  use ExUnit.Case, async: true

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Telemetry

  test "public runtime accessors and acknowledgements use the connection protocol" do
    parent = self()
    pid = spawn(fn -> serve(parent) end)
    socket = %WebSocket{pid: pid}
    assert WebSocket.http_version(socket) == :http2
    assert WebSocket.protocol(socket) == "chat"
    assert WebSocket.status(socket) == %{http_version: :http2, ready_state: 1}
    ref = make_ref()
    assert WebSocket.acknowledge(socket, ref) == :ok
    assert_receive {:acknowledged, ^ref}
    send(pid, :stop)
  end

  test "closed runtime accessors remain safe" do
    socket = %WebSocket{}
    assert WebSocket.http_version(socket) == nil
    assert %{ready_state: 3, http_version: nil, buffered_amount: 0} = WebSocket.status(socket)
    assert WebSocket.acknowledge(socket, make_ref()) == :ok
  end

  test "connect telemetry preserves subprotocol and reports actual HTTP version and fallback" do
    id = make_ref()
    parent = self()

    :telemetry.attach(
      id,
      [:http_web_socket, :connect, :stop],
      fn event, measurements, metadata, _ ->
        send(parent, {event, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(id) end)
    uri = URI.parse("wss://example.com")
    assert :ok = Telemetry.connect_stop(uri, "chat", 12, :http2, false)

    assert_receive {[:http_web_socket, :connect, :stop], %{duration: 12},
                    %{protocol: "chat", http_version: :http2, fallback: false}}

    assert :ok = Telemetry.connect_stop(uri, "", 13)

    assert_receive {[:http_web_socket, :connect, :stop], %{duration: 13},
                    %{protocol: "", http_version: :http1, fallback: false}}
  end

  defp serve(parent) do
    receive do
      {:"$gen_call", from, :http_version} ->
        GenServer.reply(from, :http2)
        serve(parent)

      {:"$gen_call", from, :protocol} ->
        GenServer.reply(from, "chat")
        serve(parent)

      {:"$gen_call", from, :status} ->
        GenServer.reply(from, %{http_version: :http2, ready_state: 1})
        serve(parent)

      {:"$gen_call", from, {:acknowledge, ref}} ->
        send(parent, {:acknowledged, ref})
        GenServer.reply(from, :ok)
        serve(parent)

      :stop ->
        :ok
    end
  end
end
