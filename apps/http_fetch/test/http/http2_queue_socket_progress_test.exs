defmodule HTTP.HTTP2QueueSocketProgressTest do
  use ExUnit.Case, async: false
  alias HTTP.HTTP2.Pool
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  setup do
    :ok = Supervisor.terminate_child(HTTPRuntime.Application, Pool)

    {:ok, pool} =
      start_supervised(
        {Pool, name: :http_fetch_http2_pool, max_connections: 1, max_total_connections: 1}
      )

    on_exit(fn ->
      {:ok, _pool} = Supervisor.restart_child(HTTPRuntime.Application, Pool)
    end)

    %{pool: pool}
  end

  test "a queued public request reconnects after GOAWAY and close without a rescue call", %{
    pool: pool
  } do
    test_pid = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    peer =
      spawn_link(fn ->
        socket = accept(listener)
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            Peer.frame(1, 5, id, <<0x88>>),
            Peer.frame(4, 0, 0, <<3::16, 0::32>>),
            Peer.frame(6, 0, 0, "zero-win")
          ])

        ping_ack(socket)
        send(test_pid, :zero_capacity_ready)
        receive do: (:goaway -> :ok)
        :ok = :gen_tcp.send(socket, Peer.frame(7, 0, 0, <<0::1, id::31, 0::32>>))
        :gen_tcp.close(socket)
        replacement = accept(listener)
        {next_id, true} = Peer.request(replacement)
        :ok = :gen_tcp.send(replacement, Peer.frame(1, 5, next_id, <<0x88>>))
        send(test_pid, :replacement_response)
        receive do: (:close -> :gen_tcp.close(replacement))
      end)

    on_exit(fn -> Process.exit(peer, :kill) end)

    url = "http://localhost:#{port}/test"
    assert fetch(url).status == 200
    assert_receive :zero_capacity_ready, 5_000
    handler = make_ref()

    :telemetry.attach(
      handler,
      [:http_fetch, :http2, :pool],
      fn _, _, metadata, _ ->
        if self() == pool and metadata.event == :queued, do: send(test_pid, :request_queued)
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
    task = Task.async(fn -> fetch(url) end)
    assert_receive :request_queued, 5_000
    send(peer, :goaway)
    assert Task.await(task, 5_000).status == 200
    assert_receive :replacement_response, 5_000
    send(peer, :close)
  end

  defp accept(listener) do
    {:ok, socket} = :gen_tcp.accept(listener, 5_000)
    {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)
    :ok = :gen_tcp.send(socket, Peer.frame(4, 0, 0, <<3::16, 1::32>>))
    socket
  end

  defp ping_ack(socket) do
    case Peer.recv(socket) do
      {6, 1, 0, "zero-win"} -> :ok
      _ -> ping_ack(socket)
    end
  end

  defp fetch(url) do
    HTTP.fetch(url, http_version: :h2c, timeout: 10_000) |> HTTP.Promise.await()
  end
end
