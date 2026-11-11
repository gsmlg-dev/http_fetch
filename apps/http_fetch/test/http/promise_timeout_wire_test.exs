defmodule HTTP.PromiseTimeoutWireTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  test "a finite wait preserves explicit cleanup of a request stalled before response headers" do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :http_bin, ip: {127, 0, 0, 1}])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    parent = self()
    supervisor = start_supervised!(Task.Supervisor)

    peer =
      Task.Supervisor.async_nolink(supervisor, fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)

        try do
          {:ok, {:http_request, :GET, {:abs_path, "/artifact"}, {1, 1}}} =
            :gen_tcp.recv(socket, 0, 2_000)

          recv_headers(socket)
          :ok = :inet.setopts(socket, packet: :raw)
          send(parent, {:received_get, self()})
          :gen_tcp.recv(socket, 0, 5_000)
        after
          :gen_tcp.close(socket)
        end
      end)

    promise =
      HTTP.fetch("http://127.0.0.1:#{port}/artifact",
        http_version: :http1,
        redirect: :manual,
        proxy: nil,
        http1_reuse: false,
        timeout: 5_000,
        connect_timeout: 1_000,
        read_idle_timeout: 4_000
      )

    completion = HTTP.Promise.completion(promise)
    on_exit(fn -> HTTP.RequestCompletion.abort_and_await(completion, 1_000) end)
    peer_pid = peer.pid
    assert_receive {:received_get, ^peer_pid}, 2_000

    assert {:error, :await_timeout} = HTTP.Promise.await(promise, 1)
    assert {:error, :cleanup_pending} = HTTP.RequestCompletion.await(completion, 0)
    assert :ok = HTTP.RequestCompletion.abort_and_await(completion, 1_000)
    assert {:error, :closed} = Task.await(peer, 1_000)
  end

  defp recv_headers(socket) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, :http_eoh} -> :ok
      {:ok, {:http_header, _, _, _, _}} -> recv_headers(socket)
    end
  end
end
