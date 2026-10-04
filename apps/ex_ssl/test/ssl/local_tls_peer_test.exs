defmodule ExSSL.LocalTLSPeerTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer

  test "stopping a backpressure proxy waits for forwarding socket cleanup" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)
    observer = self()

    owner =
      Task.async(fn ->
        {:ok, proxy} = Peer.start_backpressure_proxy(port, observer)
        send(observer, {:proxy, proxy})

        receive do
          :stop -> Peer.stop_backpressure_proxy(proxy)
        end

        send(observer, :proxy_stopped)
      end)

    assert_receive {:proxy, proxy}
    proxy_pid = proxy.task.pid
    controller = proxy.controller
    controller_monitor = Process.monitor(controller)
    :erlang.trace(proxy_pid, true, [:procs, {:tracer, self()}])
    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", proxy.port, [:binary, active: false])
    {:ok, upstream} = :gen_tcp.accept(listener, 1_000)
    assert_receive {:trace, ^proxy_pid, :spawn, forwarder, _}
    forwarder_monitor = Process.monitor(forwarder)
    proxy_ref = proxy.ref
    assert_receive {:backpressure_proxy, ^proxy_ref, :ready}

    try do
      assert true = :erlang.suspend_process(proxy_pid)
      send(owner.pid, :stop)
      assert_receive {:DOWN, ^controller_monitor, :process, ^controller, _}, 1_000
      refute_receive :proxy_stopped, 50
      assert true = :erlang.resume_process(proxy_pid)
      assert_receive :proxy_stopped, 1_000
      assert_receive {:DOWN, ^forwarder_monitor, :process, ^forwarder, _}, 1_000
      assert {:error, :closed} = :gen_tcp.recv(upstream, 0, 1_000)
      Task.await(owner)
    after
      for pid <- [proxy_pid, controller, forwarder] do
        if Process.alive?(pid), do: Process.exit(pid, :kill)
      end

      Task.shutdown(owner)
      :gen_tcp.close(client)
      :gen_tcp.close(upstream)
      :gen_tcp.close(listener)
    end
  end

  test "upgrading a closed TCP port returns an error without raising" do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, active: false])
    assert :ok = :gen_tcp.close(socket)
    assert :undefined = :erlang.port_info(socket, :connected)
    assert {:ok, _} = Application.ensure_all_started(:ssl)
    # OTP cannot recover the transport kind after the port has closed.
    assert {:error, _reason} = :ssl.connect(socket, [verify: :verify_none], 100)
    assert {:error, :closed} = SSL.connect(socket, [verify: :verify_none], 100)
  end
end
