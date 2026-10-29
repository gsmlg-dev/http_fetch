defmodule HTTP.ConnectDeadlineOrderingTest do
  use ExUnit.Case, async: true

  alias HTTP.Runtime.Dialer

  @moduletag :integration
  @peer_timeout 3_000

  for backend <- [nil, :ex_ssl],
      {control, request_timeout, expected} <- [
        {:abort, 5_000, :aborted},
        {:deadline, 5_000, :request_timeout},
        {:elapsed, 500, :request_timeout},
        {:short_connect, 5_000, :timeout}
      ] do
    test "#{backend} pinned native timeout respects #{control} ordering" do
      backend = unquote(backend)
      observer = self()
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_tcp.close(listener) end)
      {:ok, {_, port}} = :inet.sockname(listener)

      peer =
        Task.Supervisor.async_nolink(:http_runtime_task_supervisor, fn ->
          {:ok, socket} = :gen_tcp.accept(listener, @peer_timeout)
          assert {:ok, <<22, 3, _minor, length::16>>} = :gen_tcp.recv(socket, 5, @peer_timeout)

          assert {:ok, <<1, _client_hello::binary>>} =
                   :gen_tcp.recv(socket, length, @peer_timeout)

          send(observer, {:client_hello, self()})
          outcome = drain_peer(socket)
          :gen_tcp.close(socket)
          outcome
        end)

      request = %HTTP.Request{
        url: URI.parse("https://pinned.invalid:#{port}/"),
        transport_options: [
          connect_address: {127, 0, 0, 1},
          redirect: :manual,
          tls_backend: backend,
          connect_timeout: 500
        ]
      }

      assert {:ok, effective_backend} = HTTP.TLSBackend.resolve(backend)
      transport = HTTP.TLSBackend.transport(effective_backend)

      dial =
        Task.Supervisor.async_nolink(:http_runtime_task_supervisor, fn ->
          Dialer.connect(
            transport,
            "pinned.invalid",
            port,
            request,
            %{mode: :auto_https, alpn_protocols: ["h2", "http/1.1"]},
            unquote(request_timeout)
          )
        end)

      on_exit(fn ->
        for %{pid: pid} <- [dial, peer] do
          monitor = Process.monitor(pid)
          Process.exit(pid, :kill)
          assert_receive {:DOWN, ^monitor, :process, ^pid, _}, @peer_timeout
        end
      end)

      peer_pid = peer.pid
      assert_receive {:client_hello, ^peer_pid}, @peer_timeout
      true = :erlang.suspend_process(dial.pid)

      try do
        await_native_error(dial.pid, System.monotonic_time(:millisecond) + @peer_timeout)
        if unquote(control in [:abort, :deadline]), do: send(dial.pid, unquote(control))

        assert {:messages, [{:connect_result, _, {:error, :timeout}} | _]} =
                 Process.info(dial.pid, :messages)
      after
        true = :erlang.resume_process(dial.pid)
      end

      assert Task.await(dial, @peer_timeout) == {:error, unquote(expected)}
      assert Task.await(peer, @peer_timeout) == {:error, :closed}
      refute Process.alive?(dial.pid)
      refute Process.alive?(peer.pid)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    end
  end

  defp await_native_error(owner, deadline) do
    {:messages, messages} = Process.info(owner, :messages)

    if Enum.any?(messages, &match?({:connect_result, _, {:error, :timeout}}, &1)) do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        1 -> await_native_error(owner, deadline)
      end
    end
  end

  defp drain_peer(socket) do
    case :gen_tcp.recv(socket, 0, @peer_timeout) do
      {:ok, _bytes} -> drain_peer(socket)
      outcome -> outcome
    end
  end
end
