defmodule AbyssPhase1.FailingHandler do
  @behaviour Abyss.QUIC.Handler
  def init(connection, _metadata, {owner, mode}) do
    send(owner, {:attempt, self(), connection})

    case mode do
      :fail ->
        {:error, :deliberate_init_failure}

      :crash ->
        raise "deliberate_consumer_crash"

      :timeout ->
        receive do
          :unreachable -> {:ok, nil}
        end
    end
  end

  def handle_event(_, state), do: {:ok, state}
end

defmodule AbyssPhase1.Lifecycle do
  def run do
    Process.flag(:trap_exit, true)
    root = System.fetch_env!("ABYSS_PATH")
    fixture = Path.join(root, "test/fixtures/quic/server_flight")

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    opts = [alpn: ["abyss-echo-v1"], tls: [cert: [cert], key: {type, key}]]
    {:ok, {_, echo_port}} = Abyss.QUIC.local(AbyssEchoExample.Listener)
    unaffected = Task.async(fn -> peer(root, fixture, echo_port, "echo") end)

    for mode <- [:fail, :crash, :timeout] do
      {:ok, listener} =
        Abyss.QUIC.start_link(
          opts ++ [init_timeout: 100, handler: {AbyssPhase1.FailingHandler, {self(), mode}}]
        )

      {:ok, {_, port}} = Abyss.QUIC.local(listener)
      task = Task.async(fn -> peer(root, fixture, port, "hold") end)

      receive do
        {:attempt, worker, connection} ->
          await_down(worker)
          await_down(connection.id)
          {:ok, _} = Abyss.QUIC.local(listener)
          IO.puts("CONSUMER_ISOLATION_PASS #{mode}")
      after
        5000 -> raise "no application binding"
      end

      Task.await(task, 10_000)
      :ok = Abyss.QUIC.stop(listener)
    end

    Task.await(unaffected, 60_000)

    spec = {Abyss.QUIC, opts ++ [handler: {AbyssEchoExample.Handler, [observer: self()]}]}
    {:ok, supervisor} = Supervisor.start_link([spec], strategy: :one_for_one)
    [{_, listener, _, _}] = Supervisor.which_children(supervisor)
    {:ok, {_, port}} = Abyss.QUIC.local(listener)
    task = Task.async(fn -> peer(root, fixture, port, "hold") end)

    receive do
      {:bound, worker, connection, _} ->
        # Internal host fault injection; application receives only public handles.
        host = :sys.get_state(listener)
        Process.exit(host.writer, :kill)
        await_down(worker)
        await_down(connection.id)
        await_down(listener)
        Task.await(task, 10_000)
        [{_, restarted, _, _}] = Supervisor.which_children(supervisor)
        true = restarted != listener
        {:ok, {_, new_port}} = Abyss.QUIC.local(restarted)
        peer(root, fixture, new_port, "echo")

        receive do
          {:bound, _, new_connection, _} ->
            true = new_connection.generation != connection.generation
        after
          5000 -> raise "restarted listener did not bind"
        end

        IO.puts("WRITER_DEATH_RESTART_PASS")
    after
      5000 -> raise "no initial binding"
    end

    Supervisor.stop(supervisor)
    IO.puts("NETWORK_LIFECYCLE_PASS")
  end

  defp await_down(pid) do
    ref = Process.monitor(pid)

    receive do
      {:DOWN, ^ref, :process, ^pid, _} -> :ok
    after
      2000 -> raise "cleanup deadline for #{inspect(pid)}"
    end
  end

  defp peer(root, fixture, port, mode) do
    {out, status} =
      System.cmd(
        "uv",
        [
          "run",
          "--python",
          "3.12",
          "--with",
          "aioquic==1.2.0",
          "python",
          Path.join(root, "scripts/phase1/peer.py"),
          "--port",
          to_string(port),
          "--alpn",
          "abyss-echo-v1",
          "--mode",
          mode,
          "--ca",
          Path.join(fixture, "root.pem")
        ],
        stderr_to_stdout: true
      )

    IO.write(out)
    if status != 0, do: raise("peer failed #{status}")
  end
end

AbyssPhase1.Lifecycle.run()
