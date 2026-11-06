defmodule AbyssPhase1.Faults do
  import Bitwise

  def run do
    Process.flag(:trap_exit, true)
    root = System.fetch_env!("ABYSS_PATH")
    fixture = Path.join(root, "test/fixtures/quic/server_flight")

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    opts = [
      handler: {AbyssEchoExample.Handler, [observer: self()]},
      alpn: ["abyss-echo-v1"],
      tls: [cert: [cert], key: {type, key}]
    ]

    {:ok, listener} = Abyss.QUIC.start_link(opts)
    {:ok, {_, port}} = Abyss.QUIC.local(listener)
    peer(root, fixture, port, "other-alpn", "root.pem", ["--expect-failure"])
    peer(root, fixture, port, "abyss-echo-v1", "leaf-rsa.pem", ["--expect-failure"])

    receive do
      {:bound, _, _, _} -> raise "negative handshake reached application binding"
    after
      0 -> :ok
    end

    task = Task.async(fn -> peer(root, fixture, port) end)

    receive do
      {:bound, _worker, handle, _meta} ->
        # Fault injection only: application operations use the public API.
        :ok = :sys.suspend(listener)

        Task.await(task, 60_000)
        :ok = :sys.resume(listener)
        IO.puts("SUSPENDED_LISTENER_WRITER_PROGRESS_PASS #{inspect(handle.generation)}")
    after
      10_000 -> raise "consumer did not bind"
    end

    :ok = Abyss.QUIC.stop(listener)

    {:ok, retry} = Abyss.QUIC.start_link(Keyword.put(opts, :quic_options, retry: true))
    {:ok, {_, retry_port}} = Abyss.QUIC.local(retry)
    # Observe only this host writer's actual UDP sends. No connection enumeration.
    writer = :sys.get_state(retry).writer
    :erlang.trace_pattern({Abyss.QUIC.SocketTransport, :send, 4}, true, [:local])
    :erlang.trace(writer, true, [:call])
    peer(root, fixture, retry_port)
    :erlang.trace(writer, false, [:call])
    :erlang.trace_pattern({Abyss.QUIC.SocketTransport, :send, 4}, false, [:local])
    {retry_count, sends} = collect_sends(writer, 0, 0)
    true = retry_count > 0 and sends > retry_count
    IO.puts("HOST_RETRY_EGRESS_PASS retry=#{retry_count} sends=#{sends}")
    :ok = Abyss.QUIC.stop(retry)
    IO.puts("NETWORK_FAULTS_PASS")
  end

  defp collect_sends(writer, retry_count, sends) do
    receive do
      {:trace, ^writer, :call,
       {Abyss.QUIC.SocketTransport, :send, [_socket, _ip, _port, <<first, _::binary>>]}} ->
        collect_sends(
          writer,
          retry_count + if(band(first, 0xF0) == 0xF0, do: 1, else: 0),
          sends + 1
        )
    after
      0 -> {retry_count, sends}
    end
  end

  defp peer(root, fixture, port, alpn \\ "abyss-echo-v1", ca \\ "root.pem", extra \\ []) do
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
          alpn,
          "--mode",
          "echo",
          "--ca",
          Path.join(fixture, ca)
        ] ++ extra,
        stderr_to_stdout: true
      )

    IO.write(out)
    if status != 0, do: raise("peer failed #{status}")
  end
end

AbyssPhase1.Faults.run()
