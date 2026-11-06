# Run from examples/quic_echo with QUIC_CERT and QUIC_KEY set.
defmodule AbyssPhase1.Network do
  def run do
    root = System.fetch_env!("ABYSS_PATH")
    fixture = Path.join(root, "test/fixtures/quic/server_flight")
    peer = Path.join(root, "scripts/phase1/peer.py")
    {:ok, {_, echo_port}} = Abyss.QUIC.local(AbyssEchoExample.Listener)
    Code.require_file(Path.join(root, "examples/quic_collect/lib/handler.ex"))

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    tls = [cert: [cert], key: {type, key}]

    limits = [
      max_data: 16_384,
      max_stream_data: 16_384,
      max_buffer: 16_384,
      max_ready_bytes: 16_384,
      max_streams_bidi: 16,
      max_streams_uni: 16
    ]

    {:ok, collect} =
      Abyss.QUIC.start_link(
        handler: {AbyssCollectExample.Handler, [delay: 2]},
        alpn: ["abyss-collect-v1"],
        tls: tls,
        quic_options: [streams: limits]
      )

    {:ok, {_, collect_port}} = Abyss.QUIC.local(collect)
    # Independent applications execute simultaneously on separate listeners.
    tasks =
      for {port, alpn, mode} <- [
            {echo_port, "abyss-echo-v1", "echo"},
            {echo_port, "abyss-echo-v1", "echo"},
            {collect_port, "abyss-collect-v1", "collect"}
          ] do
        Task.async(fn -> peer(peer, fixture, port, alpn, mode) end)
      end

    Enum.each(tasks, &Task.await(&1, 60_000))
    :ok = Abyss.QUIC.stop(collect)

    {:ok, retry} =
      Abyss.QUIC.start_link(
        handler: AbyssEchoExample.Handler,
        alpn: ["abyss-echo-v1"],
        tls: tls,
        quic_options: [retry: true, streams: limits]
      )

    {:ok, {_, port}} = Abyss.QUIC.local(retry)
    peer(peer, fixture, port, "abyss-echo-v1", "echo")
    :ok = Abyss.QUIC.stop(retry)
    peer(peer, fixture, echo_port, "abyss-echo-v1", "isolation")
    IO.puts("NETWORK_BASELINE_PASS")
  end

  defp peer(script, fixture, port, alpn, mode) do
    {output, status} =
      System.cmd(
        "uv",
        [
          "run",
          "--python",
          "3.12",
          "--with",
          "aioquic==1.2.0",
          "python",
          script,
          "--port",
          Integer.to_string(port),
          "--alpn",
          alpn,
          "--mode",
          mode,
          "--ca",
          Path.join(fixture, "root.pem")
        ],
        stderr_to_stdout: true
      )

    IO.write(output)
    if status != 0, do: raise("independent #{mode} peer failed: #{status}")
  end
end

AbyssPhase1.Network.run()
