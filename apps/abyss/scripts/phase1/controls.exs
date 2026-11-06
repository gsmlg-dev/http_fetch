defmodule AbyssPhase1.Controls do
  @behaviour Abyss.QUIC.Handler
  def init(connection, _metadata, _opts), do: {:ok, connection}

  def handle_event({:stream_open, stream, :bidi}, connection) do
    case stream.id do
      0 -> {:ok, _} = Abyss.QUIC.reset_stream(stream, 0x12345)
      4 -> {:ok, _} = Abyss.QUIC.stop_stream(stream, 0x54321)
      8 -> :ok = Abyss.QUIC.close(connection, 0x111111, "opaque")
    end

    {:ok, connection}
  end

  def handle_event(_, state), do: {:ok, state}
end

defmodule AbyssPhase1.ControlsRun do
  def run do
    root = System.fetch_env!("ABYSS_PATH")
    fixture = Path.join(root, "test/fixtures/quic/server_flight")

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    for {scenario, retry_opts, mode} <- [
          {"normal", [], "controls"},
          {"retry_loss", [retry: true], "echo"},
          {"invalid_token", [retry: true], "echo"},
          {"expired_token", [retry: true, retry_ttl: 10_000], "echo"}
        ] do
      handler = if mode == "controls", do: AbyssPhase1.Controls, else: AbyssEchoExample.Handler

      {:ok, listener} =
        Abyss.QUIC.start_link(
          handler: handler,
          alpn: ["abyss-test-v1"],
          tls: [cert: [cert], key: {type, key}],
          quic_options: retry_opts
        )

      {:ok, {_, port}} = Abyss.QUIC.local(listener)

      args = [
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
        "abyss-test-v1",
        "--mode",
        mode,
        "--ca",
        Path.join(fixture, "root.pem"),
        "--scenario",
        scenario
      ]

      args =
        if scenario in ["invalid_token", "expired_token"],
          do: args ++ ["--expect-failure"],
          else: args

      {out, status} = System.cmd("uv", args, stderr_to_stdout: true)
      IO.write(out)
      :ok = Abyss.QUIC.stop(listener)
      if status != 0, do: raise("#{scenario} peer failed #{status}")
      IO.puts("CONTROL_PASS #{scenario}")
    end
  end
end

AbyssPhase1.ControlsRun.run()
