ExUnit.start()

# Execute the existing timer and lifecycle regressions against the unpacked package.
for file <- ~w(read_timeout_transition_test.exs lifecycle_regression_test.exs) do
  Code.require_file(Path.join([System.fetch_env!("HELL_TEST_DIR"), "hell", file]))
end

defmodule HellArtifactSmokeTest do
  use ExUnit.Case

  defmodule Echo do
    use Hell.Handler

    @impl Hell.Handler
    def handle_data(data, socket, state) do
      :ok = Hell.Socket.send(socket, data)
      {:continue, state}
    end

    @impl Hell.Handler
    def handle_shutdown(socket, state) do
      :ok = Hell.Socket.send(socket, "GOODBYE")
      {:close, state}
    end
  end

  test "the artifact has the intended application and version" do
    assert Application.spec(:hell, :vsn) ==
             String.to_charlist(System.fetch_env!("HELL_EXPECTED_VERSION"))

    assert Code.ensure_loaded?(Hell.Transports.TCP)
    assert Code.ensure_loaded?(Hell.Transports.SSL)

    assert Enum.sort(Application.spec(:hell, :applications)) ==
             Enum.sort([:kernel, :stdlib, :elixir, :logger, :ssl, :telemetry])

    for module <- [HTTP, Abyss, Quic, SSL, Rustler] do
      refute Code.ensure_loaded?(module)
    end
  end

  for transport <- [:tcp, :tls] do
    @transport transport
    test "#{transport} echoes data and closes gracefully" do
      fixtures = System.fetch_env!("HELL_FIXTURE_DIR")

      {client, client_options, server_options} =
        case @transport do
          :tcp ->
            {:gen_tcp, [:binary, active: false], []}

          :tls ->
            {:ssl,
             [
               :binary,
               active: false,
               verify: :verify_peer,
               cacertfile: Path.join(fixtures, "ca.pem")
             ],
             [
               transport_module: Hell.Transports.SSL,
               transport_options: [
                 certfile: Path.join(fixtures, "cert.pem"),
                 keyfile: Path.join(fixtures, "key.pem")
               ]
             ]}
        end

      {:ok, server} =
        Hell.start_link([port: 0, handler_module: Echo, num_acceptors: 1] ++ server_options)

      on_exit(fn -> if Process.alive?(server), do: Hell.stop(server, 5_000) end)
      {:ok, {_address, port}} = Hell.listener_info(server)
      {:ok, socket} = client.connect(~c"localhost", port, client_options, 5_000)
      :ok = client.send(socket, "HELLO")
      assert client.recv(socket, 5, 5_000) == {:ok, "HELLO"}
      assert :ok == Hell.stop(server, 5_000)
      assert client.recv(socket, 7, 5_000) == {:ok, "GOODBYE"}
      assert client.recv(socket, 0, 5_000) == {:error, :closed}
      refute Process.alive?(server)
      assert :ok == client.close(socket)
    end
  end
end
