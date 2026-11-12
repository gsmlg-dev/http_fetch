defmodule Hell.SecretRedactionTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  @certfile Path.expand("../support/cert.pem", __DIR__)
  @keyfile Path.expand("../support/key.pem", __DIR__)
  @password ~c"known-secret-password-168"

  defmodule Noop do
    use Hell.Handler
  end

  test "redact_transport_options/1 redacts secret TLS options" do
    options = [
      certfile: "cert.pem",
      password: @password,
      key: {:ECPrivateKey, "der"},
      certs_keys: [%{certfile: "a.pem", key: {:RSAPrivateKey, "der"}, password: @password}],
      sni_hosts: [{~c"example.com", [keyfile: "k.pem", password: @password]}],
      sni_fun: fn _ -> [] end,
      ip: :loopback
    ]

    assert Hell.ServerConfig.redact_transport_options(options) == [
             certfile: "cert.pem",
             password: :redacted,
             key: :redacted,
             certs_keys: [%{certfile: "a.pem", key: :redacted, password: :redacted}],
             sni_hosts: [{~c"example.com", [keyfile: "k.pem", password: :redacted]}],
             sni_fun: :redacted,
             ip: :loopback
           ]

    refute inspect(Hell.ServerConfig.new(handler_module: Noop, transport_options: options)) =~
             to_string(@password)
  end

  test "listener telemetry and crash logs never contain the key password" do
    detach = TelemetryHelpers.attach_all_events(Noop)
    on_exit(detach)

    {:ok, server} =
      start_supervised(
        {Hell,
         port: 0,
         num_acceptors: 1,
         handler_module: Noop,
         transport_module: Hell.Transports.SSL,
         transport_options: [certfile: @certfile, keyfile: @keyfile, password: @password]}
      )

    assert_receive {:telemetry, [:hell, :listener, :start], _measurements, metadata}, 1_000
    assert Keyword.fetch!(metadata.transport_options, :password) == :redacted
    refute inspect(metadata, limit: :infinity) =~ to_string(@password)

    listener = Hell.Server.listener_pid(server)
    assert is_pid(listener)
    refute inspect(:sys.get_state(listener), limit: :infinity) =~ to_string(@password)

    log =
      capture_log(fn ->
        ref = Process.monitor(listener)
        catch_exit(GenServer.call(listener, :force_crash))
        assert_receive {:DOWN, ^ref, :process, ^listener, _reason}, 1_000
        Process.sleep(100)
      end)

    assert log =~ "Hell.Listener"
    refute log =~ to_string(@password)
  end
end
