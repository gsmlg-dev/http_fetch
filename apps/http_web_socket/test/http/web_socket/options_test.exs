defmodule HTTP.WebSocket.OptionsTest do
  use ExUnit.Case, async: false

  alias HTTP.WebSocket.Options

  test "normalizes literal connection addresses and independent receive limits" do
    assert {:ok, options} =
             Options.new("ws://example.test/socket", [], %{
               "connectAddress" => {127, 0, 0, 1},
               "maxFrameBytes" => 128,
               "maxReadBytes" => 256,
               "maxMessageSize" => 1024
             })

    assert %{connect_address: {127, 0, 0, 1}, max_frame_bytes: 128, max_read_bytes: 256} =
             options

    for key <- [:max_frame_bytes, :max_read_bytes], value <- [0, -1, :infinity, nil] do
      assert {:error, {:invalid_option, ^key}} =
               Options.new("ws://example.test/socket", [], [{key, value}])
    end
  end

  test "connection address validation retains the URL TLS identity and route contract" do
    assert {:error, :invalid_connect_address} =
             Options.new("ws://example.test/socket", [], connect_address: "127.0.0.1")

    assert {:error, :connect_address_unsupported_route} =
             Options.new("ws://example.test/socket", [],
               connect_address: {127, 0, 0, 1},
               unix_socket: "/unused-websocket.sock"
             )

    assert {:error, :connect_address_sni_conflict} =
             Options.new("wss://example.test/socket", [],
               connect_address: {127, 0, 0, 1},
               ssl: [server_name_indication: ~c"other.test"]
             )

    assert {:error, :connect_address_identity_conflict} =
             Options.new("wss://example.test/socket", [],
               connect_address: {127, 0, 0, 1},
               ssl: [ex_ssl: [reference_identity: {:dns_id, "other.test"}]]
             )
  end

  test "pin validation uses the same first keyword values captured by the connection" do
    assert {:error, :connect_address_sni_conflict} =
             Options.new("wss://example.test/socket", [], [
               {:connect_address, {127, 0, 0, 1}},
               {:ssl, [server_name_indication: ~c"other.test"]},
               {:ssl, []}
             ])

    assert {:error, :invalid_connect_address} =
             Options.new("ws://example.test/socket", [], [
               {:connect_address, "127.0.0.1"},
               {:connect_address, {127, 0, 0, 1}}
             ])
  end

  test "proxy endpoints reject independently of frame-forwarding mode" do
    for mode <- [:browser, :proxy],
        init <- [
          [proxy: "http://proxy.example.test:8080"],
          %{"proxy" => "http://proxy.example.test:8080"}
        ] do
      init = Map.new(init) |> Map.put(:mode, mode)
      assert {:error, :proxy_not_supported} = Options.new("ws://example.test/socket", [], init)
    end

    assert {:ok, %{mode: :proxy}} =
             Options.new("ws://example.test/socket", [], mode: :proxy, proxy: nil)
  end

  test "secure Unix options reject including the HTTPS alias" do
    for scheme <- ["wss", "https"],
        init <- [
          [unix_socket: "/unused-websocket.sock"],
          %{"unix_socket" => "/unused-websocket.sock"}
        ] do
      assert {:error, :tls_over_unix_socket_not_supported} =
               Options.new("#{scheme}://example.test/socket", [], init)
    end

    assert {:ok, %{unix_socket: "/unused-websocket.sock", uri: %{scheme: "ws"}}} =
             Options.new("ws://example.test/socket", [], unix_socket: "/unused-websocket.sock")
  end

  test "normalizes http and https schemes to ws and wss" do
    assert {:ok, %{uri: %{scheme: "ws"}, url: "ws://example.com/socket"}} =
             Options.new("http://example.com/socket")

    assert {:ok, %{uri: %{scheme: "wss"}, url: "wss://example.com/socket"}} =
             Options.new("https://example.com/socket")
  end

  test "rejects unsupported schemes and fragments" do
    assert {:error, {:unsupported_scheme, "ftp"}} = Options.new("ftp://example.com/socket")
    assert {:error, :fragment_not_allowed} = Options.new("ws://example.com/socket#frag")
  end

  test "write deadline is finite and accepts flat map keys" do
    assert {:ok, %{write_timeout: 123}} =
             Options.new("ws://example.com", [], %{"writeTimeout" => 123})

    for value <- [:infinity, 0, -1] do
      assert {:error, {:invalid_option, :write_timeout}} =
               Options.new("ws://example.com", [], write_timeout: value)
    end
  end

  test "normalizes protocols" do
    assert {:ok, %{protocols: []}} = Options.new("ws://example.com/socket")
    assert {:ok, %{protocols: ["chat"]}} = Options.new("ws://example.com/socket", "chat")

    assert {:ok, %{protocols: ["chat", "json"]}} =
             Options.new("ws://example.com/socket", ["chat", "json"])
  end

  test "rejects duplicate or invalid protocols" do
    assert {:error, :duplicate_protocol} =
             Options.new("ws://example.com/socket", ["chat", "chat"])

    assert {:error, :invalid_protocol} = Options.new("ws://example.com/socket", ["bad,token"])
    assert {:error, :invalid_protocol} = Options.new("ws://example.com/socket", [""])
  end

  test "normalizes flat init options" do
    assert {:ok, options} =
             Options.new("ws://example.com/socket", [],
               owner: self(),
               binary_type: :array_buffer,
               headers: %{"x-token" => "abc"},
               timeout: 10,
               connect_timeout: 5,
               ssl: [verify: :verify_none],
               socket_opts: [nodelay: true],
               max_message_size: 32,
               max_send_queue: 64
             )

    assert options.owner == self()
    assert options.binary_type == :array_buffer
    assert {"X-Token", "abc"} in options.headers
    assert options.timeout == 10
    assert options.connect_timeout == 5
    assert options.ssl == [verify: :verify_none]
    assert options.socket_opts == [nodelay: true]
    assert options.max_message_size == 32
    assert options.max_send_queue == 64
  end

  test "selects TLS backends from atom and string map options" do
    assert {:ok, %{tls_backend: :ex_ssl}} = Options.new("wss://example.com/socket")

    assert {:error, :invalid_tls_backend} =
             Options.new("wss://example.com/socket", [], tls_backend: :ssl)

    assert {:ok, %{tls_backend: :ex_ssl}} =
             Options.new("wss://example.com/socket", [], %{"tlsBackend" => "ex_ssl"})

    assert {:error, :invalid_tls_backend} =
             Options.new("wss://example.com/socket", [], %{"tls_backend" => "ssl"})
  end

  test "pins the configured TLS backend when options are constructed" do
    previous = Application.get_env(:http_core, :tls_backend)
    on_exit(fn -> restore_tls_backend(previous) end)

    Application.put_env(:http_core, :tls_backend, :ex_ssl)
    assert {:ok, options} = Options.new("wss://example.com/socket")
    assert options.tls_backend == :ex_ssl

    assert {:error, :invalid_tls_backend} =
             Options.new("wss://example.com/socket", [], tls_backend: :ssl)

    Application.put_env(:http_core, :tls_backend, :ssl)
    assert options.tls_backend == :ex_ssl
    assert {:error, :invalid_tls_backend} = Options.new("wss://example.com/socket")
  end

  test "rejects invalid TLS backend selections" do
    assert {:error, :invalid_tls_backend} =
             Options.new("wss://example.com/socket", [], tls_backend: :unknown)
  end

  test "validates telemetry URL omission and explicit replacement without changing transport" do
    actual = "ws://example.com/private-target?signature=secret"

    assert {:ok, %{telemetry_url: nil, url: ^actual}} =
             Options.new(actual, [], telemetry_url: nil)

    safe = URI.parse("ws://example.com")

    assert {:ok, %{telemetry_url: ^safe, url: ^actual}} =
             Options.new(actual, [], %{"telemetry_url" => "ws://example.com"})

    assert {:error, :invalid_telemetry_url} =
             Options.new(actual, [], telemetry_url: false)
  end

  defp restore_tls_backend(nil), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_tls_backend(value), do: Application.put_env(:http_core, :tls_backend, value)
end
