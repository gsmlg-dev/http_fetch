defmodule HTTP.WebSocket.OptionsTest do
  use ExUnit.Case, async: false

  @trust_anchor_der Base.decode64!(
                      """
                      MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBleF9z
                      c2wtVGVzdC1Sb290MB4XDTI2MDkxMDA4MTIyNVoXDTM2MDkwNzA4MTIyNVowGzEZ
                      MBcGA1UEAwwQZXhfc3NsLVRlc3QtUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEP
                      ADCCAQoCggEBALchanJ7iECLuLQCyqF63X2XqxWenDFQpSB/9Qc8M01ee3tqXg/D
                      IatfELc5CMzXGuGkWBlzVc3wlzL//vzfZMA5jY6uDfI9n/mVlsH4hbCt7cjMbhHH
                      qYlp84niS3RSKBzuzoNP+n9fe24pfOlbRnOR1gBng7ByRDoGQsoSZx4DU3KCYuUp
                      oDUkTfyGX40KFuUME36IcF1/LlYM5d/PTjN/TLGG5jtmqh4Be5pGQlSLpu88JzGm
                      EtQ+0YuXcQ9KBYBFP/g6gXt5VxATSFxbn4phj7fK26eoJp9sPAZLIAo26aDKjs3p
                      mqe55DehYSubDA76ug6SAWaX+KoWp5xLOKECAwEAAaNmMGQwHwYDVR0jBBgwFoAU
                      hdlS4cW2w9qjB9P3WyBJCTazRMowEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8B
                      Af8EBAMCAQYwHQYDVR0OBBYEFIXZUuHFtsPaowfT91sgSQk2s0TKMA0GCSqGSIb3
                      DQEBCwUAA4IBAQAzE5L9eZQyel0/1PDsnhxK3CtNlsgV+9b4vfEDN9an6FPQeEhW
                      PBiok05Zj0Vidydr3JTyJ1LCyzG/pXzG4l+jPkz7P9LD8yWgGlKb1lA2cMtsf8bN
                      mnsJ0/SZoVT6XfnWxYOGgRdYr07iuurzxHHtclfU7zV0U3adEXm4btIu2T+gJXDB
                      Mol55IeSxwAmUNp7z4vLssA+Hw2EPVVKZC2Y3SFEsbbUAVP5S1zjFw+q9AK4miVZ
                      kte6jgtTfdHL8mZcyrIyFxFh91XEJZVNoGUqUd2KFqAKJXlmX0rPED2pgsqJNxW+
                      ZXyKoINVpC5VCv3l5WlLzjwONpj4JussZD1r
                      """,
                      ignore: :whitespace
                    )

  alias HTTP.WebSocket.Options

  test "HTTP3 is explicit, secure and rejects TCP transport selection" do
    assert {:ok, %{http_version: :http3, http3_reuse: false}} =
             Options.new("wss://example.test/socket", [],
               http_version: :http3,
               http3_reuse: false,
               ssl: [cacerts: [@trust_anchor_der]]
             )

    assert_invalid(:http3_requires_https, fn ->
      Options.new("ws://example.test/socket", [], http_version: :http3)
    end)

    assert_invalid(:connect_address_not_supported_for_quic, fn ->
      Options.new("wss://example.test/socket", [],
        http_version: :http3,
        connect_address: {127, 0, 0, 1},
        ssl: [cacerts: [@trust_anchor_der]]
      )
    end)
  end

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
      assert_invalid({:invalid_option, key}, fn ->
        Options.new("ws://example.test/socket", [], [{key, value}])
      end)
    end
  end

  test "connection address validation retains the URL TLS identity and route contract" do
    assert_invalid(:invalid_connect_address, fn ->
      Options.new("ws://example.test/socket", [], connect_address: "127.0.0.1")
    end)

    assert_invalid(:connect_address_unsupported_route, fn ->
      Options.new("ws://example.test/socket", [],
        connect_address: {127, 0, 0, 1},
        unix_socket: "/unused-websocket.sock"
      )
    end)

    assert_invalid(:connect_address_sni_conflict, fn ->
      Options.new("wss://example.test/socket", [],
        connect_address: {127, 0, 0, 1},
        ssl: [server_name_indication: ~c"other.test"]
      )
    end)

    assert_invalid(:connect_address_identity_conflict, fn ->
      Options.new("wss://example.test/socket", [],
        connect_address: {127, 0, 0, 1},
        ssl: [ex_ssl: [reference_identity: {:dns_id, "other.test"}]]
      )
    end)
  end

  test "pin validation uses the same first keyword values captured by the connection" do
    assert_invalid(:connect_address_sni_conflict, fn ->
      Options.new("wss://example.test/socket", [], [
        {:connect_address, {127, 0, 0, 1}},
        {:ssl, [server_name_indication: ~c"other.test"]},
        {:ssl, []}
      ])
    end)

    assert_invalid(:invalid_connect_address, fn ->
      Options.new("ws://example.test/socket", [], [
        {:connect_address, "127.0.0.1"},
        {:connect_address, {127, 0, 0, 1}}
      ])
    end)
  end

  test "proxy endpoints reject independently of frame-forwarding mode" do
    for mode <- [:browser, :proxy],
        init <- [
          [proxy: "http://proxy.example.test:8080"],
          %{"proxy" => "http://proxy.example.test:8080"}
        ] do
      init = Map.new(init) |> Map.put(:mode, mode)

      assert_invalid(:proxy_not_supported, fn ->
        Options.new("ws://example.test/socket", [], init)
      end)
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
      assert_invalid(:tls_over_unix_socket_not_supported, fn ->
        Options.new("#{scheme}://example.test/socket", [], init)
      end)
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
      assert_invalid({:invalid_option, :write_timeout}, fn ->
        Options.new("ws://example.com", [], write_timeout: value)
      end)
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

  test "ex_ssl is the only TLS engine and exposes no tls_backend option" do
    assert {:ok, options} = Options.new("wss://example.com/socket")
    refute Map.has_key?(options, :tls_backend)
    refute Keyword.has_key?(HTTP.Runtime.Options.transport_options(options), :tls_backend)
  end

  test "validates telemetry URL omission and explicit replacement without changing transport" do
    actual = "ws://example.com/private-target?signature=secret"

    assert {:ok, %{telemetry_url: nil, url: ^actual}} =
             Options.new(actual, [], telemetry_url: nil)

    safe = URI.parse("ws://example.com")

    assert {:ok, %{telemetry_url: ^safe, url: ^actual}} =
             Options.new(actual, [], %{"telemetry_url" => "ws://example.com"})

    assert_invalid(:invalid_telemetry_url, fn -> Options.new(actual, [], telemetry_url: false) end)
  end

  test "unknown keys, including the removed tls_backend, raise ArgumentError" do
    for init <- [[tls_backend: :ssl], %{"tls_backend" => :ssl}, [{"tlsBackend", :ssl}]] do
      key = init |> Enum.at(0) |> elem(0)

      assert_raise ArgumentError, "unknown HTTP.WebSocket option: #{inspect(key)}", fn ->
        Options.new("ws://example.com/socket", [], init)
      end
    end

    assert_raise ArgumentError, "unknown HTTP.WebSocket option: :tls_backend", fn ->
      HTTP.WebSocket.new("ws://example.com/socket", [], tls_backend: :ssl)
    end
  end

  test "malformed init raises ArgumentError at the public constructor" do
    for init <- [:bad, [:bad], [{1, :bad}]] do
      assert_invalid(:invalid_options, fn -> Options.new("ws://example.com/socket", [], init) end)

      assert_invalid(:invalid_options, fn ->
        HTTP.WebSocket.new("ws://example.com/socket", [], init)
      end)
    end
  end

  defp assert_invalid(reason, fun),
    do: assert_raise(ArgumentError, "invalid HTTP.WebSocket options: #{inspect(reason)}", fun)
end
