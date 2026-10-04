defmodule ExSslE2E.CaddyFingerprintTest do
  use ExUnit.Case, async: false

  @expected_ja3 "af851f784aed02a8b1e0b6ac13251239"
  @expected_ja4 "t13d0207h1_62ed6f6ca7ad_032b58638d3d"

  @tag :e2e
  test "Caddy observes the exact JA3 and JA4 of an authenticated ex_ssl request" do
    options = [
      host: System.get_env("EX_SSL_E2E_HOST", "127.0.0.1"),
      server_name: System.get_env("EX_SSL_E2E_SERVER_NAME", "localhost"),
      port: String.to_integer(System.get_env("EX_SSL_E2E_PORT", "8443")),
      ca_file: Path.expand("../certs/ca.pem", __DIR__),
      timeout: String.to_integer(System.get_env("EX_SSL_E2E_TIMEOUT_MS", "10000"))
    ]

    assert {:ok, response} = ExSslE2E.Client.request(options)
    assert response.status == 200

    assert response.body ==
             "control=ex_ssl-caddy-e2e\n" <>
               "ja3=#{@expected_ja3}\n" <>
               "ja4=#{@expected_ja4}\n"
  end
end
