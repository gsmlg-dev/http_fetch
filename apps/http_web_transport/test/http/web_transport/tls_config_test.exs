defmodule HTTP.WebTransport.TLSConfigTest do
  use ExUnit.Case, async: false

  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.Transport.QUIC

  test "shared TCP TLS configuration does not affect QUIC options" do
    previous = Application.fetch_env(:http_core, :tls_backend)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:http_core, :tls_backend, value)
        :error -> Application.delete_env(:http_core, :tls_backend)
      end
    end)

    for backend <- [:ex_ssl, :invalid] do
      Application.put_env(:http_core, :tls_backend, backend)

      assert {:ok, %{backend: QUIC}} =
               Options.new("https://example.com/transport")
    end
  end
end
