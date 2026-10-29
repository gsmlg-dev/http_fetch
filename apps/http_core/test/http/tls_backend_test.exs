defmodule HTTP.TLSBackendTest do
  use ExUnit.Case, async: false

  alias HTTP.TLSBackend

  setup do
    previous = Application.fetch_env(:http_core, :tls_backend)
    Application.delete_env(:http_core, :tls_backend)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:http_core, :tls_backend, value)
        :error -> Application.delete_env(:http_core, :tls_backend)
      end
    end)
  end

  test "defaults to ExSSL and accepts explicit ExSSL selection" do
    assert {:ok, :ex_ssl} = TLSBackend.resolve()
    assert {:ok, :ex_ssl} = TLSBackend.resolve(:ex_ssl)
    assert {:ok, :ex_ssl} = TLSBackend.resolve("ex_ssl")
    assert HTTP.Transport.ExSSL = TLSBackend.transport(:ex_ssl)
  end

  test "nil inherits the configured backend and explicit options override it" do
    Application.put_env(:http_core, :tls_backend, :ex_ssl)
    assert {:ok, :ex_ssl} = TLSBackend.resolve(nil)
    Application.put_env(:http_core, :tls_backend, "ssl")
    assert {:error, :invalid_tls_backend} = TLSBackend.resolve()
    assert {:ok, :ex_ssl} = TLSBackend.resolve(:ex_ssl)
  end

  test "legacy OTP selectors and configuration fail instead of changing provider" do
    for value <- [:ssl, "ssl"] do
      assert {:error, :invalid_tls_backend} = TLSBackend.resolve(value)
      Application.put_env(:http_core, :tls_backend, value)
      assert {:error, :invalid_tls_backend} = TLSBackend.resolve()
      assert {:ok, :ex_ssl} = TLSBackend.resolve(:ex_ssl)
    end
  end

  test "invalid configuration or selection fails instead of falling back" do
    Application.put_env(:http_core, :tls_backend, :unknown)
    assert {:error, :invalid_tls_backend} = TLSBackend.resolve()
    assert {:ok, :ex_ssl} = TLSBackend.resolve(:ex_ssl)

    for value <- [:unknown, "SSL", false, 1, %{}] do
      assert {:error, :invalid_tls_backend} = TLSBackend.resolve(value)
    end
  end
end
