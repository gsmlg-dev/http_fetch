defmodule HTTP.HTTP2PoolKeyConfigurationTest do
  use ExUnit.Case, async: false

  alias HTTP.HTTP2.{PoolKey, WireProfile}
  alias HTTP.{FetchOptions, Request}

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

  test "omitted and nil pool backends inherit the shared effective configuration" do
    for backend <- [:ex_ssl, "ex_ssl"], options <- [[], [tls_backend: nil]] do
      Application.put_env(:http_core, :tls_backend, backend)
      assert {:ok, %{tls: %{backend: :ex_ssl}}} = key(options)
    end
  end

  test "invalid shared configuration fails while an explicit valid backend overrides it" do
    Application.put_env(:http_core, :tls_backend, :invalid)
    assert {:error, :invalid_tls_backend} = key([])
    assert {:error, :invalid_tls_backend} = key(tls_backend: nil)
    assert {:ok, %{tls: %{backend: :ex_ssl}}} = key(tls_backend: :ex_ssl)
  end

  test "constructed request policy survives rejected legacy reconfiguration" do
    options = FetchOptions.new(http_version: :http2)
    assert options.tls_backend == :ex_ssl
    transport = FetchOptions.to_transport_options(options)
    assert {:ok, before} = key(transport)

    Application.put_env(:http_core, :tls_backend, :ssl)
    assert {:ok, ^before} = key(transport)
    assert {:error, :invalid_tls_backend} = key([])
    assert {:error, :invalid_tls_backend} = key(tls_backend: :ssl)
  end

  defp key(options) do
    request = %Request{
      url: URI.parse("https://example.test/"),
      transport_options: options
    }

    PoolKey.build(request, WireProfile.native_v1(), :h2)
  end
end
