defmodule HTTP.EventSource.OptionsTest do
  use ExUnit.Case, async: false

  alias HTTP.EventSource.Options

  test "normalizes supported URL schemes" do
    assert {:ok, %{uri: %{scheme: "http"}, url: "http://example.com/events"}} =
             Options.new("http://example.com/events")

    assert {:ok, %{uri: %{scheme: "https"}, url: "https://example.com/events"}} =
             Options.new("https://example.com/events")
  end

  test "rejects unsupported URLs" do
    assert {:error, {:unsupported_scheme, "ftp"}} = Options.new("ftp://example.com/events")
    assert {:error, {:unsupported_scheme, nil}} = Options.new("/events")
  end

  test "normalizes flat init options" do
    assert {:ok, options} =
             Options.new("http://example.com/events",
               owner: self(),
               with_credentials: true,
               headers: %{"x-token" => "abc"},
               last_event_id: "42",
               reconnect_time: 10,
               max_reconnect_time: 20,
               connect_timeout: 30,
               idle_timeout: 40,
               ssl: [verify: :verify_none],
               socket_opts: [nodelay: true],
               unix_socket: "/tmp/events.sock",
               max_line_size: 50
             )

    assert options.owner == self()
    assert options.with_credentials == true
    assert {"X-Token", "abc"} in options.headers
    assert options.last_event_id == "42"
    assert options.reconnect_time == 10
    assert options.max_reconnect_time == 20
    assert options.connect_timeout == 30
    assert options.idle_timeout == 40
    assert options.ssl == [verify: :verify_none]
    assert options.socket_opts == [nodelay: true]
    assert options.unix_socket == "/tmp/events.sock"
    assert options.max_line_size == 50
  end

  test "normalizes string init keys" do
    assert {:ok, %{with_credentials: true, last_event_id: "abc"}} =
             Options.new("http://example.com/events", %{
               "withCredentials" => true,
               "lastEventId" => "abc"
             })
  end

  test "selects TLS backends from atom and string map options" do
    assert {:ok, %{tls_backend: :ssl}} =
             Options.new("https://example.com/events", tls_backend: :ssl)

    assert {:ok, %{tls_backend: :ex_ssl}} =
             Options.new("https://example.com/events", %{"tlsBackend" => "ex_ssl"})

    assert {:ok, %{tls_backend: :ssl}} =
             Options.new("https://example.com/events", %{"tls_backend" => "ssl"})
  end

  test "pins the configured TLS backend when options are constructed" do
    previous = Application.get_env(:http_core, :tls_backend)
    on_exit(fn -> restore_tls_backend(previous) end)

    Application.put_env(:http_core, :tls_backend, :ex_ssl)
    assert {:ok, options} = Options.new("https://example.com/events")
    assert options.tls_backend == :ex_ssl

    assert {:ok, %{tls_backend: :ssl}} =
             Options.new("https://example.com/events", tls_backend: :ssl)

    Application.put_env(:http_core, :tls_backend, :ssl)
    assert options.tls_backend == :ex_ssl
    assert {:ok, %{tls_backend: :ssl}} = Options.new("https://example.com/events")
  end

  test "rejects invalid init options" do
    assert {:error, :invalid_owner} = Options.new("http://example.com/events", owner: :bad)

    assert {:error, :invalid_last_event_id} =
             Options.new("http://example.com/events", last_event_id: "bad\nid")

    assert {:error, :invalid_reconnect_time} =
             Options.new("http://example.com/events", reconnect_time: -1)

    assert {:error, :invalid_tls_backend} =
             Options.new("https://example.com/events", tls_backend: :unknown)
  end

  defp restore_tls_backend(nil), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_tls_backend(value), do: Application.put_env(:http_core, :tls_backend, value)
end
