defmodule HTTP.HTTPSProxyWireTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../support/fixtures", __DIR__)

  for backend <- [:ssl, :ex_ssl] do
    test "#{backend} TLS proxy forwards exact entities in absolute form and reuses by proxy credentials" do
      {port, peer} = proxy_peer()
      route = {:https, "localhost", port, [headers: [{"Proxy-Authorization", "Basic first"}]]}

      options = [
        proxy: route,
        tls_backend: unquote(backend),
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
        http1_reuse: true,
        http1_scope: "https-proxy-#{System.unique_integer([:positive])}",
        request_mode: :proxy,
        redirect: :manual,
        decode_body: false,
        telemetry: false,
        timeout: 3_000,
        headers: [{"Authorization", "Bearer origin"}]
      ]

      for method <- [:get, :delete] do
        assert %HTTP.Response{status: 200, body: "ok"} =
                 HTTP.fetch(
                   "http://origin.invalid:8080/entity?",
                   options ++ [method: method, body: <<0, 255, 10>>]
                 )
                 |> HTTP.Promise.await(4_000)

        assert_receive {:proxy_request, connection, head, <<0, 255, 10>>}, 2_000

        assert head =~
                 "#{String.upcase(to_string(method))} http://origin.invalid:8080/entity? HTTP/1.1\r\n"

        assert head =~ "Host: origin.invalid:8080\r\n"
        assert head =~ "Authorization: Bearer origin\r\n"
        assert head =~ "Proxy-Authorization: Basic first\r\n"

        if method == :get,
          do: Process.put(:proxy_connection, connection),
          else: assert(connection == Process.get(:proxy_connection))
      end

      other =
        Keyword.put(
          options,
          :proxy,
          {:https, "localhost", port, [headers: [{"Proxy-Authorization", "Basic second"}]]}
        )

      assert %HTTP.Response{status: 200} =
               response =
               HTTP.fetch(
                 "http://origin.invalid:8080/entity?",
                 Keyword.put(other, :stream_response, true)
               )
               |> HTTP.Promise.await(4_000)

      assert is_pid(response.stream)
      assert HTTP.Response.read_all(response) == "ok"

      assert_receive {:proxy_request, connection, head, ""}, 2_000
      refute connection == Process.get(:proxy_connection)
      assert head =~ "Proxy-Authorization: Basic second\r\n"
      assert Process.alive?(peer)
    end
  end

  for backend <- [:ssl, :ex_ssl] do
    test "#{backend} TLS proxy rejects a trusted certificate for the wrong hostname" do
      {port, _peer} = proxy_peer("pinned")

      assert {:error, reason} =
               HTTP.fetch("http://origin.invalid/",
                 proxy: {:https, "localhost", port, []},
                 tls_backend: unquote(backend),
                 ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")],
                 redirect: :manual,
                 telemetry: false,
                 timeout: 2_000
               )
               |> HTTP.Promise.await(3_000)

      assert_hostname_failure(unquote(backend), reason)
      assert_receive {:proxy_handshake_error, {:tls_alert, {alert, _}}}, 2_000
      assert alert == hostname_alert(unquote(backend))
      refute_receive {:proxy_request, _, _, _}, 0
    end
  end

  test "proxy TLS verifies proxy identity and rejects TLS-over-TLS origins before dialing" do
    {port, _peer} = proxy_peer()

    assert {:error, _reason} =
             HTTP.fetch("http://origin.invalid/",
               proxy: {:https, "127.0.0.1", port, []},
               ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")],
               redirect: :manual,
               timeout: 2_000
             )
             |> HTTP.Promise.await(3_000)

    refute_receive {:proxy_request, _, _, _}, 0

    assert {:error, :https_proxy_requires_http_origin} =
             HTTP.fetch("https://origin.invalid/",
               proxy: {:https, "localhost", port, []},
               redirect: :manual
             )
             |> HTTP.Promise.await(2_000)
  end

  test "unreachable TLS proxy never falls back to the origin" do
    {:ok, origin} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(origin)
    on_exit(fn -> :gen_tcp.close(origin) end)

    assert {:error, :econnrefused} =
             HTTP.fetch("http://127.0.0.1:#{port}/",
               proxy: {:https, "127.0.0.2", port, []},
               redirect: :manual,
               timeout: 500
             )
             |> HTTP.Promise.await(2_000)

    assert {:error, :timeout} = :gen_tcp.accept(origin, 0)
  end

  test "a streaming entity passes through proxy TLS without changing bytes" do
    {port, _peer} = proxy_peer()
    {:ok, stream} = HTTP.Stream.start_link(0)

    promise =
      HTTP.fetch("http://origin.invalid/upload",
        proxy: {:https, "localhost", port, []},
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
        method: :post,
        body: stream,
        duplex: "half",
        headers: [{"Content-Length", "3"}],
        redirect: :manual,
        request_mode: :proxy,
        decode_body: false,
        telemetry: false,
        timeout: 3_000
      )

    assert :ok = HTTP.Stream.chunk(stream, <<0, 255, 10>>, 2_000)
    HTTP.Stream.finish(stream)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise, 4_000)
    assert_receive {:proxy_request, _connection, head, <<0, 255, 10>>}, 2_000
    assert head =~ "POST http://origin.invalid/upload HTTP/1.1\r\n"
    refute String.downcase(head) =~ "transfer-encoding"
  end

  for backend <- [:ssl, :ex_ssl], stop <- [:abort, :deadline] do
    test "#{backend} TLS proxy handshake is bounded by #{stop}" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, {_, port}} = :inet.sockname(listener)
      on_exit(fn -> :gen_tcp.close(listener) end)
      controller = HTTP.AbortController.new()

      promise =
        HTTP.fetch("http://origin.invalid/",
          proxy: {:https, "localhost", port, []},
          tls_backend: unquote(backend),
          signal: controller,
          redirect: :manual,
          timeout: if(unquote(stop) == :deadline, do: 2_000, else: 5_000)
        )

      {:ok, socket} = :gen_tcp.accept(listener, 2_000)
      assert {:ok, <<22, _::binary>>} = :gen_tcp.recv(socket, 0, 2_000)
      if unquote(stop) == :abort, do: HTTP.AbortController.abort(controller)
      assert {:error, reason} = HTTP.Promise.await(promise, 3_000)
      assert_handshake_stop(unquote(stop), reason)
      await_tls_close(socket)
      :gen_tcp.close(socket)
    end
  end

  defp assert_handshake_stop(:abort, reason), do: assert(reason == :aborted)

  defp assert_handshake_stop(:deadline, reason),
    do: assert(reason in [:request_timeout, :connect_timeout, :timeout])

  defp proxy_peer(certificate \\ "localhost") do
    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1},
        certfile: Path.join(@fixtures, "#{certificate}.pem"),
        keyfile: Path.join(@fixtures, "#{certificate}.key"),
        alpn_preferred_protocols: ["http/1.1"]
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)
    parent = self()
    peer = spawn(fn -> accept(listener, parent) end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)

    {port, peer}
  end

  defp assert_hostname_failure(:ssl, reason) do
    assert {:tls_alert, {:bad_certificate, _}} = reason
    assert inspect(reason) =~ "hostname_check_failed"
  end

  defp assert_hostname_failure(:ex_ssl, reason) do
    assert {:tls_alert, {:certificate_unknown, _}} = reason
  end

  defp hostname_alert(:ssl), do: :bad_certificate
  defp hostname_alert(:ex_ssl), do: :certificate_unknown

  defp accept(listener, parent) do
    case :ssl.transport_accept(listener) do
      {:ok, socket} ->
        child =
          spawn_link(fn ->
            receive do
              :ready -> handshake(socket, parent)
            end
          end)

        :ok = :ssl.controlling_process(socket, child)
        send(child, :ready)
        accept(listener, parent)

      {:error, :closed} ->
        :ok
    end
  end

  defp handshake(socket, parent) do
    case :ssl.handshake(socket, 3_000) do
      {:ok, socket} ->
        serve(socket, parent, "")

      {:error, reason} ->
        send(parent, {:proxy_handshake_error, reason})
        :ssl.close(socket)
    end
  end

  defp serve(socket, parent, bytes) do
    case :binary.match(bytes, "\r\n\r\n") do
      {at, 4} ->
        <<head::binary-size(at + 4), rest::binary>> = bytes

        length =
          case Regex.run(~r/\r\ncontent-length:\s*(\d+)/i, head) do
            [_, size] -> String.to_integer(size)
            nil -> 0
          end

        {body, rest} = read_body(socket, rest, length)
        send(parent, {:proxy_request, self(), head, body})
        :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        serve(socket, parent, rest)

      :nomatch ->
        case :ssl.recv(socket, 0, :infinity) do
          {:ok, chunk} -> serve(socket, parent, bytes <> chunk)
          {:error, :closed} -> :ssl.close(socket)
        end
    end
  end

  defp read_body(_socket, bytes, length) when byte_size(bytes) >= length do
    <<body::binary-size(length), rest::binary>> = bytes
    {body, rest}
  end

  defp read_body(socket, bytes, length) do
    {:ok, chunk} = :ssl.recv(socket, 0, 3_000)
    read_body(socket, bytes <> chunk, length)
  end

  defp await_tls_close(socket, alerts \\ <<>>) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, bytes} ->
        assert byte_size(alerts) + byte_size(bytes) <= 64
        await_tls_close(socket, alerts <> bytes)

      {:error, :closed} ->
        assert_alert_records(alerts)

      other ->
        flunk("TLS proxy did not close: #{inspect(other)}")
    end
  end

  defp assert_alert_records(<<>>), do: :ok

  defp assert_alert_records(<<21, 3, _minor, size::16, _alert::binary-size(size), rest::binary>>),
    do: assert_alert_records(rest)
end
