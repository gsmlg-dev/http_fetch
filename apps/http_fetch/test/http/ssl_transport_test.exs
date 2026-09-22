defmodule HTTP.SSLTransportTest do
  use ExUnit.Case

  @certfile Path.expand("../support/fixtures/localhost.pem", __DIR__)
  @cacertfile Path.expand("../support/fixtures/localhost-ca.pem", __DIR__)
  @keyfile Path.expand("../support/fixtures/localhost.key", __DIR__)

  describe "https transport" do
    test "rejects explicit TLS backends for HTTP/3 through the promise" do
      for tls_backend <- [false, :unknown, "ssl", "ex_ssl"] do
        assert {:error, :tls_backend_not_supported_for_quic} =
                 "https://127.0.0.1:1/secure"
                 |> HTTP.fetch(http_version: :http3, tls_backend: tls_backend)
                 |> HTTP.Promise.await()
      end
    end

    test "does not resolve shared TLS configuration for HTTP/3" do
      previous = Application.get_env(:http_core, :tls_backend)
      on_exit(fn -> restore_tls_backend(previous) end)
      Application.put_env(:http_core, :tls_backend, :invalid)

      assert %HTTP.FetchOptions{http_version: :http3, tls_backend: nil} =
               HTTP.FetchOptions.new(http_version: :http3)
    end

    test "rejects unsupported ex_ssl socket options through HTTP.fetch" do
      for socket_opts <- [[nodelay: :invalid], [send_timeout_close: false]] do
        assert {:error, {:options, _reason}} =
                 "https://127.0.0.1:1/secure"
                 |> HTTP.fetch(tls_backend: :ex_ssl, socket_opts: socket_opts)
                 |> HTTP.Promise.await()
      end
    end

    test "propagates ex_ssl profile and ALPN conflicts through HTTP.fetch" do
      profile = %SSL.ClientHello.WireProfile{extensions: [{:alpn, ["http/1.1"]}]}

      assert {:error, {:options, {:alpn_advertised_protocols, :profile_conflict}}} =
               "https://127.0.0.1:1/secure"
               |> HTTP.fetch(
                 tls_backend: :ex_ssl,
                 http_version: :http2,
                 ssl: [
                   alpn_advertised_protocols: ["h2"],
                   ex_ssl: [profile: profile]
                 ]
               )
               |> HTTP.Promise.await()
    end

    test "rejects self-signed certificates by default" do
      url = start_https_server!(fn socket -> send_response(socket, "secure") end)

      assert {:error, _reason} = url |> HTTP.fetch() |> HTTP.Promise.await()
    end

    test "fetches responses over ssl" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, request} = recv_headers(socket, <<>>)
          assert request =~ "GET /secure HTTP/1.1\r\n"

          send_response(socket, "secure")
        end)

      response =
        url
        |> HTTP.fetch(ssl: [verify: :verify_none])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert HTTP.Response.read_all(response) == "secure"
    end

    test "honors caller cacertfile with verify peer" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, request} = recv_headers(socket, <<>>)
          assert request =~ "GET /secure HTTP/1.1\r\n"

          send_response(socket, "trusted")
        end)

      response =
        url
        |> HTTP.fetch(ssl: [cacertfile: @cacertfile])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert HTTP.Response.read_all(response) == "trusted"
    end

    test "fetches a verified response through ex_ssl" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, request} = recv_headers(socket, <<>>)
          assert request =~ "GET /secure HTTP/1.1\r\n"
          send_response(socket, "ex-ssl")
        end)

      response =
        url
        |> HTTP.fetch(tls_backend: :ex_ssl, ssl: [cacertfile: @cacertfile])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert HTTP.Response.read_all(response) == "ex-ssl"
    end

    test "streams chunked responses through ex_ssl" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)

          :ok =
            :ssl.send(socket, [
              "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
              "5\r\nchunk\r\n",
              "2\r\ned\r\n",
              "0\r\n\r\n"
            ])
        end)

      response =
        url
        |> HTTP.fetch(tls_backend: :ex_ssl, ssl: [cacertfile: @cacertfile])
        |> HTTP.Promise.await()

      assert is_pid(response.stream)
      assert HTTP.Response.read_all(response) == "chunked"
    end

    test "streams close-delimited responses through ex_ssl" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-delimited")
        end)

      controller = HTTP.AbortController.new()

      response =
        url
        |> HTTP.fetch(
          signal: controller,
          tls_backend: :ex_ssl,
          ssl: [cacertfile: @cacertfile]
        )
        |> HTTP.Promise.await()

      assert is_pid(response.stream)

      owner = :sys.get_state(controller).request_id
      assert {:ssl_closed, %SSL.Socket{pid: socket_pid}} = await_owner_close(owner)

      socket_monitor = Process.monitor(socket_pid)
      assert_receive {:DOWN, ^socket_monitor, :process, ^socket_pid, _reason}, 2_000

      assert HTTP.Response.read_all(response) == "close-delimited"
    end

    test "uploads large buffered bodies through ex_ssl" do
      body = :binary.copy("u", HTTP.Config.streaming_threshold() + 1)

      url =
        start_https_server!(fn socket ->
          assert %{body: ^body, headers: %{"content-length" => content_length}} =
                   recv_request(socket)

          assert content_length == Integer.to_string(byte_size(body))
          send_response(socket, "uploaded")
        end)

      response =
        url
        |> HTTP.fetch(
          method: :post,
          body: body,
          tls_backend: :ex_ssl,
          ssl: [cacertfile: @cacertfile]
        )
        |> HTTP.Promise.await()

      assert HTTP.Response.read_all(response) == "uploaded"
    end

    test "cancels an in-flight ex_ssl request" do
      test_pid = self()

      url =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          send(test_pid, :request_received)
          send(test_pid, {:server_recv_after_abort, :ssl.recv(socket, 0, 5_000)})
        end)

      controller = HTTP.AbortController.new()

      promise =
        HTTP.fetch(url,
          signal: controller,
          tls_backend: :ex_ssl,
          ssl: [cacertfile: @cacertfile]
        )

      assert_receive :request_received, 2_000
      :ok = HTTP.AbortController.abort(controller)

      assert {:error, :aborted} = HTTP.Promise.await(promise)
      assert_receive {:server_recv_after_abort, {:error, :closed}}, 2_000
    end

    test "times out an ex_ssl request waiting for response headers" do
      test_pid = self()

      url =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          send(test_pid, :request_received)
          send(test_pid, {:server_recv_after_timeout, :ssl.recv(socket, 0, 5_000)})
        end)

      promise =
        HTTP.fetch(url,
          timeout: 500,
          tls_backend: :ex_ssl,
          ssl: [cacertfile: @cacertfile]
        )

      assert_receive :request_received, 2_000
      assert {:error, :request_timeout} = HTTP.Promise.await(promise, 2_000)
      assert_receive {:server_recv_after_timeout, {:error, :closed}}, 2_000
    end

    test "uses TLS backend transport options on direct requests" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, request} = recv_headers(socket, <<>>)
          assert request =~ "GET /secure HTTP/1.1\r\n"
          send_response(socket, "direct")
        end)

      response =
        HTTP.SocketClient.request(%HTTP.Request{
          url: URI.parse(url),
          transport_options: [tls_backend: "ex_ssl", ssl: [cacertfile: @cacertfile]]
        })

      assert response.status == 200
      assert HTTP.Response.read_all(response) == "direct"
    end

    test "pins the configured backend through HTTPS redirects" do
      test_pid = self()

      destination =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          send_response(socket, "redirected")
        end)

      source =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          send(test_pid, {:redirect_request_received, self()})

          receive do
            :send_redirect ->
              :ok =
                :ssl.send(socket, [
                  "HTTP/1.1 302 Found\r\n",
                  "Location: ",
                  destination,
                  "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ])
          end
        end)

      previous = Application.get_env(:http_core, :tls_backend)
      on_exit(fn -> restore_tls_backend(previous) end)
      Application.put_env(:http_core, :tls_backend, :ex_ssl)

      promise = HTTP.fetch(source, ssl: [cacertfile: @cacertfile])
      assert_receive {:redirect_request_received, redirect_server}
      Application.put_env(:http_core, :tls_backend, :invalid)
      send(redirect_server, :send_redirect)

      assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise)
      assert HTTP.Response.read_all(response) == "redirected"
    end

    test "streams large responses over ssl" do
      body = String.duplicate("s", HTTP.Config.streaming_threshold() + 1)

      url =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          send_response(socket, body)
        end)

      response =
        url
        |> HTTP.fetch(ssl: [verify: :verify_none])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert is_pid(response.stream)
      assert response.body == response.stream
      assert HTTP.Response.read_all(response) == body
    end

    test "streams large verified responses through ex_ssl" do
      body = String.duplicate("s", HTTP.Config.streaming_threshold() + 1)

      url =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          send_response(socket, body)
        end)

      response =
        url
        |> HTTP.fetch(tls_backend: "ex_ssl", ssl: [cacertfile: @cacertfile])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert is_pid(response.stream)
      assert HTTP.Response.read_all(response) == body
    end
  end

  defp start_https_server!(handler) when is_function(handler, 1) do
    {:ok, listen_socket} =
      :ssl.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        certfile: @certfile,
        keyfile: @keyfile
      ])

    {:ok, {{127, 0, 0, 1}, port}} = :ssl.sockname(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, transport_socket} = :ssl.transport_accept(listen_socket, 5_000)

        case :ssl.handshake(transport_socket) do
          {:ok, socket} ->
            handler.(socket)
            :ssl.close(socket)

          {:error, _reason} ->
            :ok
        end

        :ssl.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :ssl.close(listen_socket)
    end)

    "https://127.0.0.1:#{port}/secure"
  end

  defp recv_headers(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      {:ok, acc}
    else
      case :ssl.recv(socket, 0, 5_000) do
        {:ok, data} -> recv_headers(socket, acc <> data)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp await_owner_close(owner) do
    deadline = System.monotonic_time(:millisecond) + 2_000
    wait_for_owner_close(owner, deadline)
  end

  defp wait_for_owner_close(owner, deadline) do
    case Process.info(owner, :messages) do
      {:messages, messages} ->
        case Enum.find(messages, &match?({:ssl_closed, %SSL.Socket{}}, &1)) do
          nil ->
            if System.monotonic_time(:millisecond) < deadline do
              Process.sleep(10)
              wait_for_owner_close(owner, deadline)
            else
              flunk("fetch owner did not queue an ExSSL close message")
            end

          message ->
            message
        end

      nil ->
        flunk("fetch owner exited before its queued ExSSL close could be observed")
    end
  end

  defp recv_request(socket) do
    {head, rest} = recv_header_block(socket, <<>>)
    [_request_line | header_lines] = String.split(head, "\r\n")

    headers =
      header_lines
      |> Enum.map(fn line ->
        [name, value] = String.split(line, ":", parts: 2)
        {String.downcase(name), String.trim(value)}
      end)
      |> Map.new()

    content_length = headers |> Map.fetch!("content-length") |> String.to_integer()
    %{headers: headers, body: recv_body(socket, rest, content_length)}
  end

  defp recv_header_block(socket, acc) do
    case :binary.match(acc, "\r\n\r\n") do
      {index, 4} ->
        head = binary_part(acc, 0, index)
        rest = binary_part(acc, index + 4, byte_size(acc) - index - 4)
        {head, rest}

      :nomatch ->
        {:ok, data} = :ssl.recv(socket, 0, 5_000)
        recv_header_block(socket, acc <> data)
    end
  end

  defp recv_body(_socket, data, content_length) when byte_size(data) >= content_length do
    binary_part(data, 0, content_length)
  end

  defp recv_body(socket, data, content_length) do
    {:ok, more} = :ssl.recv(socket, content_length - byte_size(data), 5_000)
    recv_body(socket, data <> more, content_length)
  end

  defp send_response(socket, body) do
    :ok =
      :ssl.send(socket, [
        "HTTP/1.1 200 OK\r\n",
        "Content-Length: ",
        Integer.to_string(byte_size(body)),
        "\r\n",
        "Connection: close\r\n",
        "\r\n",
        body
      ])

    :ssl.close(socket)
  end

  defp restore_tls_backend(nil), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_tls_backend(backend), do: Application.put_env(:http_core, :tls_backend, backend)
end
