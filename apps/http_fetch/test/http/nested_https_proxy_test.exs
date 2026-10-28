defmodule HTTP.NestedHTTPSProxyTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "verified HTTPS proxy CONNECT carries independently verified origin TLS and credentials stay outside" do
    {url, proxy, peer} = nested_peer(:serve)

    promise =
      HTTP.fetch(url, options(proxy) ++ [headers: [{"Authorization", "Bearer origin-only"}]])

    assert %HTTP.Response{status: 200, body: "ok"} = HTTP.Promise.await(promise, 4_000)
    assert_receive {:proxy_connect, ^peer, connect}, 2_000
    assert connect =~ "CONNECT localhost:"
    assert connect =~ "Proxy-Authorization: Basic proxy-only"
    refute connect =~ "origin-only"
    assert_receive {:origin_request, request}, 2_000
    assert request =~ "Authorization: Bearer origin-only"
    refute request =~ "proxy-only"
    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
    assert_receive {:proxy_closed, ^peer}, 2_000
    assert_receive {:origin_closed, _}, 2_000
  end

  test "both TLS layers retain their own hostname verification" do
    for layer <- [:proxy, :origin] do
      {url, proxy, peer} = nested_peer(:serve)
      options = options(proxy)

      options =
        if layer == :proxy do
          {:https, host, port, proxy_opts} = proxy
          tls = proxy_opts[:ssl] ++ [server_name_indication: ~c"wrong.invalid"]
          Keyword.put(options, :proxy, {:https, host, port, Keyword.put(proxy_opts, :ssl, tls)})
        else
          Keyword.update!(
            options,
            :ssl,
            &Keyword.put(&1, :server_name_indication, ~c"wrong.invalid")
          )
        end

      promise = HTTP.fetch(url, options)
      assert {:error, _} = HTTP.Promise.await(promise, 4_000)

      assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000) in [
               :ok,
               {:error, :cleanup_unconfirmed}
             ]

      if layer == :proxy do
        assert_receive {:proxy_handshake_failed, ^peer, _}, 2_000
        refute_receive {:proxy_connect, ^peer, _}, 0
        refute_receive {:origin_accepted, _}, 0
      else
        assert_receive {:origin_handshake_failed, _}, 2_000
        refute_receive {:origin_request, _}, 0
      end
    end
  end

  test "proxy CONNECT refusal never reaches the origin" do
    {url, proxy, peer} = nested_peer(:reject)
    promise = HTTP.fetch(url, options(proxy))
    assert {:error, {:proxy_connect_status, 407}} = HTTP.Promise.await(promise, 4_000)
    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
    assert_receive {:proxy_connect, ^peer, _}, 2_000
    refute_receive {:origin_accepted, _}, 0
  end

  for stage <- [:connect_gate, :inner_gate, :origin_gate], stop <- [:abort, :deadline] do
    test "#{stop} bounds nested TLS during #{stage} with truthful cleanup" do
      stage = unquote(stage)
      {url, proxy, peer} = nested_peer(stage)
      promise = HTTP.fetch(url, stop_options(options(proxy), stage, unquote(stop)))
      assert_receive {:stage, ^stage}, 2_000

      result =
        if unquote(stop) == :abort do
          completion =
            HTTP.RequestCompletion.abort_and_await(HTTP.Promise.completion(promise), 2_000)

          assert {:error, :aborted} = HTTP.Promise.await(promise, 2_000)
          completion
        else
          assert {:error, reason} = HTTP.Promise.await(promise, 2_000)
          assert reason == deadline_reason(stage)
          HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
        end

      assert_cleanup(stage, result, HTTP.Promise.completion(promise))
      assert_receive {:proxy_closed, ^peer}, 2_000
      assert_origin_closed(stage)
    end
  end

  test "header-first raw response cancellation joins both TLS sessions" do
    {url, proxy, peer} = nested_peer(:stream_gate)
    promise = HTTP.fetch(url, options(proxy) ++ [stream_response: true, decode_body: false])
    assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, 3_000)
    assert is_pid(response.stream)
    assert :ok = HTTP.RequestCompletion.abort_and_await(HTTP.Promise.completion(promise), 2_000)
    assert_receive {:proxy_closed, ^peer}, 2_000
    assert_receive {:origin_closed, {:error, :closed}}, 2_000
  end

  test "fixed-length raw streaming upload preserves bytes through nested TLS" do
    {url, proxy, _peer} = nested_peer(:serve)
    {:ok, upload} = HTTP.Stream.start_link(0)

    promise =
      HTTP.fetch(
        url,
        options(proxy) ++
          [
            method: :post,
            request_mode: :proxy,
            body: upload,
            duplex: :half,
            headers: [{"Content-Length", "3"}],
            decode_body: false
          ]
      )

    assert :ok = HTTP.Stream.chunk(upload, <<0, 255, 42>>, 2_000)
    HTTP.Stream.finish(upload)
    assert %HTTP.Response{body: "ok"} = HTTP.Promise.await(promise, 4_000)
    assert_receive {:origin_request, request}, 2_000
    assert String.ends_with?(request, <<0, 255, 42>>)
    refute String.downcase(request) =~ "transfer-encoding"
    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
  end

  test "HTTP/2 ALPN and traffic stay inside the verified HTTPS proxy tunnel" do
    {url, proxy, _peer} = nested_peer(:http2)
    promise = HTTP.fetch(url, options(proxy) ++ [http_version: :http2, http2_reuse: false])

    assert %HTTP.Response{status: 200, http_version: :http2} =
             response = HTTP.Promise.await(promise, 4_000)

    assert "ok" = HTTP.Response.text(response)
    assert_receive {:h2_request, 1}, 2_000
    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
  end

  for stop <- [:abort, :deadline] do
    test "#{stop} before proxy TLS completes retains missing setup evidence" do
      parent = self()
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, {_, port}} = :inet.sockname(listener)

      peer =
        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)
          {:ok, _client_hello} = :gen_tcp.recv(socket, 0, 2_000)
          send(parent, :proxy_tls_pending)
          result = :gen_tcp.recv(socket, 0, 3_000)
          send(parent, {:proxy_tcp_closed, result})
          :gen_tcp.close(socket)
        end)

      on_exit(fn ->
        :gen_tcp.close(listener)
        if Process.alive?(peer), do: Process.exit(peer, :kill)
      end)

      proxy = {:https, "127.0.0.1", port, []}

      promise =
        HTTP.fetch(
          "https://origin.invalid/",
          stop_options(options(proxy), :proxy_tls, unquote(stop))
        )

      assert_receive :proxy_tls_pending, 2_000
      handle = HTTP.Promise.completion(promise)

      if unquote(stop) == :abort do
        assert {:error, :cleanup_unconfirmed} =
                 HTTP.RequestCompletion.abort_and_await(handle, 3_000)

        assert {:error, :aborted} = HTTP.Promise.await(promise, 1_000)
      else
        assert {:error, :connect_timeout} = HTTP.Promise.await(promise, 2_000)
        assert {:error, :cleanup_unconfirmed} = HTTP.RequestCompletion.await(handle, 3_000)
      end

      assert_receive {:proxy_tcp_closed, {:error, :closed}}, 1_000
    end
  end

  test "invalid native ExSSL origin policy fails before proxy authentication or dialing" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    assert {:error, {:options, {:versions, :unsupported_or_invalid}}} =
             HTTP.fetch("https://origin.invalid/",
               proxy: {:https, "127.0.0.1", port, []},
               tls_backend: :ex_ssl,
               ssl: [versions: [:invalid]],
               redirect: :manual,
               telemetry: false
             )
             |> HTTP.Promise.await(2_000)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  defp stop_options(options, :connect_gate, :deadline) do
    Keyword.update!(options, :proxy, fn {scheme, host, port, proxy_options} ->
      {scheme, host, port, Keyword.put(proxy_options, :timeout, 500)}
    end)
  end

  defp stop_options(options, :origin_gate, :deadline), do: Keyword.put(options, :timeout, 500)
  defp stop_options(options, _stage, :deadline), do: Keyword.put(options, :connect_timeout, 500)
  defp stop_options(options, _stage, :abort), do: options

  defp deadline_reason(:connect_gate), do: :proxy_tunnel_timeout
  defp deadline_reason(:origin_gate), do: :request_timeout
  defp deadline_reason(_stage), do: :connect_timeout

  defp assert_cleanup(:inner_gate, result, handle) do
    assert result in [{:error, :cleanup_pending}, {:error, :cleanup_unconfirmed}]
    assert {:error, :cleanup_unconfirmed} = HTTP.RequestCompletion.await(handle, 3_000)
  end

  defp assert_cleanup(_stage, result, _handle), do: assert(result == :ok)

  defp assert_origin_closed(:origin_gate),
    do: assert_receive({:origin_closed, {:error, :closed}}, 2_000)

  defp assert_origin_closed(_stage), do: :ok

  defp options(proxy) do
    [
      proxy: proxy,
      tls_backend: :ssl,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
      redirect: :manual,
      telemetry: false,
      timeout: 3_000,
      connect_timeout: 2_500
    ]
  end

  defp nested_peer(mode) do
    parent = self()

    origin_opts =
      server_opts("localhost") ++
        [alpn_preferred_protocols: [if(mode == :http2, do: "h2", else: "http/1.1")]]

    {:ok, origin_listener} = :ssl.listen(0, origin_opts)
    {:ok, {_, origin_port}} = :ssl.sockname(origin_listener)

    origin =
      spawn_link(fn ->
        {:ok, raw} = :ssl.transport_accept(origin_listener, 4_000)
        send(parent, {:origin_accepted, self()})

        case :ssl.handshake(raw, 4_000) do
          {:ok, socket} ->
            serve_origin(socket, parent, mode)

            result = await_closed(socket)
            send(parent, {:origin_closed, result})
            :ssl.close(socket)

          {:error, reason} ->
            send(parent, {:origin_handshake_failed, reason})
            :ssl.close(raw)
        end
      end)

    {:ok, proxy_listener} =
      :ssl.listen(0, Keyword.put(server_opts("pinned-ip"), :ip, {127, 0, 0, 2}))

    {:ok, {_, proxy_port}} = :ssl.sockname(proxy_listener)

    peer =
      spawn_link(fn ->
        {:ok, raw} = :ssl.transport_accept(proxy_listener, 4_000)

        case :ssl.handshake(raw, 4_000) do
          {:ok, socket} ->
            {:ok, connect} = :ssl.recv(socket, 0, 4_000)
            send(parent, {:proxy_connect, self(), connect})

            case mode do
              :reject ->
                :ssl.send(
                  socket,
                  "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
                )

              :connect_gate ->
                send(parent, {:stage, mode})
                await_closed(socket)

              :inner_gate ->
                :ssl.send(socket, "HTTP/1.1 200 Connection Established\r\n\r\n")
                {:ok, _hello} = :ssl.recv(socket, 0, 4_000)
                send(parent, {:stage, mode})
                await_closed(socket)

              _ ->
                {:ok, upstream} =
                  :gen_tcp.connect(~c"localhost", origin_port, [:binary, active: :once], 2_000)

                :ssl.send(socket, "HTTP/1.1 200 Connection Established\r\n\r\n")
                :ssl.setopts(socket, active: :once)
                relay(socket, upstream)
            end

            :ssl.close(socket)
            send(parent, {:proxy_closed, self()})

          {:error, reason} ->
            send(parent, {:proxy_handshake_failed, self(), reason})
            :ssl.close(raw)
        end
      end)

    on_exit(fn ->
      :ssl.close(origin_listener)
      :ssl.close(proxy_listener)
      for pid <- [origin, peer], Process.alive?(pid), do: Process.exit(pid, :kill)
    end)

    proxy =
      {:https, "127.0.0.2", proxy_port,
       [
         ssl: [cacertfile: Path.join(@fixtures, "pinned-ip-ca.pem")],
         headers: [{"Proxy-Authorization", "Basic proxy-only"}]
       ]}

    {"https://localhost:#{origin_port}/nested", proxy, peer}
  end

  defp serve_origin(socket, parent, :http2), do: serve_http2(socket, parent)

  defp serve_origin(socket, parent, mode) do
    request = recv_request(socket)
    send(parent, {:origin_request, request})

    case mode do
      :origin_gate -> send(parent, {:stage, mode})
      :stream_gate -> :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n")
      _ -> :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    end
  end

  defp relay(socket, upstream) do
    receive do
      {:ssl, ^socket, bytes} ->
        :gen_tcp.send(upstream, bytes)
        :ssl.setopts(socket, active: :once)
        relay(socket, upstream)

      {:tcp, ^upstream, bytes} ->
        :ssl.send(socket, bytes)
        :inet.setopts(upstream, active: :once)
        relay(socket, upstream)

      {:ssl_closed, ^socket} ->
        :gen_tcp.close(upstream)

      {:ssl_error, ^socket, _} ->
        :gen_tcp.close(upstream)

      {:tcp_closed, ^upstream} ->
        :ssl.close(socket)

      {:tcp_error, ^upstream, _} ->
        :ssl.close(socket)
    after
      4_000 ->
        :gen_tcp.close(upstream)
        :ssl.close(socket)
    end
  end

  defp recv_request(socket, bytes \\ "") do
    case :binary.match(bytes, "\r\n\r\n") do
      {index, 4} ->
        head = binary_part(bytes, 0, index)

        length =
          case Regex.run(~r/content-length: ([0-9]+)/i, head) do
            [_, value] -> String.to_integer(value)
            _ -> 0
          end

        needed = index + 4 + length - byte_size(bytes)

        if needed > 0 do
          {:ok, data} = :ssl.recv(socket, needed, 4_000)
          bytes <> data
        else
          bytes
        end

      :nomatch ->
        {:ok, data} = :ssl.recv(socket, 0, 4_000)
        recv_request(socket, bytes <> data)
    end
  end

  defp await_closed(socket) do
    case :ssl.recv(socket, 0, 4_000) do
      {:ok, _data} -> await_closed(socket)
      error -> error
    end
  end

  defp serve_http2(socket, parent) do
    {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(socket, 24, 4_000)
    :ssl.send(socket, frame(4, 0, 0, ""))
    id = recv_h2_headers(socket)
    send(parent, {:h2_request, id})
    :ssl.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 1, id, "ok")])
  end

  defp recv_h2_headers(socket) do
    {:ok, <<length::24, type, flags, _::1, id::31>>} = :ssl.recv(socket, 9, 4_000)
    if length > 0, do: :ssl.recv(socket, length, 4_000)

    case {type, flags} do
      {1, _} ->
        id

      {4, 0} ->
        :ssl.send(socket, frame(4, 1, 0, ""))
        recv_h2_headers(socket)

      _ ->
        recv_h2_headers(socket)
    end
  end

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp server_opts(name) do
    [
      certfile: String.to_charlist(Path.join(@fixtures, name <> ".pem")),
      keyfile: String.to_charlist(Path.join(@fixtures, name <> ".key")),
      active: false,
      mode: :binary,
      reuseaddr: true,
      ip: {127, 0, 0, 1}
    ]
  end
end
