defmodule HTTP.NestedExSSLHTTPSProxyTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @fixtures Path.expand("../support/fixtures", __DIR__)
  @peer Path.expand("../support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

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

  test "both TLS layers retain their own independent identity verification" do
    for layer <- [:proxy, :origin] do
      {url, proxy, peer} = nested_peer(:serve)
      options = options(proxy)

      options =
        if layer == :proxy do
          {:https, host, port, proxy_opts} = proxy
          tls = Keyword.put(proxy_opts[:ssl], :ex_ssl, reference_identity: {:ip, {127, 0, 0, 3}})
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

  for outer_version <- [:"tlsv1.2", :"tlsv1.3"], inner_version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{outer_version} outer and #{inner_version} inner retain H1 ownership across pooled requests" do
      {url, proxy, outer, inner} =
        reused_peer(unquote(outer_version), unquote(inner_version), "http/1.1")

      opts =
        options(proxy)
        |> Keyword.put(:http1_reuse, true)
        |> Keyword.update!(:ssl, &Keyword.put(&1, :alpn_advertised_protocols, ["http/1.1"]))

      try do
        first = HTTP.fetch(url, opts)
        assert %HTTP.Response{status: 200, body: "ok"} = HTTP.Promise.await(first, 4_000)
        assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(first), 2_000)
        port = URI.parse(url).port

        assert [%{provider: %{handle: handle}}] =
                 HTTP.HTTP1.Pool
                 |> :sys.get_state()
                 |> Map.fetch!(:entries)
                 |> Map.values()
                 |> Enum.filter(&(&1.key.port == port))

        later = HTTP.fetch(url, opts ++ [method: :post, body: <<0, 255, 42>>])
        assert :ok = HTTP.RequestCompletion.abort_and_await(HTTP.Promise.completion(first), 0)

        assert %HTTP.Response{status: 200, body: <<0, 255, 42>>} =
                 HTTP.Promise.await(later, 4_000)

        assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(later), 2_000)

        assert {:pending, %{epoch: {3, 3}, provider_resources: %{tcp_sockets: 1, observers: 2}}} =
                 SSL.Lifecycle.status(handle)

        outer_state = peer_stats(outer, fn _ -> true end)
        inner_state = peer_stats(inner, &(length(&1["requests"]) == 2))
        outer_wire = wire_version(unquote(outer_version))
        inner_wire = wire_version(unquote(inner_version))
        assert [%{"tls" => ^outer_wire, "alpn" => "http/1.1"}] = outer_state["handshakes"]
        assert [%{"tls" => ^inner_wire, "alpn" => "http/1.1"}] = inner_state["handshakes"]
        assert [%{"connection" => 1}] = outer_state["connects"]

        assert [%{"connection" => 1}, %{"connection" => 1, "body" => "AP8q"}] =
                 inner_state["requests"]

        for state <- [outer_state, inner_state] do
          assert state["accepted_connections"] == 1
          assert state["closed_connections"] == 0
          assert state["errors"] == []
        end

        stop_peer(outer)

        assert {:ok, %{cleanup: :confirmed}} =
                 SSL.Lifecycle.await(
                   handle,
                   {:abs_ms, System.monotonic_time(:millisecond) + 2_000}
                 )

        assert %{"active_connections" => 0, "errors" => []} =
                 peer_stats(inner, &(&1["closed_connections"] == 1))
      after
        stop_peer(outer)
        stop_peer(inner)
      end
    end

    test "#{outer_version} outer and #{inner_version} inner retain H2 reuse after stream cancellation" do
      {url, proxy, outer, inner} = reused_peer(unquote(outer_version), unquote(inner_version))
      opts = options(proxy) ++ [http_version: :http2]

      try do
        first = HTTP.fetch(url, opts)
        assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(first, 4_000)
        assert "ok" = HTTP.Response.text(response)
        assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(first), 2_000)

        port = URI.parse(url).port

        assert [{owner, %{carrier: %{handle: handle}}}] =
                 :http_fetch_http2_pool
                 |> :sys.get_state()
                 |> Map.fetch!(:providers)
                 |> Enum.filter(fn {_, provider} -> provider.key.port == port end)

        assert {:pending,
                %{
                  scope: :pair,
                  setup: :connected,
                  epoch: {1, 1},
                  provider_resources: %{tcp_sockets: 1, observers: 2}
                }} = SSL.Lifecycle.status(handle)

        sibling = HTTP.fetch(url <> "/hold", opts)

        assert [%{"stream" => 1}, %{"stream" => 3}] =
                 peer_stats(inner, &(length(&1["requests"]) == 2))["requests"]

        assert :ok =
                 HTTP.RequestCompletion.abort_and_await(HTTP.Promise.completion(sibling), 2_000)

        assert {:error, :aborted} = HTTP.Promise.await(sibling, 2_000)

        later = HTTP.fetch(url, opts)
        assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(later, 4_000)
        assert "ok" = HTTP.Response.text(response)
        assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(later), 2_000)
        assert :ok = HTTP.RequestCompletion.abort_and_await(HTTP.Promise.completion(first), 0)
        assert {:pending, %{cleanup: :pending, epoch: {1, 1}}} = SSL.Lifecycle.status(handle)

        outer_state = peer_stats(outer, fn _ -> true end)

        inner_state =
          peer_stats(inner, &(length(&1["requests"]) == 3 and length(&1["resets"]) == 1))

        outer_wire = wire_version(unquote(outer_version))
        inner_wire = wire_version(unquote(inner_version))
        assert [%{"tls" => ^outer_wire, "alpn" => "http/1.1"}] = outer_state["handshakes"]
        assert [%{"tls" => ^inner_wire, "alpn" => "h2"}] = inner_state["handshakes"]
        assert [%{"stream" => 1}, %{"stream" => 3}, %{"stream" => 5}] = inner_state["requests"]
        assert [%{"stream" => 3, "error" => 8}] = inner_state["resets"]
        assert [%{"connection" => 1}] = outer_state["connects"]

        for state <- [outer_state, inner_state] do
          assert state["accepted_connections"] == 1
          assert state["closed_connections"] == 0
          assert state["errors"] == []
        end

        GenServer.stop(owner, :normal, 2_000)

        assert {:ok,
                %{
                  cleanup: :confirmed,
                  layers: %{outer: %{cleanup: :confirmed}, inner: %{cleanup: :confirmed}}
                }} =
                 SSL.Lifecycle.await(
                   handle,
                   {:abs_ms, System.monotonic_time(:millisecond) + 2_000}
                 )

        for peer <- [outer, inner] do
          state = peer_stats(peer, &(&1["closed_connections"] == 1))
          assert state["accepted_connections"] == 1
          assert state["active_connections"] == 0
          assert state["errors"] == []
        end
      after
        stop_peer(outer)
        stop_peer(inner)
      end
    end
  end

  for stop <- [:abort, :deadline] do
    test "#{stop} before proxy TLS completes joins both provider reservations" do
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
        assert :ok = HTTP.RequestCompletion.abort_and_await(handle, 3_000)

        assert {:error, :aborted} = HTTP.Promise.await(promise, 1_000)
      else
        assert {:error, :connect_timeout} = HTTP.Promise.await(promise, 2_000)
        assert :ok = HTTP.RequestCompletion.await(handle, 3_000)
      end

      assert_receive {:proxy_tcp_closed, {:error, :closed}}, 1_000
    end
  end

  test "invalid origin policy fails before proxy authentication or dialing" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    promise =
      HTTP.fetch("https://origin.invalid/",
        proxy: {:https, "127.0.0.1", port, []},
        tls_backend: :ex_ssl,
        ssl: [versions: [:invalid]],
        redirect: :manual,
        telemetry: false
      )

    assert {:error, {:options, {:versions, :unsupported_or_invalid}}} =
             HTTP.Promise.await(promise, 2_000)

    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
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

  defp assert_cleanup(_stage, result, _handle), do: assert(result == :ok)

  defp assert_origin_closed(:origin_gate),
    do: assert_receive({:origin_closed, {:error, :closed}}, 2_000)

  defp assert_origin_closed(_stage), do: :ok

  defp options(proxy) do
    [
      proxy: proxy,
      tls_backend: :ex_ssl,
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
      :ssl.listen(0, server_opts("pinned-ip"))

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
      {:https, "127.0.0.1", proxy_port,
       [
         ssl: [
           cacertfile: Path.join(@fixtures, "pinned-ip-ca.pem"),
           server_name_indication: :disable,
           ex_ssl: [reference_identity: {:ip, {127, 0, 0, 2}}]
         ],
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

  defp reused_peer(outer_version, inner_version, protocol \\ "h2") do
    inner = start_peer(inner_version, "localhost", protocol, ["--route", "forward"])
    %{"port" => origin_port} = peer_event(inner)

    outer =
      start_peer(outer_version, "pinned-ip", "http/1.1", [
        "--route",
        "nested",
        "--upstream-port",
        Integer.to_string(origin_port)
      ])

    %{"port" => proxy_port} = peer_event(outer)

    proxy =
      {:https, "127.0.0.1", proxy_port,
       [
         ssl: [
           cacertfile: Path.join(@fixtures, "pinned-ip-ca.pem"),
           server_name_indication: :disable,
           ex_ssl: [reference_identity: {:ip, {127, 0, 0, 2}}]
         ]
       ]}

    {"https://localhost:#{origin_port}/nested", proxy, outer, inner}
  end

  defp start_peer(version, certificate, protocol, extra) do
    python = System.find_executable("python3") || raise "python3 is required"

    peer =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          @peer,
          "--cert",
          Path.join(@fixtures, certificate <> ".pem"),
          "--key",
          Path.join(@fixtures, certificate <> ".key"),
          "--tls",
          wire_version(version),
          "--protocol",
          protocol | extra
        ]
      ])

    on_exit(fn -> if Port.info(peer), do: Port.close(peer) end)
    peer
  end

  defp wire_version(:"tlsv1.2"), do: "TLSv1.2"
  defp wire_version(:"tlsv1.3"), do: "TLSv1.3"

  defp peer_event(peer) do
    receive do
      {^peer, {:data, {:eol, line}}} -> JSON.decode!(line)
      {^peer, {:exit_status, code}} -> flunk("independent peer exited #{code}")
    after
      5_000 -> flunk("independent peer event timeout")
    end
  end

  defp peer_stats(peer, predicate),
    do: peer_stats(peer, predicate, System.monotonic_time(:millisecond) + 1_000)

  defp peer_stats(peer, predicate, deadline) do
    assert Port.command(peer, JSON.encode!(%{command: "stats"}) <> "\n")
    state = peer_event(peer)

    if predicate.(state) do
      state
    else
      assert System.monotonic_time(:millisecond) < deadline, "peer condition did not settle"

      receive do
      after
        1 -> peer_stats(peer, predicate, deadline)
      end
    end
  end

  defp stop_peer(peer) do
    if Port.info(peer) do
      assert Port.command(peer, JSON.encode!(%{command: "stop"}) <> "\n")
      assert %{"event" => "stop"} = peer_event(peer)
      assert_receive {^peer, {:exit_status, 0}}, 5_000
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
