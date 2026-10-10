defmodule HTTP.ProxyCompletionAcceptanceTest do
  use ExUnit.Case, async: false

  import Bitwise
  alias HTTP.{Promise, RequestCompletion}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Frames

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "HTTPS forwarding completion preserves reuse and isolates proxy credentials and origin authority" do
    {listener, port} = listener()

    peer =
      peer(fn parent ->
        sockets =
          for {connection, requests} <- [{1, 2}, {2, 1}, {3, 1}] do
            socket = accept_tls(listener)

            for request <- 1..requests do
              {head, rest} = recv_head(socket, :ssl)

              body =
                if connection == 1 and request == 1, do: recv_bytes(socket, rest, 3), else: rest

              send(parent, {:forwarded, connection, request, head, body})
              :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            end

            socket
          end

        send(parent, :forwarding_complete)
        await_command(:close)
        Enum.each(sockets, &:ssl.close/1)
      end)

    opts = forwarding_options(port, "first", http1_reuse: true)
    {:ok, upload} = HTTP.Stream.from_enumerable(["abc"])
    source_monitor = Process.monitor(upload)

    first =
      HTTP.fetch(
        "http://origin.invalid:8080/entity?",
        Keyword.merge(opts,
          method: :post,
          body: upload,
          duplex: :half,
          headers: [{"Content-Length", "3"}, {"Authorization", "Bearer origin"}]
        )
      )

    assert %HTTP.Response{body: "ok"} = Promise.await(first, 3_000)
    assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
    assert_receive {:DOWN, ^source_monitor, :process, ^upload, :normal}, 1_000
    assert_receive {:forwarded, 1, 1, head, "abc"}, 1_000
    assert head =~ "POST http://origin.invalid:8080/entity? HTTP/1.1\r\n"
    assert head =~ "Proxy-Authorization: Basic first\r\n"
    assert head =~ "Authorization: Bearer origin\r\n"

    second = HTTP.fetch("http://origin.invalid:8080/entity?", opts)
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(first), 0)
    assert %HTTP.Response{body: "ok"} = Promise.await(second, 3_000)
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    assert_receive {:forwarded, 1, 2, _, ""}, 1_000

    third =
      HTTP.fetch(
        "http://origin.invalid:8080/entity?",
        forwarding_options(port, "second", http1_reuse: true)
      )

    assert %HTTP.Response{body: "ok"} = Promise.await(third, 3_000)
    assert :ok = RequestCompletion.await(Promise.completion(third), 1_000)
    assert_receive {:forwarded, 2, 1, head, ""}, 1_000
    assert head =~ "Proxy-Authorization: Basic second\r\n"

    fourth = HTTP.fetch("http://other.invalid:8080/entity?", opts)
    assert %HTTP.Response{body: "ok"} = Promise.await(fourth, 3_000)
    assert :ok = RequestCompletion.await(Promise.completion(fourth), 1_000)
    assert_receive {:forwarded, 3, 1, head, ""}, 1_000
    assert head =~ "GET http://other.invalid:8080/entity? HTTP/1.1\r\n"
    assert_receive :forwarding_complete, 1_000
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    send(peer, :close)
    assert_receive {:peer_complete, ^peer}, 1_000
  end

  test "HTTPS proxy cancellation waits for a suspended upload source and stops its enumerable producer" do
    {listener, port} = listener()

    peer =
      peer(fn parent ->
        socket = accept_tls(listener)
        {head, ""} = recv_head(socket, :ssl)
        send(parent, {:upload_headers, head})
        assert {:error, :closed} = :ssl.recv(socket, 0, 2_000)
        send(parent, :upload_socket_closed)
      end)

    parent = self()

    enumerable =
      Stream.resource(
        fn ->
          send(parent, {:producer_started, self()})
          :ready
        end,
        fn state ->
          receive do
            :produce -> {["never-replayed"], state}
          end
        end,
        fn _ -> :ok end
      )

    {:ok, upload} = HTTP.Stream.from_enumerable(enumerable)
    assert_receive {:producer_started, producer}, 1_000
    producer_monitor = Process.monitor(producer)
    source_monitor = Process.monitor(upload)

    promise =
      HTTP.fetch(
        "http://origin.invalid/upload",
        forwarding_options(port, "upload", method: :post, body: upload, duplex: :half)
      )

    handle = Promise.completion(promise)
    assert_receive {:upload_headers, head}, 1_000
    assert head =~ "POST http://origin.invalid/upload HTTP/1.1\r\n"
    :erlang.suspend_process(upload)

    try do
      assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 20)
      waiters = for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(handle, 20) end)
      assert Task.await_many(waiters, 1_000) == List.duplicate({:error, :cleanup_pending}, 3)
    after
      :erlang.resume_process(upload)
    end

    assert :ok = RequestCompletion.await(handle, 1_000)
    assert :ok = RequestCompletion.abort_and_await(handle, 0)
    assert {:error, :aborted} = Promise.await(promise, 3_000)
    assert_receive {:DOWN, ^source_monitor, :process, ^upload, :normal}, 1_000
    assert_receive {:DOWN, ^producer_monitor, :process, ^producer, :killed}, 1_000
    assert_receive :upload_socket_closed, 1_000
    assert_receive {:peer_complete, ^peer}, 1_000
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  test "CONNECT HTTP2 cancellation releases one request while siblings and later requests reuse the tunnel" do
    {origin, origin_port} = listener()
    {listener, port} = listener()

    peer =
      peer(fn parent ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        {connect, ""} = recv_head(tcp, :gen_tcp)
        send(parent, {:connect_authority, connect})
        :ok = :gen_tcp.send(tcp, "HTTP/1.1 200 Connection Established\r\n\r\n")
        socket = handshake(tcp, "localhost", "h2")
        {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
        send(parent, {:origin_sni, info[:sni_hostname]})
        assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(socket, 24, 2_000)
        :ok = :ssl.send(socket, Frames.frame(4, 0, 0, <<>>))
        decoder = HTTP.HTTP2.HPACK.new_decoder()
        {first, headers, decoder} = h2_request(socket, decoder)
        send(parent, {:tunneled_headers, headers})
        :ok = :ssl.send(socket, Frames.frame(1, 4, first, <<0x88>>))
        {second, _, decoder} = h2_request(socket, decoder)
        :ok = :ssl.send(socket, Frames.frame(1, 4, second, <<0x88>>))
        await_reset(socket, first)
        send(parent, :cancelled_stream_reset)
        await_command(:finish_sibling)
        :ok = :ssl.send(socket, Frames.frame(0, 1, second, "survived"))
        {third, _, _} = h2_request(socket, decoder)
        assert third > second

        :ok =
          :ssl.send(socket, [
            Frames.frame(1, 4, third, <<0x88>>),
            Frames.frame(0, 1, third, "reused")
          ])

        send(parent, :same_tunnel_reused)
        await_command(:close)
        :ssl.close(socket)
      end)

    url = "https://localhost:#{origin_port}/private"

    opts = [
      proxy: {:http, "127.0.0.1", port, [headers: [{"Proxy-Authorization", "Basic tunnel"}]]},
      http_version: :http2,
      tls_backend: :ssl,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
      redirect: :manual,
      stream_response: true,
      headers: [{"Authorization", "Bearer origin"}, {"Proxy-Authorization", "must-not-leak"}],
      http2_scope: unique_scope(),
      telemetry: false,
      timeout: 4_000
    ]

    first = HTTP.fetch(url, opts)
    assert %HTTP.Response{status: 200, stream: first_stream} = Promise.await(first, 3_000)
    first_monitor = Process.monitor(first_stream)
    second = HTTP.fetch(url, opts)
    sibling = Promise.await(second, 3_000)
    handle = Promise.completion(first)

    waiters =
      for _ <- 1..3, do: Task.async(fn -> RequestCompletion.abort_and_await(handle, 1_000) end)

    assert Task.await_many(waiters, 2_000) == [:ok, :ok, :ok]
    assert_receive {:DOWN, ^first_monitor, :process, ^first_stream, :normal}, 1_000
    assert_receive :cancelled_stream_reset, 1_000
    assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(second), 0)
    send(peer, :finish_sibling)
    assert HTTP.Response.read_all(sibling) == "survived"
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    third = HTTP.fetch(url, opts)
    assert HTTP.Response.read_all(Promise.await(third, 3_000)) == "reused"
    assert :ok = RequestCompletion.await(Promise.completion(third), 1_000)
    assert :ok = RequestCompletion.abort_and_await(handle, 0)
    assert_receive :same_tunnel_reused, 1_000
    assert_receive {:connect_authority, connect}, 1_000
    assert connect =~ "CONNECT localhost:#{origin_port} HTTP/1.1\r\n"
    assert connect =~ "Proxy-Authorization: Basic tunnel\r\n"
    refute connect =~ "Bearer origin"
    refute connect =~ "must-not-leak"
    assert_receive {:origin_sni, ~c"localhost"}, 1_000
    assert_receive {:tunneled_headers, headers}, 1_000
    assert {"authorization", "Bearer origin"} in headers
    refute Enum.any?(headers, fn {name, _} -> name == "proxy-authorization" end)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 0)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    send(peer, :close)
    assert_receive {:peer_complete, ^peer}, 1_000
  end

  test "verified proxy identity failure confirms cleanup without origin fallback or replay" do
    {origin, origin_port} = listener()
    {listener, port} = listener()

    peer =
      peer(fn parent ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)

        assert {:error, {:tls_alert, {:bad_certificate, _}}} =
                 :ssl.handshake(tcp, tls_options("pinned", "http/1.1"), 2_000)

        send(parent, :wrong_proxy_identity_rejected)
      end)

    promise =
      HTTP.fetch(
        "http://127.0.0.1:#{origin_port}/mutation",
        forwarding_options(port, "identity",
          method: :post,
          body: "must-not-replay",
          ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")]
        )
      )

    assert {:error, {:tls_alert, {:bad_certificate, description}}} = Promise.await(promise, 3_000)
    assert to_string(description) =~ "hostname_check_failed"
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(promise), 0)
    assert_receive :wrong_proxy_identity_rejected, 1_000
    assert_receive {:peer_complete, ^peer}, 1_000
    assert {:error, :timeout} = :gen_tcp.accept(origin, 0)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  defp forwarding_options(port, credential, extra) do
    Keyword.merge(
      [
        proxy:
          {:https, "localhost", port,
           [headers: [{"Proxy-Authorization", "Basic " <> credential}]]},
        http_version: :http1,
        tls_backend: :ssl,
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
        http1_scope: "proxy-completion-#{port}",
        redirect: :manual,
        telemetry: false,
        timeout: 4_000
      ],
      extra
    )
  end

  defp unique_scope, do: "proxy-completion-#{System.unique_integer([:positive])}"

  defp listener do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {listener, port}
  end

  defp peer(script) do
    parent = self()

    pid =
      spawn_link(fn ->
        script.(parent)
        send(parent, {:peer_complete, self()})
      end)

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    pid
  end

  defp accept_tls(listener) do
    {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
    handshake(tcp, "localhost", "http/1.1")
  end

  defp handshake(tcp, certificate, alpn) do
    {:ok, socket} = :ssl.handshake(tcp, tls_options(certificate, alpn), 2_000)
    socket
  end

  defp tls_options(certificate, alpn) do
    [
      certfile: Path.join(@fixtures, certificate <> ".pem"),
      keyfile: Path.join(@fixtures, certificate <> ".key"),
      alpn_preferred_protocols: [alpn],
      active: false,
      mode: :binary
    ]
  end

  defp recv_head(socket, transport, bytes \\ "") do
    case :binary.match(bytes, "\r\n\r\n") do
      {at, 4} ->
        <<head::binary-size(at + 4), rest::binary>> = bytes
        {head, rest}

      :nomatch ->
        assert byte_size(bytes) < 16_384
        {:ok, chunk} = transport.recv(socket, 0, 2_000)
        recv_head(socket, transport, bytes <> chunk)
    end
  end

  defp recv_bytes(_socket, bytes, length) when byte_size(bytes) == length, do: bytes

  defp recv_bytes(socket, bytes, length) when byte_size(bytes) < length do
    {:ok, chunk} = :ssl.recv(socket, length - byte_size(bytes), 2_000)
    recv_bytes(socket, bytes <> chunk, length)
  end

  defp await_command(command) do
    receive do
      ^command -> :ok
    after
      2_000 -> flunk("scripted proxy command timed out: #{command}")
    end
  end

  defp recv_frame(socket) do
    {:ok, <<length::24, type, flags, _::1, id::31>>} = :ssl.recv(socket, 9, 2_000)
    payload = if length == 0, do: <<>>, else: elem(:ssl.recv(socket, length, 2_000), 1)
    {type, flags, id, payload}
  end

  defp h2_request(socket, decoder) do
    case recv_frame(socket) do
      {1, flags, id, bytes} ->
        assert (flags &&& 4) == 4
        assert (flags &&& 1) == 1
        {:ok, decoder, headers} = HTTP.HTTP2.HPACK.decode(decoder, bytes)
        {id, headers, decoder}

      _ ->
        h2_request(socket, decoder)
    end
  end

  defp await_reset(socket, id) do
    case recv_frame(socket) do
      {3, 0, ^id, <<8::32>>} -> :ok
      _ -> await_reset(socket, id)
    end
  end
end
