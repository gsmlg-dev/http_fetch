defmodule ExternalConsumerSmoke do
  alias HTTP.HTTP2.Frame
  alias HTTP.HTTP2.HPACK

  @http1_response "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nconsumer-ok"
  @end_stream 0x1
  @end_headers 0x4
  @guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  def run do
    for app <- [:http_fetch, :http_web_socket, :http_event_source, :http_web_transport] do
      {:ok, _} = Application.ensure_all_started(app)
    end

    assert Enum.any?(Application.started_applications(), fn {app, _, _} -> app == :ex_ssl end),
           ":ex_ssl was not started through http_core's package dependency"

    assert Application.spec(:ex_ssl, :vsn) == ~c"0.4.0",
           "published ex_ssl 0.4.0 must be loaded through http_core"

    certfile = System.fetch_env!("HTTP_FETCH_CERTFILE")
    cacertfile = System.fetch_env!("HTTP_FETCH_CACERTFILE")
    keyfile = System.fetch_env!("HTTP_FETCH_KEYFILE")

    assert_package_metadata!()

    {:ok, :ssl} = HTTP.TLSBackend.resolve()
    fetch_http1!(certfile, keyfile, cacertfile)
    fetch_h2!(certfile, keyfile, cacertfile)
    web_socket!(certfile, keyfile, cacertfile)
    event_source!(certfile, keyfile, cacertfile)

    {:error, :tls_backend_not_supported_for_quic} =
      HTTP.WebTransport.new("https://localhost:443/", tls_backend: :ex_ssl)

    Application.put_env(:http_core, :tls_backend, :ex_ssl)

    {:ok, %{backend: HTTP.WebTransport.Transport.QUIC}} =
      HTTP.WebTransport.Options.new("https://localhost:443/")

    Application.delete_env(:http_core, :tls_backend)

    IO.puts("external consumer smoke passed")
  end

  defp fetch_http1!(certfile, keyfile, cacertfile) do
    {listen, port} = listen!(certfile, keyfile, [])

    spawn_link(fn ->
      for _ <- 1..2 do
        {:ok, socket} = accept!(listen)
        {:ok, _} = recv_headers(socket)
        :ok = :ssl.send(socket, @http1_response)
        :ssl.close(socket)
      end

      :ssl.close(listen)
    end)

    for {label, options} <- [
          default: [ssl: [cacertfile: cacertfile]],
          ex_ssl: [tls_backend: :ex_ssl, ssl: [cacertfile: cacertfile]]
        ] do
      response = HTTP.fetch("https://localhost:#{port}/", options) |> HTTP.Promise.await()

      assert response.status == 200 and HTTP.Response.read_all(response) == "consumer-ok",
             "HTTP/1.1 #{label} failed"
    end
  end

  defp assert_package_metadata! do
    package_dir = System.fetch_env!("HTTP_FETCH_PACKAGE_DIR")
    core = metadata!(package_dir, "http_core")
    core_version = Map.fetch!(core, <<"version">>)

    assert requirement!(core, <<"ex_ssl">>) == <<"~> 0.4.0">>,
           "http_core package must require ex_ssl ~> 0.4.0"

    for app <- ["http_fetch", "http_web_socket", "http_event_source", "http_web_transport"] do
      assert requirement!(metadata!(package_dir, app), <<"http_core">>) == "~> " <> core_version,
             "#{app} package must require the built http_core version"
    end
  end

  defp metadata!(package_dir, app) do
    {:ok, entries} =
      :file.consult(String.to_charlist(Path.join([package_dir, app, "hex_metadata.config"])))

    Map.new(entries)
  end

  defp requirement!(metadata, name) do
    metadata
    |> Map.fetch!(<<"requirements">>)
    |> Enum.map(&Map.new/1)
    |> Enum.find_value(fn requirement ->
      if Map.fetch!(requirement, <<"name">>) == name do
        assert Map.fetch!(requirement, <<"optional">>) == false,
               "#{name} package dependency must not be optional"

        Map.fetch!(requirement, <<"requirement">>)
      end
    end)
    |> case do
      nil -> raise "package is missing #{name} requirement"
      requirement -> requirement
    end
  end

  defp fetch_h2!(certfile, keyfile, cacertfile) do
    {listen, port} = listen!(certfile, keyfile, alpn_preferred_protocols: [<<"h2">>])

    spawn_link(fn ->
      for _ <- 1..2 do
        {:ok, socket} = accept!(listen)
        {preface, buffer} = recv_exact(socket, byte_size(HTTP.HTTP2.connection_preface()), <<>>)
        assert preface == HTTP.HTTP2.connection_preface(), "missing HTTP/2 preface"
        {_settings, buffer} = recv_frame(socket, buffer)
        {%Frame{type: :headers, stream_id: 1}, _buffer} = recv_frame(socket, buffer)
        headers = HPACK.encode_headers([{":status", "200"}, {"content-length", "2"}])

        :ok =
          :ssl.send(socket, [
            Frame.encode(:settings, 0, 0, ""),
            Frame.encode(:headers, @end_headers, 1, headers),
            Frame.encode(:data, @end_stream, 1, "h2")
          ])

        {%Frame{type: :settings, flags: 1, stream_id: 0, payload: ""}, _buffer} =
          recv_frame(socket, "")

        :ssl.close(socket)
      end

      :ssl.close(listen)
    end)

    for {label, options} <- [
          default: [http_version: :http2, ssl: [cacertfile: cacertfile]],
          ex_ssl: [http_version: :http2, tls_backend: :ex_ssl, ssl: [cacertfile: cacertfile]]
        ] do
      response = HTTP.fetch("https://localhost:#{port}/", options) |> HTTP.Promise.await()

      assert response.status == 200 and HTTP.Response.read_all(response) == "h2",
             "HTTP/2 #{label} failed"
    end
  end

  defp web_socket!(certfile, keyfile, cacertfile) do
    {listen, port} = listen!(certfile, keyfile, [])

    spawn_link(fn ->
      for _ <- 1..2 do
        {:ok, socket} = accept!(listen)
        {:ok, request} = recv_headers(socket)
        [_, key] = Regex.run(~r/sec-websocket-key:\s*([^\r\n]+)/i, request)
        accept = :crypto.hash(:sha, String.trim(key) <> @guid) |> Base.encode64()

        :ok =
          :ssl.send(socket, [
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
            accept,
            "\r\n\r\n",
            <<0x81, 11, "consumer-ws">>
          ])

        :ssl.close(socket)
      end

      :ssl.close(listen)
    end)

    for {label, options} <- [
          default: [ssl: [cacertfile: cacertfile]],
          ex_ssl: [tls_backend: :ex_ssl, ssl: [cacertfile: cacertfile]]
        ] do
      socket = HTTP.WebSocket.new("wss://localhost:#{port}/", [], options)
      assert match?(%HTTP.WebSocket{}, socket), "WebSocket #{label} did not start"
      await_web_socket_open(socket)
      await_web_socket_message(socket, "consumer-ws")
    end
  end

  defp event_source!(certfile, keyfile, cacertfile) do
    {listen, port} = listen!(certfile, keyfile, [])

    spawn_link(fn ->
      for _ <- 1..2 do
        {:ok, socket} = accept!(listen)
        {:ok, _} = recv_headers(socket)

        :ok =
          :ssl.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: consumer-sse\n\n"
          )

        :ssl.close(socket)
      end

      :ssl.close(listen)
    end)

    for {label, options} <- [
          default: [ssl: [cacertfile: cacertfile]],
          ex_ssl: [tls_backend: :ex_ssl, ssl: [cacertfile: cacertfile]]
        ] do
      source = HTTP.EventSource.new("https://localhost:#{port}/", options)
      assert match?(%HTTP.EventSource{}, source), "EventSource #{label} did not start"
      await_event_source_open(source)
      await_event_source_message(source, "consumer-sse")
      :ok = HTTP.EventSource.close(source)
    end
  end

  defp listen!(certfile, keyfile, extra) do
    {:ok, listen} =
      :ssl.listen(
        0,
        [
          :binary,
          active: false,
          ip: {127, 0, 0, 1},
          reuseaddr: true,
          versions: [:"tlsv1.3"],
          certfile: certfile,
          keyfile: keyfile
        ] ++ extra
      )

    {:ok, {{127, 0, 0, 1}, port}} = :ssl.sockname(listen)
    {listen, port}
  end

  defp accept!(listen) do
    with {:ok, transport} <- :ssl.transport_accept(listen, 5_000),
         do: :ssl.handshake(transport, 5_000)
  end

  defp recv_headers(socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n"),
      do: {:ok, buffer},
      else:
        with({:ok, data} <- :ssl.recv(socket, 0, 5_000), do: recv_headers(socket, buffer <> data))
  end

  defp recv_exact(_socket, 0, buffer), do: {"", buffer}

  defp recv_exact(_socket, size, buffer) when byte_size(buffer) >= size do
    <<data::binary-size(size), rest::binary>> = buffer
    {data, rest}
  end

  defp recv_exact(socket, size, buffer) do
    {:ok, data} = :ssl.recv(socket, 0, 5_000)
    recv_exact(socket, size, buffer <> data)
  end

  defp recv_frame(socket, buffer) do
    case Frame.decode(buffer) do
      {:ok, frame, rest} ->
        {frame, rest}

      :more ->
        {:ok, data} = :ssl.recv(socket, 0, 5_000)
        recv_frame(socket, buffer <> data)
    end
  end

  defp await_web_socket_open(socket) do
    receive do
      {HTTP.WebSocket, ^socket, %HTTP.WebSocket.Event.Open{}} -> :ok
      _ -> await_web_socket_open(socket)
    after
      5_000 -> raise "WebSocket did not open"
    end
  end

  defp await_web_socket_message(socket, expected) do
    receive do
      {HTTP.WebSocket, ^socket, %HTTP.WebSocket.Event.Message{data: ^expected}} -> :ok
      _ -> await_web_socket_message(socket, expected)
    after
      5_000 -> raise "WebSocket did not deliver #{expected}"
    end
  end

  defp await_event_source_open(source) do
    receive do
      {HTTP.EventSource, ^source, %HTTP.EventSource.Event.Open{}} -> :ok
      _ -> await_event_source_open(source)
    after
      5_000 -> raise "EventSource did not open"
    end
  end

  defp await_event_source_message(source, expected) do
    receive do
      {HTTP.EventSource, ^source, %HTTP.EventSource.Event.Message{data: ^expected}} -> :ok
      _ -> await_event_source_message(source, expected)
    after
      5_000 -> raise "EventSource did not deliver #{expected}"
    end
  end

  defp assert(value, message)
  defp assert(true, _message), do: :ok
  defp assert(false, message), do: raise(message)
end

ExternalConsumerSmoke.run()
