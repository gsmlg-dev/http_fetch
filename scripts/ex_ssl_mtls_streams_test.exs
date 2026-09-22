# Run only through scripts/ex_ssl_source_smoke.sh with an explicit source checkout.
for fixture <- ["signature_fixtures.ex", "client_auth_fixtures.ex"] do
  Code.require_file(
    Path.join([System.fetch_env!("EX_SSL_SOURCE_DIR"), "test", "support", fixture])
  )
end

defmodule CandidateMtlsStreamsTest do
  use ExUnit.Case, async: false
  import Bitwise

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias HTTP.EventSource
  alias HTTP.EventSource.Event.Error
  alias HTTP.EventSource.Event.Message, as: SSEMessage
  alias HTTP.EventSource.Event.Open, as: SSEOpen
  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.Close
  alias HTTP.WebSocket.Event.Message, as: WSMessage
  alias HTTP.WebSocket.Event.Open, as: WSOpen

  @guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  @timeout 5_000

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "http-mtls-streams-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "packaged WSS uses ex_ssl mTLS through passive upgrade and active-once echo close", %{
    fixtures: fixtures
  } do
    ref = make_ref()
    %{listener: listener, port: port, task: task} = start_web_socket_peer(self(), ref, fixtures)

    socket =
      WebSocket.new("wss://127.0.0.1:#{port}/socket", [],
        tls_backend: :ex_ssl,
        ssl: client_ssl_options(fixtures)
      )

    try do
      assert_receive {:mtls_wss, ^ref, :authenticated, client_der}, @timeout
      assert client_der == fixtures.rsa.der
      assert_receive {:mtls_wss, ^ref, :upgrade}, @timeout
      assert_receive {WebSocket, ^socket, %WSOpen{}}, @timeout

      assert :ok = WebSocket.send(socket, "mtls-echo")
      assert_receive {:mtls_wss, ^ref, {:text, "mtls-echo"}}, @timeout
      assert_receive {WebSocket, ^socket, %WSMessage{data: "echo:mtls-echo"}}, @timeout

      assert :ok = WebSocket.close(socket, 1000, "done")
      assert_receive {:mtls_wss, ^ref, {:close, <<1000::16, "done">>}}, @timeout

      assert_receive {WebSocket, ^socket, %Close{code: 1000, reason: "done", was_clean: true}},
                     @timeout

      assert :ok = Task.await(task, @timeout)
    after
      _ = WebSocket.close(socket)
      stop_peer(listener, task)
    end
  end

  test "packaged EventSource reconnects to the same mTLS endpoint with its pinned backend", %{
    fixtures: fixtures
  } do
    ref = make_ref()
    %{listener: listener, port: port, task: task} = start_event_source_peer(self(), ref, fixtures)
    previous_backend = Application.get_env(:http_core, :tls_backend, :unset)

    on_exit(fn -> restore_backend(previous_backend) end)

    source =
      EventSource.new("https://127.0.0.1:#{port}/events",
        tls_backend: :ex_ssl,
        reconnect_time: 10,
        ssl: client_ssl_options(fixtures)
      )

    try do
      assert_receive {:mtls_sse, ^ref, :authenticated, 1, client_der}, @timeout
      assert client_der == fixtures.rsa.der
      assert_receive {:mtls_sse, ^ref, {:request, 1, first_request}}, @timeout
      assert String.starts_with?(first_request, "GET /events HTTP/1.1\r\n")
      assert_receive {EventSource, ^source, %SSEOpen{}}, @timeout

      assert_receive {EventSource, ^source, %SSEMessage{data: "first", last_event_id: "41"}},
                     @timeout

      assert_receive {:mtls_sse, ^ref, :first_ready}, @timeout

      Application.put_env(:http_core, :tls_backend, :invalid)
      assert %{tls_backend: :ex_ssl} = :sys.get_state(source.pid)
      send(task.pid, {:close_first, ref})
      assert_receive {:mtls_sse, ^ref, :first_closed}, @timeout
      assert_receive {EventSource, ^source, %Error{reason: :eof}}, @timeout

      assert_receive {:mtls_sse, ^ref, :authenticated, 2, second_der}, @timeout
      assert second_der == fixtures.rsa.der
      assert_receive {:mtls_sse, ^ref, {:request, 2, second_request}}, @timeout
      assert String.starts_with?(second_request, "GET /events HTTP/1.1\r\n")
      assert second_request =~ "Last-Event-ID: 41\r\n"
      assert_receive {EventSource, ^source, %SSEOpen{}}, @timeout

      assert_receive {EventSource, ^source, %SSEMessage{data: "second", last_event_id: "41"}},
                     @timeout

      assert :ok = EventSource.close(source)
      assert :ok = Task.await(task, @timeout)
    after
      _ = EventSource.close(source)
      stop_peer(listener, task)
    end
  end

  defp start_web_socket_peer(parent, ref, fixtures) do
    {:ok, listener} = listen(fixtures)
    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, socket} = accept_authenticated(listener, fixtures.rsa.der)
        send(parent, {:mtls_wss, ref, :authenticated, fixtures.rsa.der})
        request = recv_headers(socket, <<>>)
        key = websocket_key(request)
        :ok = :ssl.send(socket, websocket_upgrade_response(key))
        send(parent, {:mtls_wss, ref, :upgrade})

        {:text, "mtls-echo", buffer} = recv_client_frame(socket, <<>>)
        send(parent, {:mtls_wss, ref, {:text, "mtls-echo"}})
        :ok = :ssl.send(socket, frame(:text, "echo:mtls-echo"))

        {:close, payload, <<>>} = recv_client_frame(socket, buffer)
        send(parent, {:mtls_wss, ref, {:close, payload}})
        :ok = :ssl.send(socket, frame(:close, payload))
        :ssl.close(socket)
        :ssl.close(listener)
      end)

    %{listener: listener, port: port, task: task}
  end

  defp start_event_source_peer(parent, ref, fixtures) do
    {:ok, listener} = listen(fixtures)
    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        serve_event_source_connection(
          listener,
          parent,
          ref,
          fixtures.rsa.der,
          1,
          "id: 41\ndata: first\n\n",
          true
        )

        serve_event_source_connection(
          listener,
          parent,
          ref,
          fixtures.rsa.der,
          2,
          "data: second\n\n",
          false
        )

        :ssl.close(listener)
      end)

    %{listener: listener, port: port, task: task}
  end

  defp serve_event_source_connection(listener, parent, ref, expected_der, index, body, close?) do
    {:ok, socket} = accept_authenticated(listener, expected_der)
    send(parent, {:mtls_sse, ref, :authenticated, index, expected_der})
    request = recv_headers(socket, <<>>)
    send(parent, {:mtls_sse, ref, {:request, index, request}})

    :ok =
      :ssl.send(socket, [
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: ",
        if(close?, do: "close", else: "keep-alive"),
        "\r\n\r\n",
        body
      ])

    if close? do
      send(parent, {:mtls_sse, ref, :first_ready})

      receive do
        {:close_first, ^ref} -> :ok
      after
        @timeout -> raise "first EventSource connection was not explicitly released"
      end

      :ssl.close(socket)
      send(parent, {:mtls_sse, ref, :first_closed})
    else
      assert {:error, :closed} = :ssl.recv(socket, 0, @timeout)
    end
  end

  defp listen(fixtures) do
    :ssl.listen(0, [
      :binary,
      active: false,
      mode: :binary,
      packet: :raw,
      reuseaddr: true,
      ip: {127, 0, 0, 1},
      versions: [:"tlsv1.3"],
      certfile: String.to_charlist(fixtures.server.certificate),
      keyfile: String.to_charlist(fixtures.server.key),
      cacerts: [fixtures.ca.der],
      verify: :verify_peer,
      fail_if_no_peer_cert: true
    ])
  end

  defp accept_authenticated(listener, expected_der) do
    with {:ok, transport} <- :ssl.transport_accept(listener, @timeout),
         {:ok, socket} <- :ssl.handshake(transport, @timeout),
         {:ok, ^expected_der} <- :ssl.peercert(socket) do
      {:ok, socket}
    end
  end

  defp client_ssl_options(fixtures) do
    [
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      certfile: fixtures.rsa.certificate,
      keyfile: fixtures.rsa.key
    ]
  end

  defp recv_headers(socket, buffer) when byte_size(buffer) < 16_384 do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      {:ok, bytes} = :ssl.recv(socket, 0, @timeout)
      recv_headers(socket, buffer <> bytes)
    else
      buffer
    end
  end

  defp websocket_key(request) do
    [_, key] = Regex.run(~r/sec-websocket-key:\s*([^\r\n]+)/i, request)
    String.trim(key)
  end

  defp websocket_upgrade_response(key) do
    accept = :crypto.hash(:sha, key <> @guid) |> Base.encode64()

    [
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
      accept,
      "\r\n\r\n"
    ]
  end

  defp recv_client_frame(socket, buffer) do
    case parse_client_frame(buffer) do
      {:ok, frame, rest} ->
        {frame_type(frame), frame.payload, rest}

      :more ->
        {:ok, bytes} = :ssl.recv(socket, 0, @timeout)
        recv_client_frame(socket, buffer <> bytes)
    end
  end

  defp parse_client_frame(<<first, second, rest::binary>>) do
    opcode = first &&& 0x0F
    masked? = (second &&& 0x80) != 0
    length_code = second &&& 0x7F

    with true <- masked?,
         {:ok, length, rest} <- frame_length(length_code, rest),
         <<mask::binary-size(4), encrypted::binary-size(length), remainder::binary>> <- rest do
      {:ok, %{opcode: opcode, payload: unmask(encrypted, mask)}, remainder}
    else
      _ -> :more
    end
  end

  defp parse_client_frame(_), do: :more
  defp frame_length(length, rest) when length <= 125, do: {:ok, length, rest}
  defp frame_length(126, <<length::16, rest::binary>>), do: {:ok, length, rest}
  defp frame_length(127, <<length::64, rest::binary>>), do: {:ok, length, rest}
  defp frame_length(_, _), do: :more
  defp frame_type(%{opcode: 0x1}), do: :text
  defp frame_type(%{opcode: 0x8}), do: :close

  defp frame(:text, payload) when byte_size(payload) <= 125,
    do: <<0x81, byte_size(payload), payload::binary>>

  defp frame(:close, payload) when byte_size(payload) <= 125,
    do: <<0x88, byte_size(payload), payload::binary>>

  defp unmask(payload, mask) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map_join(fn {byte, index} -> <<bxor(byte, :binary.at(mask, rem(index, 4)))>> end)
  end

  defp stop_peer(listener, task) do
    _ = :ssl.close(listener)
    if Process.alive?(task.pid), do: Task.shutdown(task, :brutal_kill)
  end

  defp restore_backend(:unset), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_backend(value), do: Application.put_env(:http_core, :tls_backend, value)
end
