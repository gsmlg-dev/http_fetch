defmodule HTTP.SocketClientHTTP2Test do
  use ExUnit.Case, async: true

  import Bitwise

  alias HTTP.HTTP2.Frame
  alias HTTP.HTTP2.HPACK

  @certfile Path.expand("../support/fixtures/localhost.pem", __DIR__)
  @cacertfile Path.expand("../support/fixtures/localhost-ca.pem", __DIR__)
  @keyfile Path.expand("../support/fixtures/localhost.key", __DIR__)

  @ack 0x1
  @end_stream 0x1
  @end_headers 0x4
  @initial_window_size 65_535

  test "fetches an explicit h2c prior-knowledge response" do
    test_pid = self()

    url =
      start_h2c_server!(fn socket, transport ->
        {request_headers, buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:h2_request, request_headers})

        send_h2_response(socket, transport, "h2c")
        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :h2c)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Headers.get(response.headers, "x-protocol") == "h2"
    assert HTTP.Response.read_all(response) == "h2c"

    assert_receive {:h2_request, headers}
    assert {":method", "GET"} in headers
    assert {":scheme", "http"} in headers
    assert {":path", "/test"} in headers
  end

  test "reuses one h2c socket for sequential explicit-profile requests" do
    parent = self()
    url = start_h2c_reuse_server!(parent)

    fetch = fn path ->
      response =
        String.replace(url, "/test", path)
        |> HTTP.fetch(http_version: :h2c, http2_profile: :native_v1)
        |> HTTP.Promise.await()

      assert HTTP.Response.read_all(response) == path
    end

    fetch.("/one")
    fetch.("/two")
    assert_receive {:h2c_accepts, 1}, 1_000
  end

  test "overlaps three explicit-profile requests on one h2c socket" do
    parent = self()
    url = start_h2c_overlap_server!(parent, 3)

    task_for = fn path ->
      Task.async(fn ->
        response =
          String.replace(url, "/test", path)
          |> HTTP.fetch(http_version: :h2c, http2_profile: :native_v1)
          |> HTTP.Promise.await()

        {path, HTTP.Response.read_all(response)}
      end)
    end

    first = task_for.("/one")
    assert_receive {:h2c_overlap_first, 1}, 1_000
    tasks = [first, task_for.("/two"), task_for.("/three")]

    assert Enum.sort(Task.await_many(tasks, 5_000)) ==
             [{"/one", "/one"}, {"/three", "/three"}, {"/two", "/two"}]

    assert_receive {:h2c_overlap, 1, [1, 3, 5]}, 1_000
  end

  test "coalesces simultaneous cold h2c connections per pool key" do
    parent = self()
    url = start_h2c_overlap_server!(parent, 3)

    tasks =
      for path <- ["/one", "/two", "/three"] do
        Task.async(fn ->
          response =
            String.replace(url, "/test", path)
            |> HTTP.fetch(http_version: :h2c, http2_profile: :native_v1)
            |> HTTP.Promise.await()

          {path, HTTP.Response.read_all(response)}
        end)
      end

    assert Enum.sort(Task.await_many(tasks, 5_000)) ==
             [{"/one", "/one"}, {"/three", "/three"}, {"/two", "/two"}]

    assert_receive {:h2c_overlap, 1, [1, 3, 5]}, 1_000
  end

  test "explicit wire profile routes the request through the long-lived owner" do
    test_pid = self()

    url =
      start_h2c_server!(fn socket, transport ->
        {request_headers, buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:profile_request, request_headers})
        send_h2_response(socket, transport, "profile-owner")
        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :h2c, http2_profile: :native_v1)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "profile-owner"
    assert_receive {:profile_request, headers}
    assert {":method", "GET"} in headers
  end

  test "explicit wire profile uploads a stream through the body bridge" do
    {:ok, body} = HTTP.Stream.from_enumerable(["streamed", "-body"])

    url =
      start_h2c_server!(fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)
        {uploaded, _buffer} = recv_request_body_until_end(socket, transport, buffer)
        assert uploaded == "streamed-body"
        send_h2_response(socket, transport, "upload-owner")
      end)

    response =
      url
      |> HTTP.fetch(
        method: :post,
        body: body,
        duplex: :half,
        http_version: :h2c,
        http2_profile: :native_v1
      )
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "upload-owner"
  end

  test "sends WINDOW_UPDATE frames while receiving a large h2c response" do
    body = :binary.copy("x", 70_000)

    url =
      start_h2c_server!(fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        send_h2_response_headers(socket, transport, body)
        buffer = assert_settings_ack(socket, transport, buffer)

        chunks = chunk_binary(body, 16_384)
        last_index = length(chunks) - 1

        Enum.reduce(Enum.with_index(chunks), buffer, fn {chunk, index}, buffer ->
          flags = if index == last_index, do: @end_stream, else: 0
          send_all(socket, transport, Frame.encode(:data, flags, 1, chunk))

          buffer = assert_window_update(socket, transport, buffer, 0, byte_size(chunk))
          assert_window_update(socket, transport, buffer, 1, byte_size(chunk))
        end)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :h2c)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == body
  end

  test "waits for WINDOW_UPDATE before sending request body beyond the send window" do
    body = :binary.copy("p", @initial_window_size + 5)

    url =
      start_h2c_server!(fn socket, transport ->
        {request_headers, buffer} = recv_client_h2_request(socket, transport)

        assert {":method", "POST"} in request_headers
        assert {"content-length", Integer.to_string(byte_size(body))} in request_headers

        {initial_body, buffer} =
          recv_request_body_until(socket, transport, buffer, @initial_window_size)

        assert initial_body == binary_part(body, 0, @initial_window_size)
        assert buffer == ""
        assert {:error, :timeout} = apply(transport, :recv, [socket, 0, 50])

        send_all(socket, transport, [
          Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>),
          Frame.encode(:window_update, 0, 1, <<0::1, 5::31>>)
        ])

        {rest, _buffer} = recv_request_body_until_end(socket, transport, buffer)
        assert rest == "ppppp"

        send_h2_response(socket, transport, "upload-ok")
        assert_settings_ack(socket, transport, "")
      end)

    response =
      url
      |> HTTP.fetch(method: :post, body: body, http_version: :h2c)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "upload-ok"
  end

  test "continues an in-flight h2c response after graceful GOAWAY" do
    url =
      start_h2c_server!(fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        send_h2_response_headers(socket, transport, "ok")

        send_all(socket, transport, [
          Frame.encode(:goaway, 0, 0, <<0::1, 1::31, 0x0::32, "drain">>),
          Frame.encode(:data, @end_stream, 1, "ok")
        ])

        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :h2c)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "ok"
  end

  test "auto over https negotiates h2 with ALPN" do
    test_pid = self()

    url =
      start_https_h2_server!([<<"h2">>, <<"http/1.1">>], fn socket, transport ->
        send(test_pid, {:negotiated, negotiated_protocol(socket)})
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        send_h2_response(socket, transport, "tls-h2")
        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(
        http_version: :auto,
        http2_profile: :native_v1,
        ssl: [verify: :verify_none]
      )
      |> HTTP.Promise.await()

    assert_receive {:negotiated, "h2"}
    assert response.status == 200
    assert HTTP.Response.read_all(response) == "tls-h2"
  end

  test "forced https http2 fails when ALPN does not negotiate h2" do
    url =
      start_https_h2_server!([], fn socket, _transport ->
        :timer.sleep(100)
        :ssl.close(socket)
      end)

    assert {:error, {:http2_not_negotiated, nil}} =
             url
             |> HTTP.fetch(http_version: :http2, ssl: [verify: :verify_none])
             |> HTTP.Promise.await()
  end

  test "auto over https negotiates h2 through ex_ssl" do
    url =
      start_https_h2_server!([<<"h2">>, <<"http/1.1">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)
        send_h2_response(socket, transport, "ex-ssl-h2")
        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(
        http_version: :auto,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "ex-ssl-h2"
  end

  test "forced HTTPS HTTP/2 succeeds through ex_ssl" do
    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)
        send_h2_response(socket, transport, "forced-ex-ssl-h2")
        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(
        http_version: :http2,
        http2_profile: :native_v1,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )
      |> HTTP.Promise.await()

    assert HTTP.Response.read_all(response) == "forced-ex-ssl-h2"
  end

  test "delivers a complete ex_ssl HTTP/2 response queued before a peer close" do
    test_pid = self()

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:server_received_request, self()})

        receive do
          :send_response_and_close ->
            send_h2_response(socket, transport, "queued-before-close")
            :ok = :ssl.close(socket)
            send(test_pid, :server_closed)
        end
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_response_and_close)
    assert_receive :server_closed, 5_000
    tls_pid = await_owner_tls_data_and_close(owner)
    tls_monitor = Process.monitor(tls_pid)
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, _reason}, 5_000
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    response = HTTP.Promise.await(promise)
    assert response.status == 200
    assert HTTP.Response.read_all(response) == "queued-before-close"
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :cross_record
  test "drains a second ex_ssl TLS record after control writes fail following peer close" do
    test_pid = self()
    body = "second-record-body"

    first_record = [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, response_headers(body))
    ]

    first_record_binary = IO.iodata_to_binary(first_record)
    second_record = Frame.encode(:data, @end_stream, 1, body)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:server_received_request, self()})

        await_test_gate(:send_first_record)
        send_all(socket, transport, first_record)
        send(test_pid, :first_record_sent)

        await_test_gate(:send_second_record_and_close)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :second_record_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_first_record)
    assert_receive :first_record_sent, 5_000

    {tls_pid, ^first_record_binary} = await_owner_tls_data(owner, first_record_binary)
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    send(server_pid, :send_second_record_and_close)
    assert_receive :second_record_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, byte_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    tls_monitor = Process.monitor(tls_pid)
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    response = HTTP.Promise.await(promise)
    assert response.status == 200
    assert HTTP.Response.read_all(response) == body
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :cross_record
  test "drains a split HTTP/2 frame from the ex_ssl receive buffer after peer close" do
    test_pid = self()
    body = "split-frame-body"
    headers = Frame.encode(:headers, @end_headers, 1, response_headers(body))
    split_at = 5
    <<headers_start::binary-size(split_at), headers_rest::binary>> = headers

    first_record = [Frame.encode(:settings, 0, 0, ""), headers_start]
    first_record_binary = IO.iodata_to_binary(first_record)
    second_record = [headers_rest, Frame.encode(:data, @end_stream, 1, body)]

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:server_received_request, self()})

        await_test_gate(:send_first_record)
        send_all(socket, transport, first_record)
        send(test_pid, :first_record_sent)

        await_test_gate(:send_second_record_and_close)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :second_record_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_first_record)
    assert_receive :first_record_sent, 5_000

    {tls_pid, ^first_record_binary} = await_owner_tls_data(owner, first_record_binary)
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    send(server_pid, :send_second_record_and_close)
    assert_receive :second_record_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, :erlang.iolist_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    tls_monitor = Process.monitor(tls_pid)
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    response = HTTP.Promise.await(promise)
    assert response.status == 200
    assert HTTP.Response.read_all(response) == body
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  for mode <- [:buffered_short, :buffered_long, :streamed_short] do
    @tag :cross_record
    @tag :content_length_gate
    @tag length_mode: mode
    test "rejects #{mode} Content-Length mismatch after cross-record peer close", %{
      length_mode: mode
    } do
      test_pid = self()
      body = "invalid-length-body"

      declared_size =
        case mode do
          :buffered_short -> byte_size(body) + 1
          :buffered_long -> byte_size(body) - 1
          :streamed_short -> HTTP.Config.streaming_threshold() + 1
        end

      headers =
        HPACK.encode_headers([
          {":status", "200"},
          {"content-length", Integer.to_string(declared_size)}
        ])

      first_record = [
        Frame.encode(:settings, 0, 0, ""),
        Frame.encode(:headers, @end_headers, 1, headers)
      ]

      first_record_binary = IO.iodata_to_binary(first_record)
      second_record = Frame.encode(:data, @end_stream, 1, body)

      url =
        start_https_h2_server!([<<"h2">>], fn socket, transport ->
          {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
          send(test_pid, {:server_received_request, self()})

          await_test_gate(:send_first_record)
          send_all(socket, transport, first_record)
          send(test_pid, :first_record_sent)

          await_test_gate(:send_second_record_and_close)
          send_all(socket, transport, second_record)
          :ok = :ssl.close(socket)
          send(test_pid, :second_record_closed)
        end)

      controller = HTTP.AbortController.new()

      promise =
        HTTP.fetch(url,
          http_version: :http2,
          signal: controller,
          tls_backend: :ex_ssl,
          ssl: [cacertfile: @cacertfile]
        )

      assert_receive {:server_received_request, server_pid}, 5_000
      owner = await_owner(controller)
      await_owner_loop(owner)

      on_exit(fn ->
        cleanup_owner(owner, controller)
      end)

      true = :erlang.suspend_process(owner)
      send(server_pid, :send_first_record)
      assert_receive :first_record_sent, 5_000

      {tls_pid, ^first_record_binary} = await_owner_tls_data(owner, first_record_binary)
      send(server_pid, :send_second_record_and_close)
      assert_receive :second_record_closed, 5_000
      assert_tls_buffered_after_peer_close(tls_pid, byte_size(second_record))
      assert_owner_has_only_tls_data(owner, tls_pid, 1)

      tls_monitor = Process.monitor(tls_pid)
      owner_monitor = Process.monitor(owner)
      true = :erlang.resume_process(owner)

      case mode do
        :streamed_short ->
          response = HTTP.Promise.await(promise)
          assert response.status == 200
          assert is_pid(response.stream)
          stream_monitor = Process.monitor(response.stream)

          assert_raise RuntimeError, "stream read failed: :content_length_mismatch", fn ->
            HTTP.Response.read_all(response)
          end

          assert_receive {:DOWN, ^stream_monitor, :process, _stream, :normal}, 5_000

        _ ->
          assert {:error, :content_length_mismatch} = HTTP.Promise.await(promise)
      end

      assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
    end
  end

  @tag :cross_record
  test "rejects a truncated second ex_ssl TLS record after a control write fails" do
    test_pid = self()
    body = "truncated-second-record"

    first_record = [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, response_headers(body))
    ]

    first_record_binary = IO.iodata_to_binary(first_record)
    second_record = Frame.encode(:data, 0, 1, body)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:server_received_request, self()})

        await_test_gate(:send_first_record)
        send_all(socket, transport, first_record)
        send(test_pid, :first_record_sent)

        await_test_gate(:send_second_record_and_close)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :second_record_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_first_record)
    assert_receive :first_record_sent, 5_000

    {tls_pid, ^first_record_binary} = await_owner_tls_data(owner, first_record_binary)
    send(server_pid, :send_second_record_and_close)
    assert_receive :second_record_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, byte_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    tls_monitor = Process.monitor(tls_pid)
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    assert {:error, :closed} = HTTP.Promise.await(promise)
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :cross_record
  test "does not turn a reset buffered after peer close into a successful response" do
    test_pid = self()
    body = "reset-after-drain"

    first_record = [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, response_headers(body))
    ]

    first_record_binary = IO.iodata_to_binary(first_record)

    second_record = [
      Frame.encode(:data, @end_stream, 1, body),
      Frame.encode(:rst_stream, 0, 1, <<0x8::32>>)
    ]

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:server_received_request, self()})

        await_test_gate(:send_first_record)
        send_all(socket, transport, first_record)
        send(test_pid, :first_record_sent)

        await_test_gate(:send_second_record_and_close)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :second_record_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_first_record)
    assert_receive :first_record_sent, 5_000

    {tls_pid, ^first_record_binary} = await_owner_tls_data(owner, first_record_binary)
    send(server_pid, :send_second_record_and_close)
    assert_receive :second_record_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, :erlang.iolist_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    tls_monitor = Process.monitor(tls_pid)
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    assert {:error, {:stream_reset, :cancel}} = HTTP.Promise.await(promise)
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :cross_record
  @tag :early_response
  test "delivers a complete 413 response when the HTTP/2 request body is still pending" do
    test_pid = self()
    body = :binary.copy("p", @initial_window_size + 5)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        {initial_body, _buffer} =
          recv_request_body_until(socket, transport, buffer, @initial_window_size)

        assert initial_body == binary_part(body, 0, @initial_window_size)
        send(test_pid, {:server_received_request, self()})

        await_test_gate(:send_response_and_close)

        response_body = "payload-too-large"

        send_all(socket, transport, [
          Frame.encode(:settings, 0, 0, ""),
          Frame.encode(:headers, @end_headers, 1, response_headers(413, response_body)),
          Frame.encode(:data, @end_stream, 1, response_body)
        ])

        :ok = :ssl.close(socket)
        send(test_pid, :server_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        method: :post,
        body: body,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_response_and_close)
    assert_receive :server_closed, 5_000
    tls_pid = await_owner_tls_data_and_close(owner)
    tls_monitor = Process.monitor(tls_pid)
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, _reason}, 5_000
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    response = HTTP.Promise.await(promise)
    assert response.status == 413
    assert HTTP.Response.read_all(response) == "payload-too-large"

    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :early_response
  test "drains a cross-record 413 response without resuming its pending HTTP/2 upload" do
    test_pid = self()
    request_body = :binary.copy("p", @initial_window_size + 5)
    response_body = "cross-record-payload-too-large"

    first_record = [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, response_headers(413, response_body))
    ]

    first_record_binary = IO.iodata_to_binary(first_record)

    second_record = [
      Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>),
      Frame.encode(:window_update, 0, 1, <<0::1, 5::31>>),
      Frame.encode(:data, @end_stream, 1, response_body)
    ]

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        {initial_body, _buffer} =
          recv_request_body_until(socket, transport, buffer, @initial_window_size)

        assert initial_body == binary_part(request_body, 0, @initial_window_size)
        send(test_pid, {:server_received_request, self()})

        await_test_gate(:send_early_response_first_record)
        send_all(socket, transport, first_record)
        send(test_pid, :early_response_first_record_sent)

        await_test_gate(:send_early_response_second_record_and_close)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :early_response_second_record_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        method: :post,
        body: request_body,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_early_response_first_record)
    assert_receive :early_response_first_record_sent, 5_000

    {tls_pid, ^first_record_binary} = await_owner_tls_data(owner, first_record_binary)
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    send(server_pid, :send_early_response_second_record_and_close)
    assert_receive :early_response_second_record_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, :erlang.iolist_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    tls_monitor = Process.monitor(tls_pid)
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    response = HTTP.Promise.await(promise)
    assert response.status == 413
    assert HTTP.Response.read_all(response) == response_body
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :early_response
  test "delivers a no-body 413 response through ex_ssl while the HTTP/2 upload is pending" do
    test_pid = self()
    request_body = :binary.copy("p", @initial_window_size + 5)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        {initial_body, _buffer} =
          recv_request_body_until(socket, transport, buffer, @initial_window_size)

        assert initial_body == binary_part(request_body, 0, @initial_window_size)
        send(test_pid, {:server_received_request, self()})
        await_test_gate(:send_no_body_early_response_and_close)

        send_all(socket, transport, [
          Frame.encode(:settings, 0, 0, ""),
          Frame.encode(:headers, @end_headers ||| @end_stream, 1, response_headers(413, ""))
        ])

        :ok = :ssl.close(socket)
        send(test_pid, :no_body_early_response_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        method: :post,
        body: request_body,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_no_body_early_response_and_close)
    assert_receive :no_body_early_response_closed, 5_000
    tls_pid = await_owner_tls_data_and_close(owner)
    tls_monitor = Process.monitor(tls_pid)
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, _reason}, 5_000
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    response = HTTP.Promise.await(promise)

    assert response.status == 413
    assert HTTP.Response.read_all(response) == ""
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :early_response
  test "delivers an early 413 response through OTP TLS while the peer stays open for SETTINGS ACK" do
    test_pid = self()
    request_body = :binary.copy("p", @initial_window_size + 5)
    response_body = "otp-payload-too-large"

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        {initial_body, buffer} =
          recv_request_body_until(socket, transport, buffer, @initial_window_size)

        assert initial_body == binary_part(request_body, 0, @initial_window_size)

        send_all(socket, transport, [
          Frame.encode(:settings, 0, 0, ""),
          Frame.encode(:headers, @end_headers, 1, response_headers(413, response_body)),
          Frame.encode(:data, @end_stream, 1, response_body)
        ])

        buffer = assert_settings_ack(socket, transport, buffer)
        buffer = assert_window_update(socket, transport, buffer, 0, byte_size(response_body))
        buffer = assert_window_update(socket, transport, buffer, 1, byte_size(response_body))
        assert buffer == ""
        send(test_pid, {:otp_early_response_settings_acknowledged, self()})
        await_test_gate(:close_otp_early_response)
      end)

    promise =
      HTTP.fetch(url,
        method: :post,
        body: request_body,
        http_version: :http2,
        ssl: [verify: :verify_none]
      )

    response = HTTP.Promise.await(promise)
    assert response.status == 413
    assert HTTP.Response.read_all(response) == response_body
    assert_receive {:otp_early_response_settings_acknowledged, server_pid}, 5_000
    send(server_pid, :close_otp_early_response)
  end

  @tag :early_response
  test "delivers one complete response when a later buffered NO_ERROR reset follows END_STREAM" do
    test_pid = self()
    request_body = :binary.copy("p", @initial_window_size + 5)
    body = "no-error-reset-after-end-stream"

    first_record = [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, response_headers(body)),
      Frame.encode(:data, @end_stream, 1, body)
    ]

    first_record_binary = IO.iodata_to_binary(first_record)
    second_record = Frame.encode(:rst_stream, 0, 1, <<0::32>>)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        {initial_body, _buffer} =
          recv_request_body_until(socket, transport, buffer, @initial_window_size)

        assert initial_body == binary_part(request_body, 0, @initial_window_size)
        send(test_pid, {:server_received_request, self()})

        await_test_gate(:send_complete_response_record)
        send_all(socket, transport, first_record)
        send(test_pid, :complete_response_record_sent)

        await_test_gate(:send_no_error_reset_and_close)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :no_error_reset_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        method: :post,
        body: request_body,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:server_received_request, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_complete_response_record)
    assert_receive :complete_response_record_sent, 5_000

    {tls_pid, ^first_record_binary} = await_owner_tls_data(owner, first_record_binary)
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    send(server_pid, :send_no_error_reset_and_close)
    assert_receive :no_error_reset_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, byte_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    tls_monitor = Process.monitor(tls_pid)
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    response = HTTP.Promise.await(promise)
    assert response.status == 200
    assert HTTP.Response.read_all(response) == body
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  for {completion, end_stream_flag} <- [complete: @end_stream, incomplete: 0] do
    @tag :early_response
    test "handles a #{completion} NO_ERROR reset in the same HTTP/2 response batch" do
      test_pid = self()
      request_body = :binary.copy("p", @initial_window_size + 5)
      body = "no-error-reset"

      url =
        start_https_h2_server!([<<"h2">>], fn socket, transport ->
          {_request_headers, buffer} = recv_client_h2_request(socket, transport)

          {initial_body, _buffer} =
            recv_request_body_until(socket, transport, buffer, @initial_window_size)

          assert initial_body == binary_part(request_body, 0, @initial_window_size)

          send_all(socket, transport, [
            Frame.encode(:settings, 0, 0, ""),
            Frame.encode(:headers, @end_headers, 1, response_headers(body)),
            Frame.encode(:data, unquote(end_stream_flag), 1, body),
            Frame.encode(:rst_stream, 0, 1, <<0::32>>)
          ])

          send(test_pid, {:no_error_response_sent, self()})
          await_test_gate(:close_no_error_response)
        end)

      result =
        url
        |> HTTP.fetch(
          method: :post,
          body: request_body,
          http_version: :http2,
          tls_backend: :ex_ssl,
          ssl: [cacertfile: @cacertfile]
        )
        |> HTTP.Promise.await()

      case unquote(completion) do
        :complete ->
          assert result.status == 200
          assert HTTP.Response.read_all(result) == body

        :incomplete ->
          assert result == {:error, {:stream_reset, :no_error}}
      end

      assert_receive {:no_error_response_sent, server_pid}, 5_000
      send(server_pid, :close_no_error_response)
    end
  end

  @tag :cross_record
  test "drains a final streaming HTTP/2 frame buffered by ex_ssl after peer close" do
    test_pid = self()
    body = :binary.copy("q", HTTP.Config.streaming_threshold() + 1)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)
        send_h2_response_headers(socket, transport, body)
        buffer = assert_settings_ack(socket, transport, buffer)
        chunks = chunk_binary(body, 16_384)
        preceding_chunks = Enum.drop(chunks, -3)
        [first_final_chunk, second_final_chunk, third_final_chunk] = Enum.take(chunks, -3)

        Enum.reduce(preceding_chunks, buffer, fn chunk, current_buffer ->
          send_all(socket, transport, Frame.encode(:data, 0, 1, chunk))

          current_buffer =
            assert_window_update(socket, transport, current_buffer, 0, byte_size(chunk))

          assert_window_update(socket, transport, current_buffer, 1, byte_size(chunk))
        end)

        first_final_frame = Frame.encode(:data, 0, 1, first_final_chunk)
        split_at = 8_000
        <<first_frame_start::binary-size(split_at), first_frame_rest::binary>> = first_final_frame

        first_record = [Frame.encode(:ping, 0, 0, "final123"), first_frame_start]

        second_record = [
          first_frame_rest,
          Frame.encode(:data, 0, 1, second_final_chunk),
          Frame.encode(:data, @end_stream, 1, third_final_chunk)
        ]

        send(
          test_pid,
          {:server_ready_to_finish, self(), IO.iodata_to_binary(first_record), second_record}
        )

        await_test_gate(:send_final_first_record)
        send_all(socket, transport, first_record)
        send(test_pid, :final_first_record_sent)

        await_test_gate(:send_final_second_record_and_close)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :final_second_record_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    response = HTTP.Promise.await(promise)
    assert response.status == 200
    stream_monitor = monitor_test_process(response.stream)
    reader = Task.async(fn -> HTTP.Response.read_all(response) end)
    monitor_test_process(reader.pid)

    assert_receive {:server_ready_to_finish, server_pid, first_record, second_record}, 10_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_final_first_record)
    assert_receive :final_first_record_sent, 5_000

    {tls_pid, ^first_record} = await_owner_tls_data(owner, first_record)
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    send(server_pid, :send_final_second_record_and_close)
    assert_receive :final_second_record_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, :erlang.iolist_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    tls_monitor = Process.monitor(tls_pid)
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    assert Task.await(reader, 10_000) == body
    assert_receive {:DOWN, ^stream_monitor, :process, _stream, :normal}, 5_000
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  @tag :cross_record
  test "aborts an ex_ssl cross-record drain while stream backpressure holds the final body" do
    {server_pid, controller, promise, owner, first_record, second_record} =
      cross_record_stream_drain_fixture(self(), 5_000)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    {tls_pid, owner_monitor, tls_monitor} =
      queue_cross_record_stream_drain(server_pid, owner, first_record, second_record)

    response = HTTP.Promise.await(promise)
    assert response.status == 200
    assert is_pid(response.stream)
    stream = response.stream
    stream_monitor = monitor_test_process(stream)

    holder = hold_cross_record_stream_chunk(stream, self())
    monitor_test_process(holder)

    assert_receive {:held_cross_record_stream_chunk, ^holder, ^stream, _chunk, _ack_ref},
                   5_000

    await_cross_record_stream_backpressure(owner)

    :ok = HTTP.AbortController.abort(controller)
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000

    reader =
      Task.Supervisor.async_nolink(:http_fetch_task_supervisor, fn ->
        assert_raise RuntimeError, "stream read failed: :aborted", fn ->
          HTTP.Response.read_all(response)
        end
      end)

    monitor_test_process(reader.pid)
    await_cross_record_read_all(reader.pid)
    send(holder, :release_cross_record_stream_chunk)

    assert %RuntimeError{message: "stream read failed: :aborted"} = Task.await(reader, 5_000)
    assert_receive {:DOWN, ^stream_monitor, :process, _stream, :normal}, 5_000
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
  end

  @tag :cross_record
  test "keeps the original deadline while an ex_ssl cross-record drain is backpressured" do
    timeout = 2_000
    started_at = System.monotonic_time(:millisecond)

    {server_pid, controller, promise, owner, first_record, second_record} =
      cross_record_stream_drain_fixture(self(), timeout)

    on_exit(fn ->
      cleanup_owner(owner, controller)
    end)

    # This explicit timer gate consumes half the request budget before entering
    # the drain. A drain that reset the request timeout would outlive the
    # original absolute deadline asserted below.
    Process.send_after(self(), :begin_cross_record_deadline_drain, div(timeout, 2))
    assert_receive :begin_cross_record_deadline_drain, div(timeout, 2) + 250

    {tls_pid, owner_monitor, tls_monitor} =
      queue_cross_record_stream_drain(server_pid, owner, first_record, second_record)

    response = HTTP.Promise.await(promise)
    assert response.status == 200
    assert is_pid(response.stream)
    stream = response.stream
    stream_monitor = monitor_test_process(stream)

    holder = hold_cross_record_stream_chunk(stream, self())
    monitor_test_process(holder)

    assert_receive {:held_cross_record_stream_chunk, ^holder, ^stream, _chunk, _ack_ref},
                   5_000

    await_cross_record_stream_backpressure(owner)

    deadline_at = started_at + timeout
    remaining = deadline_at - System.monotonic_time(:millisecond)
    assert remaining > 0

    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, remaining + 400

    reader =
      Task.Supervisor.async_nolink(:http_fetch_task_supervisor, fn ->
        assert_raise RuntimeError, ~r/^stream read failed: :(request_timeout|timeout)$/, fn ->
          HTTP.Response.read_all(response)
        end
      end)

    monitor_test_process(reader.pid)
    await_cross_record_read_all(reader.pid)
    send(holder, :release_cross_record_stream_chunk)

    assert %RuntimeError{message: message} = Task.await(reader, 5_000)
    assert message in ["stream read failed: :request_timeout", "stream read failed: :timeout"]

    assert_receive {:DOWN, ^stream_monitor, :process, _stream, :normal}, 5_000
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
  end

  for {completion, end_stream_flag} <- [complete: @end_stream, incomplete: 0] do
    @tag :early_response
    test "handles a closed ex_ssl HTTP/2 connection with request body writes for a #{completion} response" do
      test_pid = self()
      body = :binary.copy("p", @initial_window_size + 5)

      url =
        start_https_h2_server!([<<"h2">>], fn socket, transport ->
          {_request_headers, buffer} = recv_client_h2_request(socket, transport)

          {initial_body, _buffer} =
            recv_request_body_until(socket, transport, buffer, @initial_window_size)

          assert initial_body == binary_part(body, 0, @initial_window_size)
          send(test_pid, {:server_received_request, self()})

          await_test_gate(:send_response_and_close)

          frames = [
            Frame.encode(:settings, 0, 0, ""),
            Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>),
            Frame.encode(:window_update, 0, 1, <<0::1, 5::31>>),
            Frame.encode(:headers, @end_headers, 1, response_headers("complete")),
            Frame.encode(:data, unquote(end_stream_flag), 1, "complete")
          ]

          send_all(socket, transport, frames)

          :ssl.close(socket)
          send(test_pid, :server_closed)
        end)

      controller = HTTP.AbortController.new()

      promise =
        HTTP.fetch(url,
          method: :post,
          body: body,
          http_version: :http2,
          signal: controller,
          tls_backend: :ex_ssl,
          ssl: [cacertfile: @cacertfile]
        )

      assert_receive {:server_received_request, server_pid}, 5_000
      owner = await_owner(controller)
      await_owner_loop(owner)

      on_exit(fn ->
        if Process.info(owner, :status) == {:status, :suspended},
          do: :erlang.resume_process(owner)

        if Process.alive?(controller), do: HTTP.AbortController.abort(controller)
      end)

      true = :erlang.suspend_process(owner)
      send(server_pid, :send_response_and_close)
      assert_receive :server_closed, 5_000
      tls_pid = await_owner_tls_data_and_close(owner)
      tls_monitor = Process.monitor(tls_pid)
      assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, _reason}, 5_000
      owner_monitor = Process.monitor(owner)
      true = :erlang.resume_process(owner)

      result = HTTP.Promise.await(promise)

      case unquote(completion) do
        :complete ->
          assert result.status == 200
          assert HTTP.Response.read_all(result) == "complete"

        :incomplete ->
          assert result == {:error, :closed}
      end

      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
    end
  end

  test "delivers a complete ex_ssl HTTP/2 response when the peer closes immediately" do
    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send_h2_response(socket, transport, "closed-after-response")
      end)

    response =
      url
      |> HTTP.fetch(
        http_version: :http2,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "closed-after-response"
  end

  test "delivers a complete large ex_ssl HTTP/2 response without a final window update" do
    test_pid = self()
    body = :binary.copy("z", HTTP.Config.streaming_threshold() + 1)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)
        send_h2_response_headers(socket, transport, body)
        buffer = assert_settings_ack(socket, transport, buffer)
        chunks = chunk_binary(body, 16_384)
        last_index = length(chunks) - 1

        {final_chunk, preceding_chunks} = List.pop_at(chunks, last_index)

        Enum.reduce(preceding_chunks, buffer, fn chunk, buffer ->
          send_all(socket, transport, Frame.encode(:data, 0, 1, chunk))
          buffer = assert_window_update(socket, transport, buffer, 0, byte_size(chunk))
          assert_window_update(socket, transport, buffer, 1, byte_size(chunk))
        end)

        send(test_pid, {:server_ready_to_finish, self()})

        receive do
          :send_final_chunk_and_close ->
            send_all(socket, transport, Frame.encode(:data, @end_stream, 1, final_chunk))
            :ok = :ssl.close(socket)
            send(test_pid, :server_closed)
        end
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    response =
      HTTP.Promise.await(promise)

    stream_monitor = Process.monitor(response.stream)
    reader = Task.async(fn -> HTTP.Response.read_all(response) end)
    assert_receive {:server_ready_to_finish, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    on_exit(fn ->
      if Process.info(owner, :status) == {:status, :suspended}, do: :erlang.resume_process(owner)
      if Process.alive?(controller), do: HTTP.AbortController.abort(controller)
    end)

    true = :erlang.suspend_process(owner)
    send(server_pid, :send_final_chunk_and_close)
    assert_receive :server_closed, 5_000
    tls_pid = await_owner_tls_data_and_close(owner)
    tls_monitor = Process.monitor(tls_pid)
    assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, _reason}, 5_000
    owner_monitor = Process.monitor(owner)
    true = :erlang.resume_process(owner)

    assert response.status == 200
    assert Task.await(reader, 5_000) == body
    assert_receive {:DOWN, ^stream_monitor, :process, _stream, :normal}, 5_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
  end

  test "rejects an ex_ssl HTTP/2 response that closes without END_STREAM" do
    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send_h2_response_headers(socket, transport, "truncated")
        send_all(socket, transport, Frame.encode(:data, 0, 1, "truncated"))
      end)

    assert {:error, :closed} =
             url
             |> HTTP.fetch(
               http_version: :http2,
               tls_backend: :ex_ssl,
               ssl: [cacertfile: @cacertfile]
             )
             |> HTTP.Promise.await()
  end

  test "auto HTTPS falls back to HTTP/1.1 through ex_ssl without ALPN" do
    url =
      start_https_h2_server!([], fn socket, _transport ->
        assert {:ok, request} = recv_http1_headers(socket, <<>>)
        assert request =~ "GET /test HTTP/1.1\r\n"

        :ok =
          :ssl.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfallback"
          )
      end)

    response =
      url
      |> HTTP.fetch(
        http_version: :auto,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )
      |> HTTP.Promise.await()

    assert HTTP.Response.read_all(response) == "fallback"
  end

  test "streams large forced HTTPS HTTP/2 responses through ex_ssl" do
    body = :binary.copy("h", HTTP.Config.streaming_threshold() + 1)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)
        send_h2_response_headers(socket, transport, body)
        buffer = assert_settings_ack(socket, transport, buffer)

        chunks = chunk_binary(body, 16_384)
        last_index = length(chunks) - 1

        Enum.reduce(Enum.with_index(chunks), buffer, fn {chunk, index}, buffer ->
          flags = if index == last_index, do: @end_stream, else: 0
          send_all(socket, transport, Frame.encode(:data, flags, 1, chunk))

          buffer = assert_window_update(socket, transport, buffer, 0, byte_size(chunk))
          assert_window_update(socket, transport, buffer, 1, byte_size(chunk))
        end)
      end)

    response =
      url
      |> HTTP.fetch(
        http_version: :http2,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )
      |> HTTP.Promise.await()

    assert is_pid(response.stream)
    assert HTTP.Response.read_all(response) == body
  end

  test "forced HTTPS HTTP/2 through ex_ssl fails without h2 ALPN" do
    url =
      start_https_h2_server!([], fn socket, _transport ->
        :timer.sleep(100)
        :ssl.close(socket)
      end)

    assert {:error, {:http2_not_negotiated, nil}} =
             url
             |> HTTP.fetch(
               http_version: :http2,
               tls_backend: :ex_ssl,
               ssl: [cacertfile: @cacertfile]
             )
             |> HTTP.Promise.await()
  end

  defp start_h2c_server!(handler) do
    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        handler.(socket, :gen_tcp)
        :gen_tcp.close(socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp start_h2c_reuse_server!(parent) do
    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        send(parent, {:h2c_accepts, 1})

        {preface, buffer} =
          recv_exact(socket, :gen_tcp, byte_size(HTTP.HTTP2.connection_preface()), <<>>)

        assert preface == HTTP.HTTP2.connection_preface()

        {:ok, %Frame{type: :settings, stream_id: 0}, buffer} =
          recv_frame(socket, :gen_tcp, buffer)

        {:ok, %Frame{type: :headers, stream_id: 1, flags: flags, payload: header_block}, buffer} =
          recv_frame(socket, :gen_tcp, buffer)

        assert (flags &&& @end_headers) == @end_headers
        {:ok, decoder, _headers} = HPACK.decode(HPACK.new_decoder(), header_block)

        send_all(socket, :gen_tcp, [
          Frame.encode(:settings, 0, 0, ""),
          Frame.encode(:headers, @end_headers, 1, response_headers(200, "/one")),
          Frame.encode(:data, @end_stream, 1, "/one")
        ])

        buffer = assert_settings_ack(socket, :gen_tcp, buffer)
        {path, _buffer} = recv_h2_request(socket, :gen_tcp, buffer, 3, decoder)

        send_all(socket, :gen_tcp, [
          Frame.encode(:headers, @end_headers, 3, response_headers(200, path)),
          Frame.encode(:data, @end_stream, 3, path)
        ])

        :gen_tcp.close(socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp start_h2c_overlap_server!(parent, expected) do
    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)

        {preface, buffer} =
          recv_exact(socket, :gen_tcp, byte_size(HTTP.HTTP2.connection_preface()), <<>>)

        assert preface == HTTP.HTTP2.connection_preface()

        {:ok, %Frame{type: :settings, stream_id: 0}, buffer} =
          recv_frame(socket, :gen_tcp, buffer)

        send_all(socket, :gen_tcp, [Frame.encode(:settings, 0, 0, "")])
        requests = collect_h2_requests(socket, buffer, HPACK.new_decoder(), %{}, expected, parent)
        send(parent, {:h2c_overlap, 1, Enum.sort(Map.keys(requests))})
        reply_h2_requests(requests, socket)
        Process.sleep(200)

        :gen_tcp.close(socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp collect_h2_requests(_socket, _buffer, _decoder, requests, expected, _parent)
       when map_size(requests) == expected do
    requests
  end

  defp collect_h2_requests(socket, buffer, decoder, requests, expected, parent) do
    case recv_frame(socket, :gen_tcp, buffer) do
      {:ok, %Frame{type: :headers, stream_id: stream_id, flags: flags, payload: block}, buffer}
      when stream_id > 0 ->
        assert (flags &&& @end_headers) == @end_headers
        {:ok, decoder, headers} = HPACK.decode(decoder, block)
        {_, path} = Enum.find(headers, fn {name, _value} -> name == ":path" end)
        requests = Map.put(requests, stream_id, path)

        if map_size(requests) == 1, do: send(parent, {:h2c_overlap_first, 1})
        collect_h2_requests(socket, buffer, decoder, requests, expected, parent)

      {:ok, _frame, buffer} ->
        collect_h2_requests(socket, buffer, decoder, requests, expected, parent)
    end
  end

  defp reply_h2_requests(requests, socket) do
    send_all(
      socket,
      :gen_tcp,
      Enum.flat_map(requests, fn {stream_id, path} ->
        [
          Frame.encode(:headers, @end_headers, stream_id, response_headers(200, path)),
          Frame.encode(:data, @end_stream, stream_id, path)
        ]
      end)
    )
  end

  defp recv_h2_request(socket, transport, buffer, stream_id, decoder) do
    case recv_frame(socket, transport, buffer) do
      {:ok, %Frame{type: :headers, stream_id: ^stream_id, flags: flags, payload: block}, buffer} ->
        assert (flags &&& @end_headers) == @end_headers
        {:ok, _decoder, headers} = HPACK.decode(decoder, block)
        {_, path} = Enum.find(headers, fn {name, _} -> name == ":path" end)
        {path, buffer}

      {:ok, _other, buffer} ->
        recv_h2_request(socket, transport, buffer, stream_id, decoder)
    end
  end

  defp start_https_h2_server!(alpn_protocols, handler) do
    alpn_opts =
      if alpn_protocols == [] do
        []
      else
        [alpn_preferred_protocols: alpn_protocols]
      end

    {:ok, listen_socket} =
      :ssl.listen(
        0,
        [
          :binary,
          packet: :raw,
          active: false,
          ip: {127, 0, 0, 1},
          reuseaddr: true,
          certfile: @certfile,
          keyfile: @keyfile
        ] ++ alpn_opts
      )

    {:ok, {{127, 0, 0, 1}, port}} = :ssl.sockname(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, transport_socket} = :ssl.transport_accept(listen_socket, 5_000)

        case :ssl.handshake(transport_socket) do
          {:ok, socket} ->
            handler.(socket, :ssl)
            :ok = :ssl.close(socket)

          {:error, _reason} ->
            :ok
        end

        :ssl.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :ssl.close(listen_socket)
    end)

    "https://127.0.0.1:#{port}/test"
  end

  defp recv_client_h2_request(socket, transport) do
    {preface, buffer} =
      recv_exact(socket, transport, byte_size(HTTP.HTTP2.connection_preface()), <<>>)

    assert preface == HTTP.HTTP2.connection_preface()

    {:ok, %Frame{type: :settings, stream_id: 0}, buffer} =
      recv_frame(socket, transport, buffer)

    {:ok, %Frame{type: :headers, stream_id: 1, flags: flags, payload: header_block}, buffer} =
      recv_frame(socket, transport, buffer)

    assert (flags &&& @end_headers) == @end_headers

    {:ok, _decoder, headers} = HPACK.decode(HPACK.new_decoder(), header_block)
    {headers, buffer}
  end

  defp recv_http1_headers(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      {:ok, acc}
    else
      case :ssl.recv(socket, 0, 5_000) do
        {:ok, data} -> recv_http1_headers(socket, acc <> data)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp send_h2_response(socket, transport, body) do
    headers = response_headers(body)

    send_all(socket, transport, [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, headers),
      Frame.encode(:data, @end_stream, 1, body)
    ])
  end

  defp send_h2_response_headers(socket, transport, body) do
    send_all(socket, transport, [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, response_headers(body))
    ])
  end

  defp response_headers(body), do: response_headers(200, body)

  defp response_headers(status, body) do
    HPACK.encode_headers([
      {":status", Integer.to_string(status)},
      {"content-length", Integer.to_string(byte_size(body))},
      {"x-protocol", "h2"}
    ])
  end

  defp assert_settings_ack(socket, transport, buffer) do
    assert {:ok, %Frame{type: :settings, flags: flags, stream_id: 0, payload: ""}, buffer} =
             recv_frame(socket, transport, buffer)

    assert (flags &&& @ack) == @ack
    buffer
  end

  defp assert_window_update(socket, transport, buffer, stream_id, increment) do
    assert {:ok,
            %Frame{
              type: :window_update,
              stream_id: ^stream_id,
              payload: <<0::1, received_increment::31>>
            }, buffer} = recv_frame(socket, transport, buffer)

    assert received_increment == increment
    buffer
  end

  defp recv_frame(socket, transport, buffer) do
    case Frame.decode(buffer) do
      {:ok, frame, rest} ->
        {:ok, frame, rest}

      :more ->
        {:ok, data} = apply(transport, :recv, [socket, 0, 5_000])
        recv_frame(socket, transport, buffer <> data)
    end
  end

  defp recv_exact(_socket, _transport, size, acc) when byte_size(acc) >= size do
    <<data::binary-size(size), rest::binary>> = acc
    {data, rest}
  end

  defp recv_exact(socket, transport, size, acc) do
    {:ok, data} = apply(transport, :recv, [socket, 0, 5_000])
    recv_exact(socket, transport, size, acc <> data)
  end

  defp recv_request_body_until(socket, transport, buffer, size),
    do: recv_request_body_until(socket, transport, buffer, size, "")

  defp recv_request_body_until(_socket, _transport, buffer, size, body)
       when byte_size(body) >= size do
    {body, buffer}
  end

  defp recv_request_body_until(socket, transport, buffer, size, body) do
    {:ok, %Frame{type: :data, stream_id: 1, flags: flags, payload: chunk}, buffer} =
      recv_frame(socket, transport, buffer)

    refute (flags &&& @end_stream) == @end_stream
    recv_request_body_until(socket, transport, buffer, size, body <> chunk)
  end

  defp recv_request_body_until_end(socket, transport, buffer),
    do: recv_request_body_until_end(socket, transport, buffer, "")

  defp recv_request_body_until_end(socket, transport, buffer, body) do
    {:ok, %Frame{type: :data, stream_id: 1, flags: flags, payload: chunk}, buffer} =
      recv_frame(socket, transport, buffer)

    body = body <> chunk

    if (flags &&& @end_stream) == @end_stream do
      {body, buffer}
    else
      recv_request_body_until_end(socket, transport, buffer, body)
    end
  end

  defp send_all(socket, transport, iodata) do
    :ok = apply(transport, :send, [socket, iodata])
  end

  defp await_test_gate(gate) do
    receive do
      ^gate -> :ok
    after
      5_000 -> exit({:test_gate_timeout, gate})
    end
  end

  defp monitor_test_process(pid) do
    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
    end)

    Process.monitor(pid)
  end

  defp cleanup_owner(owner, controller) do
    if Process.info(owner, :status) == {:status, :suspended}, do: :erlang.resume_process(owner)

    if Process.alive?(controller) do
      HTTP.AbortController.abort(controller)
    else
      if Process.alive?(owner), do: send(owner, :abort)
    end
  end

  defp await_owner(controller) do
    case :sys.get_state(controller).request_id do
      owner when is_pid(owner) -> owner
      nil -> flunk("socket owner was not registered before the request reached the server")
    end
  end

  defp await_owner_tls_data_and_close(owner) do
    await_owner_tls_data_and_close(owner, nil, System.monotonic_time(:millisecond) + 5_000)
  end

  defp await_owner_tls_data(owner, expected_data) do
    await_owner_tls_data(owner, expected_data, System.monotonic_time(:millisecond) + 5_000)
  end

  defp await_owner_tls_data(owner, expected_data, deadline_at) do
    case Process.info(owner, :messages) do
      {:messages, messages} ->
        case Enum.find(messages, fn
               {:ssl, %SSL.Socket{}, ^expected_data} -> true
               _message -> false
             end) do
          {:ssl, %SSL.Socket{pid: tls_pid}, ^expected_data} -> {tls_pid, expected_data}
          nil -> await_owner_tls_data_or_fail(owner, expected_data, deadline_at)
        end

      nil ->
        flunk("socket owner exited before receiving the first TLS record")
    end
  end

  defp await_owner_tls_data_or_fail(owner, expected_data, deadline_at) do
    remaining = deadline_at - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      flunk("socket owner did not receive the first TLS record as one active-once delivery")
    else
      receive do
      after
        min(10, remaining) -> await_owner_tls_data(owner, expected_data, deadline_at)
      end
    end
  end

  defp assert_owner_has_only_tls_data(owner, tls_pid, expected_count) do
    {:messages, messages} = Process.info(owner, :messages)

    assert messages
           |> Enum.count(&match?({:ssl, %SSL.Socket{pid: ^tls_pid}, _data}, &1)) == expected_count
  end

  defp assert_tls_buffered_after_peer_close(tls_pid, expected_size) do
    assert Application.spec(:ex_ssl, :vsn) == ~c"0.4.0",
           "revalidate this private buffer probe before testing another ex_ssl version"

    assert_tls_buffered_after_peer_close(
      tls_pid,
      expected_size,
      System.monotonic_time(:millisecond) + 5_000
    )
  end

  defp assert_tls_buffered_after_peer_close(tls_pid, expected_size, deadline_at) do
    {_phase, state} = :sys.get_state(tls_pid)

    if state.closed do
      assert state.size == expected_size
      assert state.active == false
      :ok
    else
      remaining = deadline_at - System.monotonic_time(:millisecond)

      if remaining <= 0 do
        flunk("second TLS record was not retained in the TLS receive buffer after peer close")
      else
        receive do
        after
          min(10, remaining) ->
            assert_tls_buffered_after_peer_close(tls_pid, expected_size, deadline_at)
        end
      end
    end
  end

  defp await_owner_loop(owner) do
    await_owner_loop(owner, System.monotonic_time(:millisecond) + 5_000)
  end

  defp await_owner_loop(owner, deadline_at) do
    if Process.info(owner, :current_function) ==
         {:current_function, {HTTP.SocketClient, :owner_loop, 1}} and
         Process.info(owner, :status) == {:status, :waiting} do
      :ok
    else
      remaining = deadline_at - System.monotonic_time(:millisecond)

      if remaining <= 0 do
        flunk("socket owner did not return to its receive loop before the TLS close gate")
      else
        receive do
        after
          min(10, remaining) -> await_owner_loop(owner, deadline_at)
        end
      end
    end
  end

  defp await_owner_tls_data_and_close(owner, tls_pid, deadline_at) do
    case Process.info(owner, :messages) do
      {:messages, messages} ->
        tls_pid =
          tls_pid ||
            Enum.find_value(messages, fn
              {:ssl, %SSL.Socket{pid: pid}, _data} -> pid
              _message -> nil
            end)

        if is_pid(tls_pid) and
             Enum.any?(messages, &match?({:ssl_closed, %SSL.Socket{pid: ^tls_pid}}, &1)) do
          tls_pid
        else
          remaining = deadline_at - System.monotonic_time(:millisecond)

          if remaining <= 0 do
            flunk("socket owner did not receive the queued TLS response and close")
          else
            receive do
            after
              min(10, remaining) -> await_owner_tls_data_and_close(owner, tls_pid, deadline_at)
            end
          end
        end

      nil ->
        flunk("socket owner exited before receiving the queued TLS response and close")
    end
  end

  defp cross_record_stream_drain_fixture(test_pid, timeout) do
    body = "backpressured-final-record"

    first_record = [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(
        :headers,
        @end_headers,
        1,
        HPACK.encode_headers([{":status", "200"}, {"x-protocol", "h2"}])
      )
    ]

    first_record_binary = IO.iodata_to_binary(first_record)
    second_record = Frame.encode(:data, @end_stream, 1, body)

    url =
      start_https_h2_server!([<<"h2">>], fn socket, transport ->
        {_request_headers, _buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:cross_record_stream_server_ready, self()})

        await_test_gate(:send_cross_record_stream_first)
        send_all(socket, transport, first_record)
        send(test_pid, :cross_record_stream_first_sent)

        await_test_gate(:send_cross_record_stream_second)
        send_all(socket, transport, second_record)
        :ok = :ssl.close(socket)
        send(test_pid, :cross_record_stream_second_closed)
      end)

    controller = HTTP.AbortController.new()

    promise =
      HTTP.fetch(url,
        http_version: :http2,
        signal: controller,
        timeout: timeout,
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile]
      )

    assert_receive {:cross_record_stream_server_ready, server_pid}, 5_000
    owner = await_owner(controller)
    await_owner_loop(owner)

    {server_pid, controller, promise, owner, first_record_binary, second_record}
  end

  defp queue_cross_record_stream_drain(server_pid, owner, first_record, second_record) do
    true = :erlang.suspend_process(owner)
    send(server_pid, :send_cross_record_stream_first)
    assert_receive :cross_record_stream_first_sent, 5_000

    {tls_pid, ^first_record} = await_owner_tls_data(owner, first_record)
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    send(server_pid, :send_cross_record_stream_second)
    assert_receive :cross_record_stream_second_closed, 5_000
    assert_tls_buffered_after_peer_close(tls_pid, byte_size(second_record))
    assert_owner_has_only_tls_data(owner, tls_pid, 1)

    owner_monitor = Process.monitor(owner)
    tls_monitor = Process.monitor(tls_pid)
    true = :erlang.resume_process(owner)
    {tls_pid, owner_monitor, tls_monitor}
  end

  defp hold_cross_record_stream_chunk(stream, test_pid) do
    spawn(fn ->
      send(stream, {:read_chunk, self(), :ack})

      receive do
        {:stream_chunk, ^stream, chunk, ack_ref} ->
          send(test_pid, {:held_cross_record_stream_chunk, self(), stream, chunk, ack_ref})

          receive do
            :release_cross_record_stream_chunk ->
              send(stream, {:stream_chunk_ack, ack_ref})
          after
            5_000 ->
              send(test_pid, {:held_cross_record_stream_chunk_timeout, self()})
          end
      after
        5_000 ->
          send(test_pid, {:held_cross_record_stream_chunk_timeout, self()})
      end
    end)
  end

  defp await_cross_record_stream_backpressure(owner) do
    await_cross_record_stream_backpressure(owner, System.monotonic_time(:millisecond) + 5_000)
  end

  defp await_cross_record_stream_backpressure(owner, deadline_at) do
    if Process.info(owner, :current_function) == {:current_function, {HTTP.Stream, :chunk, 3}} and
         Process.info(owner, :status) == {:status, :waiting} do
      :ok
    else
      await_cross_record_condition(
        owner,
        deadline_at,
        "socket owner did not block on stream backpressure",
        fn -> await_cross_record_stream_backpressure(owner, deadline_at) end
      )
    end
  end

  defp await_cross_record_read_all(reader) do
    await_cross_record_read_all(reader, System.monotonic_time(:millisecond) + 5_000)
  end

  defp await_cross_record_read_all(reader, deadline_at) do
    if Process.info(reader, :current_function) ==
         {:current_function, {HTTP.Response, :collect_stream, 2}} and
         Process.info(reader, :status) == {:status, :waiting} do
      :ok
    else
      await_cross_record_condition(
        reader,
        deadline_at,
        "response reader did not wait for stream error",
        fn -> await_cross_record_read_all(reader, deadline_at) end
      )
    end
  end

  defp await_cross_record_condition(_pid, deadline_at, message, fun) do
    remaining = deadline_at - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      flunk(message)
    else
      receive do
      after
        min(10, remaining) -> fun.()
      end
    end
  end

  defp chunk_binary(binary, size) when byte_size(binary) <= size, do: [binary]

  defp chunk_binary(binary, size) do
    <<chunk::binary-size(size), rest::binary>> = binary
    [chunk | chunk_binary(rest, size)]
  end

  defp negotiated_protocol(socket) do
    case :ssl.negotiated_protocol(socket) do
      {:ok, protocol} when is_binary(protocol) -> protocol
      {:ok, protocol} when is_list(protocol) -> List.to_string(protocol)
      {:error, :protocol_not_negotiated} -> nil
    end
  end
end
