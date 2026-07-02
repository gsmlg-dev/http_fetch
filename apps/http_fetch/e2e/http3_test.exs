defmodule E2E.HTTP3Test do
  use ExUnit.Case, async: false

  require Logger

  @moduletag :e2e
  @moduletag timeout: 30_000

  @certfile Path.expand("../test/support/fixtures/localhost.pem", __DIR__)
  @keyfile Path.expand("../test/support/fixtures/localhost.key", __DIR__)

  setup_all do
    previous_level = Logger.level()
    Logger.configure(level: :warning)

    on_exit(fn -> Logger.configure(level: previous_level) end)
  end

  test "fetches a response over HTTP/3" do
    test_pid = self()

    url =
      start_http3_server!(fn conn, stream_id, method, path, headers ->
        send(test_pid, {:h3_request, method, path, headers})

        :ok =
          :quic_h3.send_response(conn, stream_id, 200, [
            {"content-type", "text/plain"},
            {"x-protocol", "h3"}
          ])

        :ok = :quic_h3.send_data(conn, stream_id, "h3-ok", true)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :http3, ssl: [verify: :verify_none], timeout: 5_000)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Headers.get(response.headers, "x-protocol") == "h3"
    refute HTTP.Headers.get(response.headers, ":status")
    assert HTTP.Response.read_all(response) == "h3-ok"

    assert_receive {:h3_request, <<"GET">>, <<"/hello?transport=h3">>, headers}
    assert {<<"user-agent">>, _user_agent} = List.keyfind(headers, <<"user-agent">>, 0)
  end

  test "sends a request body over HTTP/3" do
    test_pid = self()

    url =
      start_http3_server!(fn conn, stream_id, method, path, headers ->
        send(test_pid, {:h3_post_request, method, path, headers})
        :ok = :quic_h3.set_stream_handler(conn, stream_id, self(), %{drain_buffer: false})

        body = receive_h3_body(conn, stream_id, test_pid, [])
        send(test_pid, {:h3_post_body, body})

        :ok = :quic_h3.send_response(conn, stream_id, 200, [{"content-type", "text/plain"}])
        :ok = :quic_h3.send_data(conn, stream_id, "received:" <> body, true)
      end)

    response =
      url
      |> HTTP.fetch(
        method: :post,
        body: "h3-payload",
        content_type: "text/plain",
        http_version: :http3,
        ssl: [verify: :verify_none],
        timeout: 5_000
      )
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "received:h3-payload"

    assert_receive {:h3_post_request, <<"POST">>, <<"/hello?transport=h3">>, headers}
    assert {<<"content-length">>, <<"10">>} in headers
    assert_receive {:h3_post_body, "h3-payload"}
  end

  test "sends a large request body over HTTP/3 in chunks" do
    test_pid = self()
    body = :binary.copy("h3-large-payload", 5_000)

    url =
      start_http3_server!(fn conn, stream_id, method, path, headers ->
        send(test_pid, {:h3_large_post_request, method, path, headers})
        :ok = :quic_h3.set_stream_handler(conn, stream_id, self(), %{drain_buffer: false})

        received_body = receive_h3_body(conn, stream_id, test_pid, [])
        send(test_pid, {:h3_large_post_body_size, byte_size(received_body)})

        :ok = :quic_h3.send_response(conn, stream_id, 200, [{"content-type", "text/plain"}])
        :ok = :quic_h3.send_data(conn, stream_id, "received:#{byte_size(received_body)}", true)
      end)

    response =
      url
      |> HTTP.fetch(
        method: :post,
        body: body,
        content_type: "application/octet-stream",
        http_version: :http3,
        ssl: [verify: :verify_none],
        timeout: 10_000
      )
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "received:#{byte_size(body)}"

    assert_receive {:h3_large_post_request, <<"POST">>, <<"/hello?transport=h3">>, headers}
    assert {<<"content-length">>, content_length} = List.keyfind(headers, <<"content-length">>, 0)
    assert to_string(content_length) == Integer.to_string(byte_size(body))
    assert_receive {:h3_large_post_body_size, size}
    assert size == byte_size(body)
  end

  test "aborts an in-flight HTTP/3 request" do
    test_pid = self()
    controller = HTTP.AbortController.new()

    url =
      start_http3_server!(fn _conn, _stream_id, method, path, _headers ->
        send(test_pid, {:h3_abort_request, method, path})
        Process.sleep(5_000)
      end)

    promise =
      HTTP.fetch(url,
        http_version: :http3,
        ssl: [verify: :verify_none],
        signal: controller,
        timeout: 10_000
      )

    assert_receive {:h3_abort_request, <<"GET">>, <<"/hello?transport=h3">>}, 5_000
    :ok = HTTP.AbortController.abort(controller)

    assert {:error, :aborted} = HTTP.Promise.await(promise, 10_000)
  end

  test "aborts while waiting for HTTP/3 connect" do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(socket)
    on_exit(fn -> :gen_udp.close(socket) end)

    controller = HTTP.AbortController.new()

    promise =
      "https://127.0.0.1:#{port}/never-connect"
      |> HTTP.fetch(
        http_version: :http3,
        ssl: [verify: :verify_none],
        signal: controller,
        connect_timeout: 10_000,
        timeout: 10_000
      )

    Process.sleep(100)
    started_at = System.monotonic_time(:millisecond)
    :ok = HTTP.AbortController.abort(controller)

    assert {:error, :aborted} = HTTP.Promise.await(promise, 10_000)
    assert System.monotonic_time(:millisecond) - started_at < 2_000
  end

  test "ignores informational HTTP/3 responses before the final response" do
    url =
      start_http3_server!(fn conn, stream_id, _method, _path, _headers ->
        :ok = :quic_h3.send_response(conn, stream_id, 103, [{"link", "</style.css>"}])
        :ok = :quic_h3.send_response(conn, stream_id, 200, [{"content-type", "text/plain"}])
        :ok = :quic_h3.send_data(conn, stream_id, "final", true)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :http3, ssl: [verify: :verify_none], timeout: 5_000)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "final"
  end

  test "streams large HTTP/3 responses" do
    previous_threshold = Application.get_env(:http_fetch, :streaming_threshold)
    Application.put_env(:http_fetch, :streaming_threshold, 1_024)

    on_exit(fn ->
      if is_nil(previous_threshold) do
        Application.delete_env(:http_fetch, :streaming_threshold)
      else
        Application.put_env(:http_fetch, :streaming_threshold, previous_threshold)
      end
    end)

    body = :binary.copy("s", HTTP.Config.streaming_threshold() + 1)

    url =
      start_http3_server!(fn conn, stream_id, _method, _path, _headers ->
        :ok =
          :quic_h3.send_response(conn, stream_id, 200, [
            {"content-type", "application/octet-stream"},
            {"content-length", Integer.to_string(byte_size(body))}
          ])

        :ok = :quic_h3.send_data(conn, stream_id, body, true)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :http3, ssl: [verify: :verify_none], timeout: 10_000)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert response.body == nil
    assert is_pid(response.stream)
    assert HTTP.Response.read_all(response) == body
  end

  defp start_http3_server!(handler) do
    :ok = ensure_quic_started!()

    name = :"http3_e2e_#{System.unique_integer([:positive])}"

    {:ok, _pid} =
      :quic_h3.start_server(name, 0, %{
        cert: cert_der(),
        key: private_key(),
        handler: handler
      })

    {:ok, port} = :quic.get_server_port(name)

    on_exit(fn -> :quic_h3.stop_server(name) end)

    "https://localhost:#{port}/hello?transport=h3"
  end

  defp ensure_quic_started! do
    case Application.ensure_all_started(:quic) do
      {:ok, _apps} -> :ok
      {:error, reason} -> raise "failed to start quic: #{inspect(reason)}"
    end
  end

  defp cert_der do
    @certfile
    |> pem_entries()
    |> Enum.find_value(fn
      {:Certificate, der, _} -> der
      _entry -> nil
    end)
  end

  defp private_key do
    @keyfile
    |> pem_entries()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp pem_entries(path) do
    path
    |> File.read!()
    |> :public_key.pem_decode()
  end

  defp receive_h3_body(conn, stream_id, test_pid, chunks) do
    receive do
      {:quic_h3, ^conn, {:data, ^stream_id, data, true}} ->
        IO.iodata_to_binary(Enum.reverse([data | chunks]))

      {:quic_h3, ^conn, {:data, ^stream_id, data, false}} ->
        receive_h3_body(conn, stream_id, test_pid, [data | chunks])
    after
      5_000 ->
        send(test_pid, {:h3_post_body_timeout, Enum.reverse(chunks)})
        ""
    end
  end
end
