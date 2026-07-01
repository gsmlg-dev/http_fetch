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
