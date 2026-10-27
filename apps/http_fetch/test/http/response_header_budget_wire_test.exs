defmodule HTTP.ResponseHeaderBudgetWireTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "flat options preserve per-caller policies, raw streaming and same-read body bytes" do
    head = response_head(200, 18, "Content-Length: 3\r\n")

    {url, peer} =
      peer(fn socket ->
        recv_head(socket)
        :gen_tcp.send(socket, [head, <<0, 255, 42>>])
      end)

    promise =
      HTTP.fetch(url,
        response_header_limits: [max_head_bytes: 262_144],
        stream_response: true,
        decode_body: false,
        redirect: :manual,
        telemetry: false
      )

    assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, 2_000)
    assert HTTP.Response.read_all(response) == <<0, 255, 42>>
    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
    assert_receive {:peer_done, ^peer, _}, 2_000

    {url, _} =
      peer(fn socket ->
        recv_head(socket)
        :gen_tcp.send(socket, head)
      end)

    assert {:error, :headers_too_large} =
             HTTP.fetch(url, telemetry: false) |> HTTP.Promise.await(2_000)
  end

  test "redirect requests retain the same explicit response policy" do
    {last_url, _} =
      peer(fn socket ->
        recv_head(socket)
        :gen_tcp.send(socket, response_head(200, 18, "Content-Length: 0\r\n"))
      end)

    {url, _} =
      peer(fn socket ->
        recv_head(socket)

        :gen_tcp.send(
          socket,
          response_head(302, 18, "Content-Length: 0\r\nLocation: #{last_url}\r\n")
        )
      end)

    assert %HTTP.Response{status: 200} =
             HTTP.fetch(url, response_header_limits: [max_head_bytes: 262_144], telemetry: false)
             |> HTTP.Promise.await(3_000)
  end

  for backend <- [:ssl, :ex_ssl] do
    test "CONNECT larger than 16 KiB reaches independently verified #{backend} origin TLS" do
      {url, peer_pid} =
        peer(fn socket ->
          request = recv_head(socket)
          send(self_parent(), {:connect_request, request})
          :ok = :gen_tcp.send(socket, response_head(200, 6, ""))
          {:ok, tls} = :ssl.handshake(socket, tls_server_options(), 3_000)
          {:ok, request} = :ssl.recv(tls, 0, 3_000)
          :ok = :ssl.send(tls, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
          :ssl.close(tls)
          request
        end)

      proxy_port = URI.parse(url).port

      result =
        HTTP.fetch("https://localhost:443/budget",
          proxy: {:http, "127.0.0.1", proxy_port, []},
          tls_backend: unquote(backend),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          response_header_limits: [max_connect_head_bytes: 65_536],
          redirect: :manual,
          telemetry: false,
          timeout: 3_000
        )
        |> HTTP.Promise.await(4_000)

      assert %HTTP.Response{status: 200, body: "ok"} = result
      assert_receive {:connect_request, head}, 2_000
      assert head =~ "CONNECT localhost:443 HTTP/1.1"
      assert_receive {:peer_done, ^peer_pid, request}, 2_000
      assert request =~ "GET /budget HTTP/1.1"
    end
  end

  test "CONNECT exhaustion identifies stage and finite cleanup closes the proxy socket" do
    {url, peer_pid} =
      peer(fn socket ->
        recv_head(socket)
        :gen_tcp.send(socket, response_head(200, 6, ""))
        :gen_tcp.recv(socket, 0, 2_000)
      end)

    promise =
      HTTP.fetch("https://localhost/budget",
        proxy: {:http, "127.0.0.1", URI.parse(url).port, []},
        response_header_limits: [max_connect_head_bytes: 20_000],
        tls_backend: :ssl,
        redirect: :manual,
        telemetry: false,
        timeout: 3_000
      )

    assert {:error, {:response_header_limit, %{stage: :connect, limit: :max_connect_head_bytes}}} =
             HTTP.Promise.await(promise, 4_000)

    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
    assert_receive {:peer_done, ^peer_pid, {:error, :closed}}, 2_000
  end

  test "fragmented partial response heads remain cancellable with a larger budget" do
    parent = self()

    {url, peer_pid} =
      peer(fn socket ->
        recv_head(socket)
        :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nX-Pad: " <> String.duplicate("p", 12_000))
        send(parent, :partial_head)
        :gen_tcp.recv(socket, 0, 2_000)
      end)

    promise =
      HTTP.fetch(url,
        response_header_limits: [max_head_bytes: 262_144],
        redirect: :manual,
        telemetry: false,
        timeout: 3_000
      )

    assert_receive :partial_head, 2_000
    assert :ok = HTTP.RequestCompletion.abort_and_await(HTTP.Promise.completion(promise), 2_000)
    assert {:error, :aborted} = HTTP.Promise.await(promise, 1_000)
    assert_receive {:peer_done, ^peer_pid, {:error, :closed}}, 2_000
  end

  test "fragmented partial response head still expires at the request deadline" do
    {url, peer_pid} =
      peer(fn socket ->
        recv_head(socket)
        :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nX-Pad: ")
        :gen_tcp.recv(socket, 0, 2_000)
      end)

    promise =
      HTTP.fetch(url,
        response_header_limits: [max_head_bytes: 262_144],
        redirect: :manual,
        telemetry: false,
        timeout: 200
      )

    assert {:error, :request_timeout} = HTTP.Promise.await(promise, 2_000)
    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
    assert_receive {:peer_done, ^peer_pid, {:error, :closed}}, 2_000
  end

  test "CONNECT informational chains are charged to the request policy" do
    {url, peer_pid} =
      peer(fn socket ->
        recv_head(socket)
        :gen_tcp.send(socket, String.duplicate("HTTP/1.1 103 Early Hints\r\n\r\n", 2))
        :gen_tcp.recv(socket, 0, 2_000)
      end)

    promise =
      HTTP.fetch("https://localhost/budget",
        proxy: {:http, "127.0.0.1", URI.parse(url).port, []},
        response_header_limits: [max_informational_responses: 1],
        tls_backend: :ssl,
        redirect: :manual,
        telemetry: false,
        timeout: 3_000
      )

    assert {:error,
            {:response_header_limit, %{stage: :connect, limit: :max_informational_responses}}} =
             HTTP.Promise.await(promise, 4_000)

    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000)
    assert_receive {:peer_done, ^peer_pid, {:error, :closed}}, 2_000
  end

  defp response_head(status, count, extra) do
    padding =
      Enum.map_join(1..count, "", fn n ->
        "X-Pad-#{n}: " <> String.duplicate("p", 4096) <> "\r\n"
      end)

    "HTTP/1.1 #{status} OK\r\n" <> extra <> padding <> "\r\n"
  end

  defp peer(fun) do
    parent = self()

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)

    pid =
      spawn_link(fn ->
        Process.put(:test_parent, parent)
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)

        result =
          try do
            fun.(socket)
          after
            :gen_tcp.close(socket)
          end

        send(parent, {:peer_done, self(), result})
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(pid), do: Process.exit(pid, :kill)
    end)

    {"http://127.0.0.1:#{port}/", pid}
  end

  defp self_parent, do: Process.get(:test_parent)

  defp recv_head(socket, bytes \\ "") do
    if String.contains?(bytes, "\r\n\r\n") do
      bytes
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 3_000)
      recv_head(socket, bytes <> data)
    end
  end

  defp tls_server_options do
    [
      certfile: String.to_charlist(Path.join(@fixtures, "localhost.pem")),
      keyfile: String.to_charlist(Path.join(@fixtures, "localhost.key")),
      active: false,
      mode: :binary
    ]
  end
end
