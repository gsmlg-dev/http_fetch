defmodule HTTP.HeaderFirstTest do
  use ExUnit.Case, async: true

  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer
  alias HTTP.HTTP2.HPACK

  test "stream_response supports flat forms and rejects invalid values" do
    options = HTTP.FetchOptions.new(%{"streamResponse" => true})
    assert Keyword.get(HTTP.FetchOptions.to_transport_options(options), :stream_response)
    assert_raise ArgumentError, fn -> HTTP.FetchOptions.new(stream_response: :yes) end
  end

  for protocol <- [:http1, :h2c], status <- [200, 404] do
    test "#{protocol} resolves #{status} at headers while body remains gated" do
      {url, peer} = gated_peer(unquote(protocol), unquote(status), "ok")

      promise =
        HTTP.fetch(url,
          http_version: unquote(protocol),
          stream_response: true,
          decode_body: false,
          redirect: :manual,
          timeout: 3_000
        )

      assert_receive {:headers_sent, ^peer}, 2_000
      response = HTTP.Promise.await(promise, 1_000)
      assert %HTTP.Response{status: unquote(status)} = response
      assert is_pid(response.body)
      send(peer, :release_body)
      assert HTTP.Response.read_all(response) == "ok"
    end
  end

  test "concurrent default caller still waits for the small body" do
    {url, peer} = gated_peer(:http1, 200, "ok")
    promise = HTTP.fetch(url, timeout: 3_000)
    assert_receive {:headers_sent, ^peer}, 2_000
    refute_receive {_ref, %HTTP.Response{}}, 50
    send(peer, :release_body)
    assert %HTTP.Response{body: "ok"} = HTTP.Promise.await(promise)
  end

  for {method, status} <- [{:head, 200}, {:get, 204}, {:get, 304}] do
    test "stream policy preserves bodyless #{method}/#{status}" do
      {url, peer} = gated_peer(:http1, unquote(status), "", "2")
      promise = HTTP.fetch(url, method: unquote(method), stream_response: true, redirect: :manual)
      assert_receive {:headers_sent, ^peer}, 2_000
      assert %HTTP.Response{body: ""} = HTTP.Promise.await(promise, 1_000)
      send(peer, :release_body)
    end
  end

  test "abort after headers reports stream error and closes connection" do
    controller = HTTP.AbortController.new()
    {url, peer} = gated_peer(:http1, 200, "ok")
    promise = HTTP.fetch(url, stream_response: true, signal: controller, timeout: 3_000)
    assert_receive {:headers_sent, ^peer}, 2_000
    response = HTTP.Promise.await(promise, 1_000)
    assert is_pid(response.body)
    send(response.body, {:read_chunk, self(), :ack})
    HTTP.AbortController.abort(controller)
    stream = response.body
    assert_receive {:stream_error, ^stream, :aborted}, 2_000
    send(peer, :check_closed)
    assert_receive {:peer_closed, ^peer}, 2_000
  end

  test "acknowledgement gates stream completion" do
    {url, peer} = gated_peer(:http1, 200, "ok")
    promise = HTTP.fetch(url, stream_response: true, timeout: 3_000)
    assert_receive {:headers_sent, ^peer}, 2_000
    response = HTTP.Promise.await(promise, 1_000)
    stream = response.body
    send(stream, {:read_chunk, self(), :ack})
    send(peer, :release_body)
    assert_receive {:stream_chunk, ^stream, "ok", ack}, 2_000
    refute_receive {:stream_end, ^stream}, 50
    send(stream, {:stream_chunk_ack, ack})
    assert_receive {:stream_end, ^stream}, 2_000
  end

  test "request deadline still bounds the body after headers" do
    {url, peer} = gated_peer(:http1, 200, "ok")
    promise = HTTP.fetch(url, stream_response: true, timeout: 500)
    assert_receive {:headers_sent, ^peer}, 2_000
    response = HTTP.Promise.await(promise, 1_000)
    stream = response.body
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_error, ^stream, :request_timeout}, 2_000
    send(peer, :check_closed)
    assert_receive {:peer_closed, ^peer}, 2_000
  end

  defp gated_peer(protocol, status, body, length \\ nil)

  defp gated_peer(:http1, status, body, length) do
    parent = self()

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        :gen_tcp.close(listener)
        receive_head(socket, "")

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 #{status} Response\r\nContent-Length: #{length || byte_size(body)}\r\n\r\n"
          )

        send(parent, {:headers_sent, self()})

        receive do
          :release_body ->
            :gen_tcp.send(socket, body)

          :check_closed ->
            {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
            send(parent, {:peer_closed, self()})
        after
          4_000 -> :ok
        end

        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      Process.unlink(peer)
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {"http://127.0.0.1:#{port}/", peer}
  end

  defp gated_peer(:h2c, status, body, _length) do
    parent = self()

    Peer.start(parent, fn socket ->
      {id, true} = Peer.request(socket)

      fields =
        HPACK.encode_headers([
          {":status", to_string(status)},
          {"content-length", to_string(byte_size(body))}
        ])
        |> IO.iodata_to_binary()

      :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, fields))
      send(parent, {:headers_sent, self()})

      receive do
        :release_body -> :ok = :gen_tcp.send(socket, Peer.frame(0, 1, id, body))
      after
        4_000 -> :ok
      end
    end)
  end

  defp receive_head(socket, buffer) do
    if String.contains?(buffer, "\r\n\r\n") do
      :ok
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 2_000)
      receive_head(socket, buffer <> data)
    end
  end
end
