defmodule HTTP.HTTP2ProductionLifecycleTest do
  use ExUnit.Case, async: true

  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  defp fetch(url, opts \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge([http_version: :h2c, http2_profile: :native_v1, timeout: 2_000], opts)
    )
    |> HTTP.Promise.await()
  end

  test "scripted peer reserves its origin port while the pooled socket is alive" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = Peer.response(socket, id, "ok")
      end)

    response = fetch(url)
    assert HTTP.Response.read_all(response) == "ok"
    assert_receive {:peer_complete, ^peer}, 5_000

    assert {:error, :eaddrinuse} =
             :gen_tcp.listen(URI.parse(url).port, [:binary, reuseaddr: true])

    monitor = Process.monitor(peer)
    send(peer, :close)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}, 5_000
  end

  test "RST_STREAM fails an already returned response stream" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))

        receive do
          :reset_after_response -> :ok
        after
          2_000 -> raise "response delivery barrier timed out"
        end

        :ok = :gen_tcp.send(socket, Peer.frame(3, 0, id, <<7::32>>))
      end)

    response = fetch(url)
    assert response.status == 200
    send(peer, :reset_after_response)

    assert_raise RuntimeError, ~r/stream read failed: \{:stream_reset, :refused_stream\}/, fn ->
      HTTP.Response.read_all(response)
    end

    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "transport EOF fails an already returned response stream" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
      end)

    response = fetch(url)
    assert response.status == 200
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
    assert_raise RuntimeError, ~r/stream read failed:/, fn -> HTTP.Response.read_all(response) end
  end

  test "abort fails an already returned response stream" do
    controller = HTTP.AbortController.new()

    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
      end)

    response = fetch(url, signal: controller)
    assert response.status == 200
    assert :ok = HTTP.AbortController.abort(controller)

    assert_raise RuntimeError, "stream read failed: :aborted", fn ->
      HTTP.Response.read_all(response)
    end

    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "deadline fails an already returned response stream" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
      end)

    response = fetch(url)
    assert response.status == 200

    # Deliver the timer event only after the response has actually been returned.
    # Real timer expiry during a backpressured drain is covered by socket_client_http2_test.
    port = URI.parse(url).port

    owner =
      :http_fetch_http2_pool
      |> :sys.get_state()
      |> Map.fetch!(:entries)
      |> Enum.find_value(fn {key, entry} ->
        if key.port == port, do: entry.connections |> Map.keys() |> List.first()
      end)

    %{streams: %{1 => %{pid: coordinator}}} = :sys.get_state(owner)
    send(coordinator, :deadline)

    assert_raise RuntimeError, "stream read failed: :request_timeout", fn ->
      HTTP.Response.read_all(response)
    end

    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "expiry before final headers fails the promise instead of returning a response" do
    test_pid = self()

    {url, peer} =
      Peer.start(test_pid, fn socket ->
        {id, true} = Peer.request(socket)
        send(test_pid, {:awaiting_headers, self(), id})
        receive do: (:close -> :ok)
      end)

    task = Task.async(fn -> fetch(url) end)
    assert_receive {:awaiting_headers, ^peer, 1}, 5_000
    port = URI.parse(url).port

    owner =
      :http_fetch_http2_pool
      |> :sys.get_state()
      |> Map.fetch!(:entries)
      |> Enum.find_value(fn {key, entry} ->
        if key.port == port, do: entry.connections |> Map.keys() |> List.first()
      end)

    %{streams: %{1 => %{pid: coordinator}}} = :sys.get_state(owner)
    send(coordinator, :deadline)
    assert {:error, :request_timeout} = Task.await(task, 5_000)
    send(peer, :close)
    assert_receive {:peer_complete, ^peer}, 5_000
    send(peer, :close)
  end

  test "producer error settles a request waiting for response headers" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {_id, false} = Peer.request(socket)
      end)

    body = Stream.map([:fail], fn _ -> raise "producer failed" end)
    {:ok, stream} = HTTP.Stream.from_enumerable(body)

    assert {:error, {:body_error, %RuntimeError{message: "producer failed"}}} =
             fetch(url, method: :post, body: stream, duplex: "half")

    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "owner death fails an already returned response stream" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
      end)

    response = fetch(url)
    assert response.status == 200
    port = URI.parse(url).port

    owner =
      :http_fetch_http2_pool
      |> :sys.get_state()
      |> Map.fetch!(:entries)
      |> Enum.find_value(fn {key, entry} ->
        if key.port == port, do: entry.connections |> Map.keys() |> List.first()
      end)

    assert is_pid(owner)
    Process.exit(owner, :kill)
    assert_raise RuntimeError, ~r/stream read failed:/, fn -> HTTP.Response.read_all(response) end
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "reset interrupts a DATA delivery held by a paused reader" do
    test_pid = self()

    {url, peer} =
      Peer.start(test_pid, fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))

        receive do
          :send_data -> :ok
        end

        :ok = :gen_tcp.send(socket, Peer.frame(0, 0, id, "waiting"))

        receive do
          :send_reset -> :ok
        end

        :ok = :gen_tcp.send(socket, Peer.frame(3, 0, id, <<7::32>>))
      end)

    response = fetch(url)
    stream = response.stream

    _reader =
      spawn(fn ->
        send(stream, {:read_chunk, self(), :ack})

        receive do
          {:stream_chunk, ^stream, "waiting", _ref} -> send(test_pid, :chunk_seen)
        end

        receive do
          {:stream_error, ^stream, reason} -> send(test_pid, {:reader_error, reason})
        end
      end)

    send(peer, :send_data)
    assert_receive :chunk_seen
    send(peer, :send_reset)
    assert_receive {:reader_error, {:stream_reset, :refused_stream}}, 500
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end
end
