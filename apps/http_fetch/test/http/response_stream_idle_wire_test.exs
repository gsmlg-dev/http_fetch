defmodule HTTP.ResponseStreamIdleWireTest do
  use ExUnit.Case, async: false

  alias HTTP.{Promise, RequestCompletion, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @wait 4_000
  @global 500
  @gap 900

  setup do
    previous = Application.fetch_env(:http_fetch, :streaming_timeout)
    Application.put_env(:http_fetch, :streaming_timeout, @global)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:http_fetch, :streaming_timeout, value)
        :error -> Application.delete_env(:http_fetch, :streaming_timeout)
      end
    end)

    :ok
  end

  for backend <- [:tcp, :ssl, :ex_ssl] do
    test "#{backend} infinite response idle permits an acknowledged network gap beyond the global limit" do
      backend = unquote(backend)
      {peer, promise, response} = response(backend, <<0, 255>>, 4)
      stream = Response.stream_pid(response)
      assert_chunk(stream, <<0, 255>>)
      tick(@gap)
      send_bytes(peer, <<128, 1>>)
      assert_chunk(stream, <<128, 1>>)
      assert_receive {:stream_end, ^stream}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} socket read idle remains the typed authority when response idle is infinite" do
      backend = unquote(backend)

      {peer, promise, response} =
        response(backend, "x", 2, read_idle_timeout: 1_000)

      stream = Response.stream_pid(response)
      assert_chunk(stream, "x")
      assert_receive {:stream_error, ^stream, :read_idle_timeout}, @wait
      refute_receive {:stream_end, ^stream}, 0
      finish(peer, promise, backend)
    end

    test "#{backend} infinite response idle still obeys the overall request deadline" do
      backend = unquote(backend)
      {peer, promise, response} = response(backend, "x", 2, timeout: 1_000)
      stream = Response.stream_pid(response)
      monitor = Process.monitor(stream)
      assert_chunk(stream, "x")
      assert_receive {:stream_error, ^stream, :request_timeout}, @wait
      assert_receive {:DOWN, ^monitor, :process, ^stream, _reason}, @wait
      refute_receive {:stream_end, ^stream}, 0
      finish(peer, promise, backend)
    end

    for policy <- [:omitted, nil] do
      test "#{backend} #{inspect(policy)} response idle preserves the global stream expiry" do
        backend = unquote(backend)

        {peer, promise, response} =
          response(backend, "x", 2, [read_idle_timeout: nil], unquote(policy))

        stream = Response.stream_pid(response)
        monitor = Process.monitor(stream)
        assert_chunk(stream, "x")
        assert_receive {:stream_error, ^stream, :timeout}, @wait
        assert_receive {:DOWN, ^monitor, :process, ^stream, _reason}, @wait
        refute_receive {:stream_end, ^stream}, 0
        finish(peer, promise, backend)
      end
    end

    test "#{backend} finite response idle expires with timeout without an overall or socket read deadline" do
      backend = unquote(backend)

      {peer, promise, response} =
        response(backend, "x", 2,
          read_idle_timeout: nil,
          response_stream_idle_timeout: 300
        )

      stream = Response.stream_pid(response)
      assert_chunk(stream, "x")
      assert_receive {:stream_error, ^stream, :timeout}, @wait
      refute_receive {:stream_end, ^stream}, 0
      finish(peer, promise, backend)
    end

    test "#{backend} concurrent finite response idle policies remain independent" do
      backend = unquote(backend)

      {short_peer, short_promise, short_response} =
        response(backend, "a", 2,
          read_idle_timeout: nil,
          response_stream_idle_timeout: 300
        )

      {long_peer, long_promise, long_response} =
        response(backend, "b", 2,
          read_idle_timeout: nil,
          response_stream_idle_timeout: 2_500
        )

      short_stream = Response.stream_pid(short_response)
      long_stream = Response.stream_pid(long_response)
      assert_chunk(short_stream, "a")
      assert_chunk(long_stream, "b")
      assert_receive {:stream_error, ^short_stream, :timeout}, @wait
      finish(short_peer, short_promise, backend)
      tick(@gap)
      send_bytes(long_peer, "c")
      assert_chunk(long_stream, "c")
      assert_receive {:stream_end, ^long_stream}, @wait
      finish(long_peer, long_promise, backend)
    end

    test "#{backend} an infinite response idle policy retains the bounded consumer acknowledgement limit" do
      backend = unquote(backend)
      {peer, promise, response} = response(backend, "x", 2)
      stream = Response.stream_pid(response)
      send(stream, {:read_chunk, self(), :ack})
      assert_receive {:stream_chunk, ^stream, "x", _unacknowledged}, @wait
      assert_receive {:stream_error, ^stream, :timeout}, @wait
      refute_receive {:stream_end, ^stream}, 0
      finish(peer, promise, backend)
    end

    test "#{backend} finite response idle does not shorten the independent acknowledgement budget" do
      backend = unquote(backend)

      {peer, promise, response} =
        response(backend, "x", 2, response_stream_idle_timeout: 150)

      stream = Response.stream_pid(response)
      send(stream, {:read_chunk, self(), :ack})
      assert_receive {:stream_chunk, ^stream, "x", ack}, @wait
      refute_receive {:stream_error, ^stream, _}, 300
      send(stream, {:stream_chunk_ack, ack})
      send_bytes(peer, "y")
      assert_chunk(stream, "y")
      assert_receive {:stream_end, ^stream}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} cancellation still closes an infinite response stream and its peer" do
      backend = unquote(backend)
      controller = HTTP.AbortController.new()
      {peer, promise, response} = response(backend, "x", 2, signal: controller)
      stream = Response.stream_pid(response)
      assert_chunk(stream, "x")
      HTTP.AbortController.abort(controller)
      assert_receive {:stream_error, ^stream, :aborted}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} a departing reader closes an infinite response stream and its peer" do
      backend = unquote(backend)
      {peer, promise, response} = response(backend, "x", 2)
      stream = Response.stream_pid(response)
      stream_monitor = Process.monitor(stream)
      test = self()

      reader =
        Task.async(fn ->
          assert_chunk(stream, "x")
          send(test, {:reader_attached, self()})
          assert_receive :leave, @wait
          :ok
        end)

      reader_pid = reader.pid
      assert_receive {:reader_attached, ^reader_pid}, @wait
      send(reader_pid, :leave)
      assert :ok = Task.await(reader, @wait)
      assert_receive {:DOWN, ^stream_monitor, :process, ^stream, _reason}, @wait
      finish(peer, promise, backend)
    end

    for consumer <- [:read_all, :write_to] do
      test "#{backend} #{consumer} has no hidden global response wait cap" do
        convenience(unquote(backend), unquote(consumer))
      end
    end
  end

  for consumer <- [:text, :json, :clone] do
    test "TCP #{consumer} respects the infinite response stream policy" do
      convenience(:tcp, unquote(consumer))
    end
  end

  defp convenience(backend, consumer) do
    {first, last, expected} =
      if consumer == :json,
        do: {"{\"ok\":", "true}", {:ok, %{"ok" => true}}},
        else: {"first", "last", "firstlast"}

    {peer, promise, response} = response(backend, first, byte_size(first <> last))
    stream = Response.stream_pid(response)

    path =
      Path.join(
        System.tmp_dir!(),
        "http-fetch-response-idle-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm(path) end)

    reader =
      Task.async(fn ->
        assert_receive :consume, @wait

        case consumer do
          :read_all -> Response.read_all(response)
          :text -> Response.text(response)
          :json -> Response.json(response)
          :clone -> response |> Response.clone() |> Response.read_all()
          :write_to -> Response.write_to(response, path)
        end
      end)

    reader_pid = reader.pid
    :erlang.trace(reader_pid, true, [:send, {:tracer, self()}])
    send(reader_pid, :consume)

    # Observe the real consumer acknowledging the first network bytes before
    # delaying the next ones. This excludes slow consumer acknowledgement.
    assert_receive {:trace, ^reader_pid, :send, {:stream_chunk_ack, _ref}, ^stream}, @wait
    :erlang.trace(reader_pid, false, [:send])
    tick(@gap)
    send_bytes(peer, last)

    case consumer do
      :write_to ->
        assert :ok = Task.await(reader, @wait)
        assert File.read!(path) == expected

      _ ->
        assert Task.await(reader, @wait) == expected
    end

    finish(peer, promise, backend)
  end

  defp response(backend, first, length, options \\ [], response_idle \\ :infinity) do
    {peer, url} = peer(backend)

    options =
      Keyword.merge(
        [
          http_version: :http1,
          redirect: :manual,
          stream_response: true,
          decode_body: false,
          timeout: :infinity,
          connect_timeout: 3_000,
          read_idle_timeout: 2_500,
          response_stream_idle_timeout: response_idle,
          tls_backend: if(backend == :ex_ssl, do: :ex_ssl, else: :ssl),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          telemetry: false
        ],
        options
      )

    options =
      if response_idle == :omitted,
        do: Keyword.delete(options, :response_stream_idle_timeout),
        else: options

    promise =
      HTTP.fetch(
        url,
        options
      )

    peer_pid = peer.pid
    assert_receive {:request_received, ^peer_pid}, @wait

    send_bytes(
      peer,
      "HTTP/1.1 200 OK\r\nContent-Length: #{length}\r\nConnection: close\r\n\r\n" <> first
    )

    assert %Response{status: 200} = response = Promise.await(promise, @wait)
    assert is_pid(Response.stream_pid(response))
    {peer, promise, response}
  end

  defp assert_chunk(stream, expected) do
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, ^expected, ack}, @wait
    send(stream, {:stream_chunk_ack, ack})
  end

  defp peer(backend) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    test = self()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, @wait)
        {transport, socket} = handshake(backend, tcp)
        assert recv_headers(transport, socket, "") =~ "GET /response-idle HTTP/1.1\r\n"
        send(test, {:request_received, self()})
        serve(transport, socket, test)
      end)

    on_exit(fn ->
      if Process.alive?(task.pid), do: Process.exit(task.pid, :kill)
      :gen_tcp.close(listener)
    end)

    scheme = if backend == :tcp, do: "http", else: "https"
    {task, "#{scheme}://localhost:#{port}/response-idle"}
  end

  defp handshake(:tcp, socket), do: {:gen_tcp, socket}

  defp handshake(_backend, socket) do
    {:ok, tls} =
      :ssl.handshake(
        socket,
        [
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          versions: [:"tlsv1.3"],
          active: false
        ],
        @wait
      )

    {:ssl, tls}
  end

  defp recv_headers(transport, socket, bytes) do
    if String.ends_with?(bytes, "\r\n\r\n") do
      bytes
    else
      assert {:ok, more} = transport.recv(socket, 1, @wait)
      recv_headers(transport, socket, bytes <> more)
    end
  end

  defp serve(transport, socket, test) do
    receive do
      {:send, ref, bytes} ->
        :ok = transport.send(socket, bytes)
        send(test, {:sent, ref})
        serve(transport, socket, test)

      :await_close ->
        assert {:error, reason} = transport.recv(socket, 0, @wait)
        assert reason in [:closed, :econnreset]
        transport.close(socket)
        send(test, {:peer_closed, self()})
        :ok
    after
      @wait -> flunk("response-idle peer was not released")
    end
  end

  defp send_bytes(%Task{pid: peer}, bytes) do
    ref = make_ref()
    send(peer, {:send, ref, bytes})
    assert_receive {:sent, ^ref}, @wait
  end

  defp tick(milliseconds) do
    ref = make_ref()
    Process.send_after(self(), {:stimulus, ref}, milliseconds)
    assert_receive {:stimulus, ^ref}, @wait
  end

  defp finish(%Task{pid: peer} = task, promise, backend) do
    send(peer, :await_close)
    assert_receive {:peer_closed, ^peer}, @wait
    assert :ok = Task.await(task, @wait)

    expected =
      if backend == :ex_ssl, do: {:error, {:unsupported_completion, :tls_backend}}, else: :ok

    assert RequestCompletion.await(Promise.completion(promise), @wait) == expected
  end
end
