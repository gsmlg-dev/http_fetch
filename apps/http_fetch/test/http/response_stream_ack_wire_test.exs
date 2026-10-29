defmodule HTTP.ResponseStreamAckWireTest do
  use ExUnit.Case, async: false
  @moduletag :integration

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

  for backend <- [:tcp, nil, :ex_ssl] do
    for policy <- [:infinity, 2_500] do
      test "#{backend} #{policy} ACK policy permits bounded delayed delivery beyond global timeout" do
        backend = unquote(backend)
        {peer, promise, response} = response(backend, <<0, 255>>, 4, [], unquote(policy))
        stream = Response.stream_pid(response)
        ack = hold_chunk(stream, <<0, 255>>)
        refute_receive {:stream_error, ^stream, _}, @gap
        send(stream, {:stream_chunk_ack, ack})
        send_bytes(peer, <<128, 1>>)
        assert_chunk(stream, <<128, 1>>)
        assert_receive {:stream_end, ^stream}, @wait
        finish(peer, promise, backend)
      end
    end

    for policy <- [:omitted, nil, 150] do
      test "#{backend} #{inspect(policy)} ACK policy expires with typed timeout and closes peer" do
        backend = unquote(backend)
        {peer, promise, response} = response(backend, "x", 2, [], unquote(policy))
        stream = Response.stream_pid(response)
        monitor = Process.monitor(stream)
        _ack = hold_chunk(stream, "x")
        assert_receive {:stream_error, ^stream, :timeout}, @wait
        assert_receive {:DOWN, ^monitor, :process, ^stream, _}, @wait
        refute_receive {:stream_end, ^stream}, 0
        finish(peer, promise, backend)
      end
    end

    test "#{backend} concurrent ACK policies are independent" do
      backend = unquote(backend)
      {short_peer, short_promise, short_response} = response(backend, "a", 2, [], 300)
      {long_peer, long_promise, long_response} = response(backend, "b", 2, [], :infinity)
      short = Response.stream_pid(short_response)
      long = Response.stream_pid(long_response)
      _short_ack = hold_chunk(short, "a")
      long_ack = hold_chunk(long, "b")
      assert_receive {:stream_error, ^short, :timeout}, @wait
      finish(short_peer, short_promise, backend)
      refute_receive {:stream_error, ^long, _}, @gap
      send(long, {:stream_chunk_ack, long_ack})
      send_bytes(long_peer, "c")
      assert_chunk(long, "c")
      assert_receive {:stream_end, ^long}, @wait
      finish(long_peer, long_promise, backend)
    end

    test "#{backend} infinite ACK policy still obeys finite overall deadline" do
      backend = unquote(backend)
      {peer, promise, response} = response(backend, "x", 2, timeout: 1_000)
      stream = Response.stream_pid(response)
      _ack = hold_chunk(stream, "x")
      assert_receive {:stream_error, ^stream, :request_timeout}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} cancellation interrupts infinite ACK wait" do
      backend = unquote(backend)
      controller = HTTP.AbortController.new()
      {peer, promise, response} = response(backend, "x", 2, signal: controller)
      stream = Response.stream_pid(response)
      _ack = hold_chunk(stream, "x")
      HTTP.AbortController.abort(controller)
      assert_receive {:stream_error, ^stream, :aborted}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} reader death interrupts infinite ACK wait" do
      backend = unquote(backend)
      {peer, promise, response} = response(backend, "x", 2)
      stream = Response.stream_pid(response)
      monitor = Process.monitor(stream)
      owner = self()

      reader =
        Task.async(fn ->
          _ack = hold_chunk(stream, "x")
          send(owner, {:held, self()})
          assert_receive :leave, @wait
        end)

      reader_pid = reader.pid
      assert_receive {:held, ^reader_pid}, @wait
      send(reader_pid, :leave)
      assert :leave = Task.await(reader, @wait)
      assert_receive {:DOWN, ^monitor, :process, ^stream, _}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} infinite ACK policy leaves finite network inactivity independent" do
      backend = unquote(backend)
      {peer, promise, response} = response(backend, "x", 2, response_stream_idle_timeout: 150)
      stream = Response.stream_pid(response)
      ack = hold_chunk(stream, "x")
      refute_receive {:stream_error, ^stream, _}, 300
      send(stream, {:stream_chunk_ack, ack})
      assert_receive {:stream_error, ^stream, :timeout}, @wait
      finish(peer, promise, backend)
    end
  end

  @tag timeout: 90_000, real_time: true
  test "unchanged 60000ms global limit permits acknowledged delivery after 61 seconds" do
    Application.put_env(:http_fetch, :streaming_timeout, 60_000)
    payload = :binary.copy(<<0, 255, 128, 1>>, 128)
    {peer, promise, response} = response(:tcp, payload, byte_size(payload))
    stream = Response.stream_pid(response)
    ack = hold_chunk(stream, payload)
    assert HTTP.Config.streaming_timeout() == 60_000
    refute_receive {:stream_error, ^stream, _}, 61_000
    send(stream, {:stream_chunk_ack, ack})
    assert_receive {:stream_end, ^stream}, @wait
    finish(peer, promise, :tcp)
  end

  defp hold_chunk(stream, expected) do
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, ^expected, ack}, @wait
    ack
  end

  defp response(backend, first, length, options \\ [], ack_policy \\ :infinity) do
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
          response_stream_idle_timeout: :infinity,
          response_stream_ack_timeout: ack_policy,
          tls_backend: if(backend == :tcp, do: nil, else: backend),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          telemetry: false
        ],
        options
      )

    options =
      if ack_policy == :omitted,
        do: Keyword.delete(options, :response_stream_ack_timeout),
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
        assert recv_headers(transport, socket, "") =~ "GET /response-ack HTTP/1.1\r\n"
        send(test, {:request_received, self()})
        serve(transport, socket, test)
      end)

    on_exit(fn ->
      if Process.alive?(task.pid), do: Process.exit(task.pid, :kill)
      :gen_tcp.close(listener)
    end)

    scheme = if backend == :tcp, do: "http", else: "https"
    {task, "#{scheme}://localhost:#{port}/response-ack"}
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
      90_000 -> flunk("response-ack peer was not released")
    end
  end

  defp send_bytes(%Task{pid: peer}, bytes) do
    ref = make_ref()
    send(peer, {:send, ref, bytes})
    assert_receive {:sent, ^ref}, @wait
  end

  defp finish(%Task{pid: peer} = task, promise, _backend) do
    send(peer, :await_close)
    assert_receive {:peer_closed, ^peer}, @wait
    assert :ok = Task.await(task, @wait)

    assert RequestCompletion.await(Promise.completion(promise), @wait) == :ok
  end
end
