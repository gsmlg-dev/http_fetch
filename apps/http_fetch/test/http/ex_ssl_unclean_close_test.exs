defmodule HTTP.ExSSLUncleanCloseTest do
  # Regression coverage for #158: a chunked `connection: close` response whose
  # server closes TCP without close_notify right after the terminating chunk
  # must complete normally and keep every byte, as it does over OTP :ssl.
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.{Promise, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @wait 5_000
  @runs 50
  @chunks for index <- 1..8,
              do:
                "data: {\"event\":#{index},\"pad\":\"#{String.duplicate("x", 200 * index)}\"}\n\n"
  @body IO.iodata_to_binary(@chunks)

  setup do
    {listener, port} = listen()
    on_exit(fn -> :gen_tcp.close(listener) end)
    %{listener: listener, url: "https://localhost:#{port}/v1/messages"}
  end

  test "acknowledged streamed reads end with :stream_end and the complete body", ctx do
    for run <- 1..@runs do
      peer = serve_once(ctx.listener)
      response = fetch!(ctx.url, stream_response: true)
      stream = Response.stream_pid(response)
      # Let the peer finish and close before the body is read, so the tail is
      # still buffered inside the TLS connection when the transport closes.
      assert_receive {:peer_closed, pid} when pid == peer.pid, @wait

      assert {:ok, @body} == read_acked(stream, []), "run #{run}"
      await_peer(peer)
    end
  end

  test "read_all of a streamed response returns the complete body", ctx do
    for run <- 1..@runs do
      peer = serve_once(ctx.listener)
      response = fetch!(ctx.url, stream_response: true)
      assert_receive {:peer_closed, pid} when pid == peer.pid, @wait
      assert Response.read_all(response) == @body, "run #{run}"
      await_peer(peer)
    end
  end

  test "stream_response: false returns the complete chunked body", ctx do
    for run <- 1..@runs do
      peer = serve_once(ctx.listener)
      response = fetch!(ctx.url, stream_response: false)
      assert Response.read_all(response) == @body, "run #{run}"
      await_peer(peer)
    end
  end

  test "a Content-Length body completes despite the unclean close", ctx do
    for run <- 1..@runs do
      peer = serve_once(ctx.listener, :content_length)
      response = fetch!(ctx.url, stream_response: true)
      assert_receive {:peer_closed, pid} when pid == peer.pid, @wait
      assert {:ok, @body} == read_acked(Response.stream_pid(response), []), "run #{run}"
      await_peer(peer)
    end
  end

  # Without framing, only close_notify proves the body is complete. An unclean
  # close must not turn a possibly truncated body into a success; the bytes
  # received before it are still delivered first.
  test "a read-to-close body closed without close_notify fails after its bytes", ctx do
    peer = serve_once(ctx.listener, :read_to_close)
    response = fetch!(ctx.url, stream_response: true)
    assert_receive {:peer_closed, pid} when pid == peer.pid, @wait
    size = byte_size(@body)
    assert {:error, :econnreset, ^size} = read_acked(Response.stream_pid(response), [])
    await_peer(peer)

    peer = serve_once(ctx.listener, :read_to_close)
    response = fetch!(ctx.url, stream_response: false)
    assert_receive {:peer_closed, pid} when pid == peer.pid, @wait
    assert_raise HTTP.ResponseError, ~r/econnreset/, fn -> Response.read_all(response) end
    await_peer(peer)
  end

  test "a read-to-close body ended by close_notify completes", ctx do
    peer = serve_once(ctx.listener, :read_to_close, :close_notify)
    response = fetch!(ctx.url, stream_response: true)
    assert_receive {:peer_closed, pid} when pid == peer.pid, @wait
    assert {:ok, @body} == read_acked(Response.stream_pid(response), [])
    await_peer(peer)
  end

  defp fetch!(url, options) do
    url
    |> HTTP.fetch(
      Keyword.merge(
        [
          method: "POST",
          headers: %{"content-type" => "application/json"},
          body: ~s({"stream":true}),
          http_version: :http1,
          error_mode: :structured,
          decode_body: false,
          connect_timeout: @wait,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          telemetry: false
        ],
        options
      )
    )
    |> Promise.await(@wait)
    |> tap(&assert(%Response{status: 200} = &1))
  end

  defp read_acked(stream, acc) do
    send(stream, {:read_chunk, self(), :ack})

    receive do
      {:stream_chunk, ^stream, chunk, ack} ->
        send(stream, {:stream_chunk_ack, ack})
        read_acked(stream, [acc | chunk])

      {:stream_end, ^stream} ->
        {:ok, IO.iodata_to_binary(acc)}

      {:stream_error, ^stream, reason} ->
        {:error, reason, byte_size(IO.iodata_to_binary(acc))}
    after
      @wait -> flunk("stream did not finish")
    end
  end

  defp listen do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    {listener, port}
  end

  defp serve_once(listener, framing \\ :chunked, close \\ :unclean) do
    test = self()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, @wait)

        {:ok, tls} =
          :ssl.handshake(
            tcp,
            [
              certfile: Path.join(@fixtures, "localhost.pem"),
              keyfile: Path.join(@fixtures, "localhost.key"),
              versions: [:"tlsv1.3"],
              active: false,
              mode: :binary
            ],
            @wait
          )

        request = recv_request(tls, "")
        true = String.starts_with?(request, "POST /v1/messages HTTP/1.1\r\n")

        :ok =
          :ssl.send(tls, [
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n" | head(framing)
          ])

        Enum.each(@chunks, &(:ok = :ssl.send(tls, frame(framing, &1))))
        if framing == :chunked, do: :ok = :ssl.send(tls, "0\r\n\r\n")

        if close == :close_notify do
          :ok = :ssl.close(tls)
        else
          # Close the carrier underneath :ssl: no close_notify is ever sent.
          :ok = :gen_tcp.close(tcp)
        end

        send(test, {:peer_closed, self()})
      end)

    task
  end

  defp await_peer(task), do: Task.await(task, @wait)

  defp head(:chunked), do: "transfer-encoding: chunked\r\nconnection: close\r\n\r\n"

  defp head(:content_length),
    do: "content-length: #{byte_size(@body)}\r\nconnection: close\r\n\r\n"

  defp head(:read_to_close), do: "connection: close\r\n\r\n"

  defp frame(:chunked, chunk),
    do: [Integer.to_string(byte_size(chunk), 16), "\r\n", chunk, "\r\n"]

  defp frame(_framing, chunk), do: chunk

  defp recv_request(tls, bytes) do
    case :binary.split(bytes, "\r\n\r\n") do
      [head, body] ->
        length =
          Regex.run(~r/content-length: *(\d+)/i, head, capture: :all_but_first)
          |> List.first()
          |> String.to_integer()

        if byte_size(body) >= length,
          do: bytes,
          else: recv_more(tls, bytes)

      [_partial] ->
        recv_more(tls, bytes)
    end
  end

  defp recv_more(tls, bytes) do
    {:ok, more} = :ssl.recv(tls, 0, @wait)
    recv_request(tls, bytes <> more)
  end
end
