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

  defp fetch!(url, options) do
    url
    |> HTTP.fetch(
      Keyword.merge(
        [
          method: "POST",
          headers: %{"content-type" => "application/json"},
          body: ~s({"stream":true}),
          http_version: :http1,
          tls_backend: :ex_ssl,
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

  defp serve_once(listener) do
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
          :ssl.send(
            tls,
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n" <>
              "transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
          )

        Enum.each(@chunks, fn chunk ->
          :ok = :ssl.send(tls, [Integer.to_string(byte_size(chunk), 16), "\r\n", chunk, "\r\n"])
        end)

        :ok = :ssl.send(tls, "0\r\n\r\n")
        # Close the carrier underneath :ssl: no close_notify is ever sent.
        :ok = :gen_tcp.close(tcp)
        send(test, {:peer_closed, self()})
      end)

    task
  end

  defp await_peer(task), do: Task.await(task, @wait)

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
