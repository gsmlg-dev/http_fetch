defmodule HTTP.RetryWireTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  # Serves one scripted reply per accepted connection and reports each request head.
  defp serve(replies) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listener)
    parent = self()

    server =
      spawn_link(fn ->
        Enum.each(replies, fn reply ->
          {:ok, socket} = :gen_tcp.accept(listener, 5_000)
          head = read_head(socket, "")
          send(parent, {:request_head, head})
          reply(socket, reply)
        end)

        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn ->
      send(server, :stop)
      :gen_tcp.close(listener)
    end)

    port
  end

  defp read_head(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      case :gen_tcp.recv(socket, 0, 5_000) do
        {:ok, data} -> read_head(socket, acc <> data)
        {:error, _} -> acc
      end
    end
  end

  defp reply(socket, :close), do: :gen_tcp.close(socket)

  # A streamed 503: no Content-Length, delimited by close, body held open.
  defp reply(socket, :streamed_503) do
    :ok =
      :gen_tcp.send(
        socket,
        "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nConnection: close\r\n\r\npartial"
      )

    # The client cancels the unread stream and closes this connection.
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 5_000)
  end

  defp reply(socket, {:ok, body}) do
    :ok =
      :gen_tcp.send(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(body)}\r\nConnection: close\r\n\r\n" <>
          body
      )

    :gen_tcp.close(socket)
  end

  defp heads do
    receive do
      {:request_head, head} -> [head | heads()]
    after
      200 -> []
    end
  end

  test "a streamed 503 is cancelled and the request completes on a new connection" do
    port = serve([:streamed_503, {:ok, "fresh"}])

    promise =
      HTTP.fetch("http://127.0.0.1:#{port}/item",
        retry: :transient,
        redirect: :manual,
        timeout: 5_000
      )

    assert %HTTP.Response{status: 200, body: "fresh"} = HTTP.Promise.await(promise, 6_000)

    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 2_000) ==
             {:error, {:unsupported_completion, :retry}}

    assert [first, second] = heads()
    assert first =~ "GET /item HTTP/1.1" and second =~ "GET /item HTTP/1.1"
  end

  test "a connection closed before any response is retried only for idempotent methods" do
    for redirect <- [:follow, :manual] do
      port = serve([:close, {:ok, "after-close"}])

      assert %HTTP.Response{status: 200, body: "after-close"} =
               HTTP.fetch("http://127.0.0.1:#{port}/put",
                 method: :put,
                 body: "same",
                 redirect: redirect,
                 retry: :safe_transient,
                 retry_delay: 10
               )
               |> HTTP.Promise.await(6_000)

      assert [first, second] = heads()
      assert first =~ "\r\n\r\n" and String.starts_with?(second, "PUT /put HTTP/1.1")
    end

    port = serve([:close, {:ok, "unused"}])

    assert {:error, :closed} =
             HTTP.fetch("http://127.0.0.1:#{port}/post",
               method: :post,
               body: "once",
               retry: :safe_transient,
               retry_delay: 10
             )
             |> HTTP.Promise.await(6_000)

    assert length(heads()) == 1
  end

  test "a refused connection is retried until max_retries" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false])
    {:ok, port} = :inet.port(listener)
    :ok = :gen_tcp.close(listener)

    events = [[:http_fetch, :request, :retry], [:http_fetch, :request, :exception]]
    ref = make_ref()
    parent = self()
    id = {__MODULE__, ref}

    :telemetry.attach_many(
      id,
      events,
      # Handlers run in the emitting Promise worker; forward only this test's fetch.
      fn event, measurements, metadata, _ ->
        if parent in Process.get(:"$callers", []),
          do: send(parent, {ref, event, measurements, metadata})
      end,
      nil
    )

    try do
      assert {:error, :econnrefused} =
               HTTP.fetch("http://127.0.0.1:#{port}/",
                 retry: :transient,
                 max_retries: 2,
                 retry_delay: 5
               )
               |> HTTP.Promise.await(6_000)

      assert_received {^ref, [:http_fetch, :request, :retry], %{attempt: 1},
                       %{reason: :econnrefused}}

      assert_received {^ref, [:http_fetch, :request, :retry], %{attempt: 2},
                       %{reason: :econnrefused}}

      assert_received {^ref, [:http_fetch, :request, :exception], _, %{error: :econnrefused}}
      refute_received {^ref, _, _, _}
    after
      :telemetry.detach(id)
    end
  end
end
