defmodule HTTP.ProxyRequestCompletionTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion}

  test "HTTP forwarding confirms socket closure and repeated concurrent waits" do
    {peer, route} =
      proxy(fn socket, parent ->
        head = read_head(socket)
        send(parent, {:forward_head, head})
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        send(parent, {:forward_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    promise = fetch("http://origin.invalid/resource", route)
    assert %HTTP.Response{body: "ok"} = Promise.await(promise)
    handle = Promise.completion(promise)
    assert :ok = RequestCompletion.await(handle, 1_000)
    assert_receive {:forward_head, head}
    assert head =~ "GET http://origin.invalid/resource HTTP/1.1\r\n"
    assert_receive {:forward_closed, {:error, :closed}}
    waits = for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(handle, 0) end)
    assert Enum.all?(waits, &(Task.await(&1) == :ok))
    assert :ok = RequestCompletion.abort_and_await(handle, 0)
    assert :ok = Task.await(peer)
  end

  for stage <- [:connect, :origin_tls, :proxy_tls] do
    test "#{stage} cancellation tracks the pending socket and waits for the dial helper" do
      assert_pending_stage(unquote(stage))
    end

    test "#{stage} deadline closes the pending proxy route and confirms cleanup" do
      assert_pending_deadline(unquote(stage))
    end
  end

  test "proxy response stream termination stays pending behind its real owner" do
    {peer, route} =
      proxy(fn socket, parent ->
        read_head(socket)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        send(parent, {:stream_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    controller = HTTP.AbortController.new()
    promise = fetch("http://origin.invalid/", route, signal: controller, stream_response: true)
    response = Promise.await(promise)
    handle = Promise.completion(promise)
    owner = Agent.get(controller, & &1.request_id)
    stream = response.stream
    monitor = Process.monitor(stream)
    send(stream, {:read_chunk, self(), :ack})
    :erlang.suspend_process(owner)

    try do
      assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 20)
      assert_receive {:stream_error, ^stream, :aborted}
      assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}
      assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    after
      :erlang.resume_process(owner)
    end

    assert :ok = RequestCompletion.await(handle, 1_000)
    assert_receive {:stream_closed, {:error, :closed}}
    assert :ok = Task.await(peer)
  end

  test "a proxy upload waits for the library source and blocked producer to stop" do
    parent = self()

    enumerable =
      Stream.resource(
        fn ->
          send(parent, {:producer, self()})
          :ready
        end,
        fn _ -> receive do: (:never -> {["body"], :ready}) end,
        fn _ -> :ok end
      )

    {:ok, source} = HTTP.Stream.from_enumerable(enumerable)
    assert_receive {:producer, producer}
    monitor = Process.monitor(producer)

    {peer, route} =
      proxy(fn socket, parent ->
        assert read_head(socket) =~ "POST http://origin.invalid/upload HTTP/1.1\r\n"
        send(parent, :upload_started)
        send(parent, {:upload_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    promise =
      fetch("http://origin.invalid/upload", route, method: :post, body: source, duplex: :half)

    assert_receive :upload_started
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(promise), 1_000)
    assert_receive {:DOWN, ^monitor, :process, ^producer, :killed}
    refute Process.alive?(source)
    assert_receive {:upload_closed, {:error, :closed}}
    assert {:error, _} = Promise.await(promise)
    assert :ok = Task.await(peer)
  end

  test "unsupported proxy families keep an explicit completion fallback" do
    for {url, options} <- [
          {"https://localhost/", [proxy: {:https, "localhost", 3128, []}]},
          {"http://localhost/", [proxy: {:http, "localhost", 3128, []}, http_version: :h2c]},
          {"http://localhost/", [proxy: {:https, "localhost", 3128, []}, http_version: :http2]}
        ] do
      promise = fetch(url, options[:proxy], Keyword.delete(options, :proxy))

      assert {:error, {:unsupported_completion, :proxy}} =
               RequestCompletion.await(Promise.completion(promise), 0)

      assert {:error, _} = Promise.await(promise)
    end
  end

  defp assert_pending_stage(stage) do
    {peer, route, url} = pending_proxy(stage)
    promise = fetch(url, route, ssl: [verify: :verify_none], timeout: 5_000)
    handle = Promise.completion(promise)
    assert_receive :pending_stage, 2_000
    assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    dial = dial_worker(handle)
    monitor = Process.monitor(dial)
    :erlang.suspend_process(dial)

    try do
      assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 20)
      assert_receive {:pending_closed, {:error, :closed}}, 1_000
      assert Process.alive?(dial)
      waits = for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(handle, 20) end)
      assert Enum.all?(waits, &(Task.await(&1) == {:error, :cleanup_pending}))
    after
      :erlang.resume_process(dial)
    end

    assert :ok = RequestCompletion.await(handle, 1_000)
    assert_receive {:DOWN, ^monitor, :process, ^dial, :normal}
    assert {:error, _} = Promise.await(promise)
    assert :ok = Task.await(peer)
  end

  defp assert_pending_deadline(stage) do
    {peer, route, url} = pending_proxy(stage)
    promise = fetch(url, route, ssl: [verify: :verify_none], timeout: 500)
    handle = Promise.completion(promise)
    assert_receive :pending_stage, 1_000
    assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    assert {:error, reason} = Promise.await(promise, 2_000)
    assert reason in [:request_timeout, :connect_timeout, :timeout, :proxy_tunnel_timeout]
    assert :ok = RequestCompletion.await(handle, 1_000)
    assert_receive {:pending_closed, {:error, :closed}}, 1_000
    assert :ok = RequestCompletion.await(handle, 0)
    assert :ok = Task.await(peer)
  end

  defp pending_proxy(stage) do
    {peer, route} =
      proxy(fn socket, parent ->
        if stage != :proxy_tls do
          assert read_head(socket) =~ "CONNECT localhost:443 HTTP/1.1\r\n"

          if stage == :origin_tls,
            do: :gen_tcp.send(socket, "HTTP/1.1 200 Connection Established\r\n\r\n")
        end

        if stage != :connect do
          assert {:ok, <<22, _::binary>>} = :gen_tcp.recv(socket, 0, 2_000)
        end

        send(parent, :pending_stage)
        send(parent, {:pending_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    {scheme, host, port, opts} = route
    route = {if(stage == :proxy_tls, do: :https, else: scheme), host, port, opts}
    url = if stage == :proxy_tls, do: "http://origin.invalid/", else: "https://localhost/"
    {peer, route, url}
  end

  defp fetch(url, route, opts \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          proxy: route,
          request_mode: :proxy,
          http_version: :http1,
          redirect: :manual,
          decode_body: false,
          tls_backend: :ssl,
          timeout: 3_000
        ],
        opts
      )
    )
  end

  defp dial_worker(handle) do
    :sys.get_state(handle.tracker).resources
    |> Map.values()
    |> Enum.find_value(fn {pid, kind} -> if kind == :dial, do: pid end)
  end

  defp proxy(fun) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    parent = self()

    task =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)

        try do
          fun.(socket, parent)
          :ok
        after
          :gen_tcp.close(socket)
        end
      end)

    {task, {:http, "127.0.0.1", port, []}}
  end

  defp read_head(socket, bytes \\ "") do
    if :binary.match(bytes, "\r\n\r\n") == :nomatch do
      {:ok, chunk} = :gen_tcp.recv(socket, 0, 2_000)
      read_head(socket, bytes <> chunk)
    else
      bytes
    end
  end
end
