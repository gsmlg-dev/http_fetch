defmodule HTTP.ManagedTransportInputTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  alias HTTP.ManagedTransport.Policy

  test "oversized convenience Content-Type rejects before any accept and settles its source" do
    {origin, listener} = listener()
    scope = open(origin)
    peer = peer(listener)
    {:ok, source} = HTTP.Stream.start_link(0)
    monitor = Process.monitor(source)

    promise =
      fetch(origin, scope,
        method: :post,
        body: source,
        duplex: :half,
        content_type: :binary.copy("a", 65_537)
      )

    assert {:error, :transport_scope_request_limit} = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
    assert_receive {:DOWN, ^monitor, :process, ^source, _}
    assert :no_accept = Task.await(peer, 2_000)
    retire(scope)
  end

  test "unused URI authority is discarded while path, query and Host reach the peer" do
    {origin, listener} = listener()
    scope = open(origin)
    peer = peer(listener)
    uri = %{URI.parse(origin <> "/raw?x=1") | authority: :binary.copy("a", 131_072)}
    response = drain(fetch(uri, scope))
    assert %URI{authority: nil, path: "/raw", query: "x=1"} = response.url
    assert {:request, head} = Task.await(peer, 2_000)
    assert head =~ "GET /raw?x=1 HTTP/1.1\r\n"
    assert head =~ "Host: #{URI.parse(origin).host}:#{URI.parse(origin).port}\r\n"
    retire(scope)
  end

  test "bounded empty iodata normalizes to an empty buffered upload" do
    {origin, listener} = listener()
    scope = open(origin)
    peer = peer(listener)
    body = List.duplicate([], 8_192)
    assert %{body: ""} = prepare(origin, body: body, method: :post)
    _response = drain(fetch(origin, scope, method: :post, body: body))
    assert {:request, head} = Task.await(peer, 2_000)
    assert head =~ "Content-Length: 0\r\n"
    assert head =~ "Content-Type: application/octet-stream\r\n"
    retire(scope)
  end

  test "structural and nesting bounds reject empty iodata before dialing" do
    {origin, listener} = listener()
    scope = open(origin)
    peer = peer(listener)

    for body <- [List.duplicate([], 65_537), Enum.reduce(1..33, [], fn _, value -> [value] end)] do
      promise = fetch(origin, scope, method: :post, body: body)
      assert {:error, :transport_scope_request_limit} = Promise.await(promise)
      assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
    end

    assert :no_accept = Task.await(peer, 2_000)
    retire(scope)
  end

  test "generated body and HTTP1 headers participate in the field count limit" do
    {origin, listener} = listener()
    scope = open(origin)
    fields = [{"User-Agent", "test"} | for(n <- 1..251, do: {"X-#{n}", "v"})]
    peer = peer(listener)
    _response = drain(fetch(origin, scope, method: :post, body: "", headers: fields))
    assert {:request, head} = Task.await(peer, 2_000)
    assert length(String.split(head, "\r\n", trim: true)) == 257

    rejected_peer = peer(listener)
    promise = fetch(origin, scope, method: :post, body: "", headers: fields ++ [{"X-252", "v"}])
    assert {:error, :transport_scope_request_limit} = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
    assert :no_accept = Task.await(rejected_peer, 2_000)
    retire(scope)
  end

  test "generated fields participate in the exact HTTP1 metadata byte boundary" do
    {origin, listener} = listener()
    scope = open(origin)
    uri = URI.parse(origin)

    effective = [
      {"User-Agent", "test"},
      {"X-Fill", ""},
      {"Host", HTTP.Request.authority(uri)},
      {"Connection", "keep-alive"},
      {"Content-Length", "0"},
      {"Content-Type", "application/octet-stream"}
    ]

    charge =
      Enum.reduce(effective, 1, fn {key, value}, acc ->
        acc + byte_size(key) + byte_size(value) + 32
      end)

    fill = :binary.copy("a", 65_536 - charge)
    peer = peer(listener)

    _response =
      drain(
        fetch(origin, scope,
          method: :post,
          body: "",
          headers: [{"User-Agent", "test"}, {"X-Fill", fill}]
        )
      )

    assert {:request, _head} = Task.await(peer, 2_000)

    rejected_peer = peer(listener)

    promise =
      fetch(origin, scope,
        method: :post,
        body: "",
        headers: [{"User-Agent", "test"}, {"X-Fill", fill <> "a"}]
      )

    assert {:error, :transport_scope_request_limit} = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
    assert :no_accept = Task.await(rejected_peer, 2_000)
    retire(scope)
  end

  test "explicit Content-Type wins and original framing is preserved for rejection" do
    {origin, listener} = listener()
    scope = open(origin)
    peer = peer(listener)

    _response =
      drain(
        fetch(origin, scope,
          method: :post,
          body: "",
          headers: [{"Content-Type", "text/plain"}],
          content_type: ~c"application/json"
        )
      )

    assert {:request, head} = Task.await(peer, 2_000)
    assert head =~ "Content-Type: text/plain\r\n"
    refute head =~ "Content-Type: application/json\r\n"

    request =
      prepare(origin, method: :post, body: "", headers: [{"Transfer-Encoding", "chunked"}])

    assert HTTP.Headers.get(request.headers, "Transfer-Encoding") == "chunked"

    assert_raise ArgumentError, "Transfer-Encoding request headers are not supported", fn ->
      HTTP.HTTP1.prepare_request(request)
    end

    retire(scope)
  end

  test "retained URL, header, body and content-type binaries own compact backing" do
    borrowed = fn value ->
      backing = value <> :binary.copy("a", 1_048_576)
      slice = binary_part(backing, 0, byte_size(value))
      assert :binary.referenced_byte_size(slice) > byte_size(slice)
      slice
    end

    path = borrowed.("/" <> :binary.copy("p", 80))
    query = borrowed.("q=" <> :binary.copy("q", 80))
    header = borrowed.(:binary.copy("v", 80))
    body = borrowed.(:binary.copy("b", 80))
    content_type = borrowed.("application/" <> :binary.copy("c", 80))
    uri = %{URI.parse("http://127.0.0.1:32123") | path: path, query: query}

    request =
      prepare(uri,
        method: :post,
        body: [body],
        content_type: content_type,
        headers: [{"X-Test", header}]
      )

    for value <- [
          request.url.path,
          request.url.query,
          request.body,
          request.content_type,
          HTTP.Headers.get(request.headers, "X-Test")
        ] do
      assert :binary.referenced_byte_size(value) == byte_size(value)
    end
  end

  defp prepare(origin, opts) do
    url = if is_binary(origin), do: URI.parse(origin), else: origin

    {:ok, policy} =
      Policy.freeze(origin: url, connect_address: {127, 0, 0, 1}, http_version: :http1)

    request =
      struct(
        HTTP.Request,
        Keyword.merge(
          [
            url: url,
            headers: [],
            transport_options: [redirect: :manual, decode_body: false, stream_response: true]
          ],
          opts
        )
      )

    request = %{request | headers: HTTP.Headers.new(request.headers)}
    assert {:ok, prepared} = Policy.prepare(policy, request, [])
    prepared
  end

  defp listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {"http://127.0.0.1:#{port}", listener}
  end

  defp open(origin) do
    assert {:ok, scope} =
             ManagedTransport.open(
               origin: origin,
               connect_address: {127, 0, 0, 1},
               http_version: :http1
             )

    on_exit(fn ->
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      _ = ManagedTransport.await_retired(receipt, 2_000)
    end)

    scope
  end

  defp peer(listener) do
    task =
      Task.async(fn ->
        case :gen_tcp.accept(listener, 500) do
          {:error, :timeout} ->
            :no_accept

          {:ok, socket} ->
            head = read_head(socket, "")

            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
              )

            :gen_tcp.close(socket)
            {:request, head}
        end
      end)

    on_exit(fn -> if Process.alive?(task.pid), do: Process.exit(task.pid, :kill) end)
    task
  end

  defp read_head(socket, bytes) do
    if String.contains?(bytes, "\r\n\r\n") do
      bytes
    else
      {:ok, chunk} = :gen_tcp.recv(socket, 0, 2_000)
      read_head(socket, bytes <> chunk)
    end
  end

  defp fetch(origin, scope, opts \\ []) do
    HTTP.fetch(
      origin,
      Keyword.merge(
        [
          transport_scope: scope,
          redirect: :manual,
          stream_response: true,
          decode_body: false,
          timeout: 2_000
        ],
        opts
      )
    )
  end

  defp drain(promise) do
    assert %Response{} = response = Promise.await(promise)
    assert Response.read_all(response) == "ok"
    assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
    response
  end

  defp retire(scope) do
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 2_000)
  end
end
