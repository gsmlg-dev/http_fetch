defmodule HTTP.FetchHTTP3Test do
  use ExUnit.Case, async: false
  alias Quic.Runtime.StreamHandle
  alias QuicHttp3.{Frame, Qpack}

  setup do
    fixture = Path.expand("../../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, server} = Quic.listen(tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]])
    {_, port} = Quic.local(server)

    on_exit(fn ->
      stop_fixture_clients(port)
      if Process.alive?(server), do: GenServer.stop(server)
    end)

    ssl = [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
    %{server: server, url: "https://127.0.0.1:#{port}/events", ssl: ssl}
  end

  test "Fetch reports actual H3 with binary body, informational fields and trailers", context do
    parent = self()
    handler = {__MODULE__, make_ref()}

    :ok =
      :telemetry.attach(
        handler,
        [:http_fetch, :request, :stop],
        fn _, _, metadata, _ ->
          send(parent, {:request_stop, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)
    promise = fetch(context)
    connection = accept(context.server)
    stream = await_stream(connection, 0, deadline())
    await_fin(stream, deadline(), [])
    write(stream, headers(103, [{"link", "</style.css>"}]), false)
    body = <<0, 255, 1, 128, 3>>

    write(
      stream,
      headers(200, [{"content-length", "5"}, {"x-peer", "native"}]) <>
        Frame.encode!(:data, body) <> trailers([{"x-checksum", "verified"}]),
      true
    )

    response = HTTP.Promise.await(promise)
    assert %{__struct__: HTTP.Response, status: 200, http_version: :http3, body: ^body} = response
    assert HTTP.Headers.get(response.headers, "x-peer") == "native"
    assert [{103, fields}] = response.informational
    assert HTTP.Headers.get(fields, "link") == "</style.css>"
    assert HTTP.Headers.get(response.trailers, "x-checksum") == "verified"
    assert_receive {:request_stop, %{http_version: :http3, status: 200}}
  end

  test "Fetch streams unknown-length response and delivers trailers before end", context do
    promise = fetch(context)
    connection = accept(context.server)
    stream = await_stream(connection, 0, deadline())
    await_fin(stream, deadline(), [])

    write(
      stream,
      headers(200, []) <>
        Frame.encode!(:data, "abc") <>
        trailers([{"x-checksum", "three"}]),
      true
    )

    response = HTTP.Promise.await(promise)
    assert %{__struct__: HTTP.Response, http_version: :http3, body: reader} = response
    assert is_pid(reader)
    send(reader, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^reader, "abc", delivery}, 5_000
    send(reader, {:stream_chunk_ack, delivery})
    assert_receive {:stream_trailers, ^reader, fields}, 5_000
    assert HTTP.Headers.get(fields, "x-checksum") == "three"
    assert_receive {:stream_end, ^reader}, 5_000
  end

  for encoding <- ["gzip", "deflate"], streaming? <- [false, true] do
    test "H3 #{encoding} streaming=#{streaming?} decodes DATA and preserves trailers", context do
      body = ~s({"protocol":"h3"})

      encoded =
        if unquote(encoding) == "gzip", do: :zlib.gzip(body), else: :zlib.compress(body)

      fields = [{"content-encoding", unquote(encoding)}]

      fields =
        if unquote(streaming?),
          do: fields,
          else: [{"content-length", to_string(byte_size(encoded))} | fields]

      promise = fetch(context)
      connection = accept(context.server)
      stream = await_stream(connection, 0, deadline())
      await_fin(stream, deadline(), [])
      data = for <<byte <- encoded>>, into: <<>>, do: Frame.encode!(:data, <<byte>>)
      write(stream, headers(200, fields) <> data <> trailers([{"x-decoded", "yes"}]), true)
      response = HTTP.Promise.await(promise)
      assert response.http_version == :http3
      assert HTTP.Headers.get(response.headers, "content-encoding") == unquote(encoding)
      assert HTTP.Response.json(response) == {:ok, %{"protocol" => "h3"}}

      if unquote(streaming?) do
        reader = response.stream
        assert_receive {:stream_trailers, ^reader, trailers}, 5_000
        assert HTTP.Headers.get(trailers, "x-decoded") == "yes"
      else
        assert HTTP.Headers.get(response.trailers, "x-decoded") == "yes"
      end
    end
  end

  for encoding <- ["gzip", "deflate"], streaming? <- [false, true] do
    test "H3 raw #{encoding} streaming=#{streaming?} preserves DATA and trailers", context do
      original = <<0, 255, 128, 1>>

      encoded =
        if unquote(encoding) == "gzip", do: :zlib.gzip(original), else: :zlib.compress(original)

      fields = [{"content-encoding", unquote(encoding)}]

      fields =
        if unquote(streaming?),
          do: fields,
          else: [{"content-length", to_string(byte_size(encoded))} | fields]

      promise = fetch(context, decode_body: false)
      connection = accept(context.server)
      stream = await_stream(connection, 0, deadline())
      await_fin(stream, deadline(), [])
      data = for <<byte <- encoded>>, into: <<>>, do: Frame.encode!(:data, <<byte>>)
      write(stream, headers(200, fields) <> data <> trailers([{"x-stored", "yes"}]), true)
      response = HTTP.Promise.await(promise)
      assert response.http_version == :http3
      assert HTTP.Headers.get(response.headers, "content-encoding") == unquote(encoding)
      assert HTTP.Response.read_all(response) == encoded

      if unquote(streaming?) do
        reader = response.stream
        assert_receive {:stream_trailers, ^reader, trailers}, 5_000
        assert HTTP.Headers.get(trailers, "x-stored") == "yes"
      else
        assert HTTP.Headers.get(response.trailers, "x-stored") == "yes"
      end
    end
  end

  for encoding <- ["gzip", "deflate"] do
    test "H3 raw #{encoding} interrupted stream preserves ACK and cancellation", context do
      original = <<0, 255, 128, 1>>

      encoded =
        if unquote(encoding) == "gzip", do: :zlib.gzip(original), else: :zlib.compress(original)

      controller = HTTP.AbortController.new()
      promise = fetch(context, decode_body: false, signal: controller)
      connection = accept(context.server)
      stream = await_stream(connection, 0, deadline())
      await_fin(stream, deadline(), [])

      write(
        stream,
        headers(200, [{"content-encoding", unquote(encoding)}]) <>
          Frame.encode!(:data, encoded),
        false
      )

      response = HTTP.Promise.await(promise)
      reader = response.stream
      monitor = Process.monitor(reader)
      send(reader, {:read_chunk, self(), :ack})
      assert_receive {:stream_chunk, ^reader, ^encoded, delivery}, 5_000
      refute_receive {:stream_end, ^reader}
      HTTP.AbortController.abort(controller)
      assert_receive {:stream_error, ^reader, :aborted}, 5_000
      send(reader, {:stream_chunk_ack, delivery})
      assert_receive {:DOWN, ^monitor, :process, ^reader, :normal}, 5_000
      refute_receive {:stream_end, ^reader}
    end
  end

  test "H3 per-request telemetry opt-out covers request and response streaming", context do
    handler = {__MODULE__, make_ref()}

    events =
      for category <- [:request, :streaming],
          phase <- [:start, :stop, :exception, :chunk],
          do: [:http_fetch, category, phase]

    parent = self()

    :ok =
      :telemetry.attach_many(
        handler,
        events,
        fn event, measures, metadata, _ ->
          send(parent, {:disabled_event, event, measures, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    promise =
      fetch(context, telemetry: false, headers: [{"authorization", "Bearer sentinel-token"}])

    connection = accept(context.server)
    stream = await_stream(connection, 0, deadline())
    await_fin(stream, deadline(), [])

    write(
      stream,
      headers(200, [{"set-cookie", "sentinel-cookie"}]) <> Frame.encode!(:data, "OK"),
      true
    )

    response = HTTP.Promise.await(promise)
    assert HTTP.Response.read_all(response) == "OK"
    refute_receive {:disabled_event, _, _, _}
  end

  test "Fetch rejects wrong reference identity without fallback", context do
    result =
      fetch(context, ssl: Keyword.put(context.ssl, :reference_identity, {:dns_id, "wrong.test"}))

    assert {:error, {:http3_not_established, _}} = HTTP.Promise.await(result)
  end

  test "H3 options survive flat normalization", _context do
    opts =
      HTTP.FetchOptions.new(%{
        "httpVersion" => "h3",
        "http3Profile" => :ordered,
        "http3Reuse" => false
      })

    transport = HTTP.FetchOptions.to_transport_options(opts)
    assert transport[:http3_profile] == :ordered
    assert transport[:http3_reuse] == false
    assert_raise ArgumentError, fn -> HTTP.FetchOptions.new(http3_reuse: :sometimes) end
  end

  test "Fetch upload producer uses DATA frames and definitive acknowledgement", context do
    chunks = [<<0, 255, 128>>, :binary.copy("abcd", 8_192)]
    {:ok, producer} = HTTP.Stream.from_enumerable(chunks)
    promise = fetch(context, method: :post, body: producer, duplex: :half)
    connection = accept(context.server)
    stream = await_stream(connection, 0, deadline())
    items = await_fin(stream, deadline(), [])
    wire = for {:data, 0, bytes} <- items, into: <<>>, do: bytes
    {:ok, %{type: 1, payload: header_block}, rest} = Frame.decode(wire)
    {:ok, fields} = Qpack.decode_header_block(header_block)
    assert {":method", "POST"} in fields
    refute Enum.any?(fields, fn {name, _} -> name == "transfer-encoding" end)
    assert decode_data(rest, []) == IO.iodata_to_binary(chunks)
    write(stream, headers(200, [{"content-length", "2"}]) <> Frame.encode!(:data, "OK"), true)
    assert %HTTP.Response{body: "OK", http_version: :http3} = HTTP.Promise.await(promise)
  end

  test "abort cancels one H3 request while a pooled sibling remains usable", context do
    controller = HTTP.AbortController.new()
    promise = fetch(context, signal: controller)
    connection = accept(context.server)
    stream = await_stream(connection, 0, deadline())
    await_fin(stream, deadline(), [])
    HTTP.AbortController.abort(controller)
    assert {:error, :aborted} = HTTP.Promise.await(promise)
    sibling = fetch(context)
    next = await_stream(connection, 4, deadline())
    await_fin(next, deadline(), [])
    write(next, headers(200, [{"content-length", "2"}]) <> Frame.encode!(:data, "OK"), true)
    assert %HTTP.Response{body: "OK", http_version: :http3} = HTTP.Promise.await(sibling)
  end

  test "streamed redirects that preserve the method never replay the producer", context do
    {:ok, producer} = HTTP.Stream.from_enumerable(["consumed"])
    promise = fetch(context, method: :post, body: producer, duplex: :half)
    connection = accept(context.server)
    stream = await_stream(connection, 0, deadline())
    await_fin(stream, deadline(), [])
    write(stream, headers(307, [{"location", "/again"}]), true)
    assert {:error, :streaming_body_redirect_not_replayable} = HTTP.Promise.await(promise)
  end

  test "H3 incompatible TCP routes are rejected explicitly", context do
    for {option, error} <- [
          {{:tls_backend, :ssl}, :tls_backend_not_supported_for_quic},
          {{:proxy, "http://127.0.0.1:1"}, :proxy_not_supported_for_quic},
          {{:socket_opts, [nodelay: true]}, :socket_opts_not_supported_for_quic},
          {{:http2_profile, :native_v1}, :http2_profile_not_supported_for_quic}
        ] do
      assert {:error, ^error} = fetch(context, [option]) |> HTTP.Promise.await()
    end
  end

  test "informational response retention has a finite application budget", context do
    promise = fetch(context)
    connection = accept(context.server)
    stream = await_stream(connection, 0, deadline())
    await_fin(stream, deadline(), [])
    wire = :binary.copy(headers(103, []), 129) <> headers(200, [{"content-length", "0"}])
    write(stream, wire, true)
    assert {:error, :http3_informational_limit} = HTTP.Promise.await(promise)
  end

  defp decode_data(<<>>, chunks), do: chunks |> Enum.reverse() |> IO.iodata_to_binary()

  defp decode_data(bytes, chunks) do
    {:ok, %{type: 0, payload: chunk}, rest} = Frame.decode(bytes)
    decode_data(rest, [chunk | chunks])
  end

  # UDP listener teardown alone cannot promptly notify reused client owners.
  # Reconcile this fixture's owners before the next test can consume pool credit.
  defp stop_fixture_clients(port) do
    for {_, owner, _, _} <-
          DynamicSupervisor.which_children(:http_fetch_http3_connection_supervisor),
        is_pid(owner),
        fixture_owner?(owner, port) do
      GenServer.stop(owner, :normal, 5_000)
    end
  end

  defp fixture_owner?(owner, port) do
    state = :sys.get_state(owner, 1_000)
    state.opts[:host] == "127.0.0.1" and state.opts[:port] == port
  catch
    :exit, {:noproc, _} -> false
  end

  defp fetch(context, opts \\ []) do
    HTTP.fetch(
      context.url,
      Keyword.merge([http_version: :http3, ssl: context.ssl, timeout: 5_000], opts)
    )
  end

  defp deadline, do: System.monotonic_time(:millisecond) + 5_000

  defp trailers(fields) do
    {:ok, payload} = Qpack.encode_header_block(fields)
    Frame.encode!(:headers, payload)
  end

  defp accept(server) do
    assert_receive {:quic_accept, ^server}, 5_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    on_exit(fn -> Quic.close(accepted, 0x100, <<>>) end)
    accepted
  end

  defp await_stream(connection, id, deadline) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(connection)

    case Enum.find(events, &match?({:stream_open, %StreamHandle{id: ^id}, :bidi}, &1)) do
      {:stream_open, stream, :bidi} -> stream
      nil -> await_stream(connection, id, deadline)
    end
  end

  defp await_fin(stream, deadline, acc) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc ++ items
    if Enum.any?(items, &match?({:fin, _}, &1)), do: acc, else: await_fin(stream, deadline, acc)
  end

  defp headers(status, fields) do
    {:ok, payload} = Qpack.encode_header_block([{":status", Integer.to_string(status)} | fields])
    Frame.encode!(:headers, payload)
  end

  defp write(stream, bytes, fin), do: assert({:ok, _} = Quic.send_stream(stream, bytes, fin))
end
