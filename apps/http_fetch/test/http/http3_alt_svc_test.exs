defmodule HTTP.FetchHTTP3AltSvcTest do
  use ExUnit.Case, async: false
  alias HTTP.AltSvc.Cache
  alias Quic.Runtime.StreamHandle
  alias QuicHttp3.{Frame, Qpack}

  @moduletag :integration
  @fixtures Path.expand("../support/fixtures", __DIR__)

  setup do
    Cache.clear()
    ca = der(File.read!(Path.join(@fixtures, "no-otp-localhost-ecdsa-ca.pem")))
    leaf = der(File.read!(Path.join(@fixtures, "no-otp-localhost-ecdsa.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(@fixtures, "no-otp-localhost-ecdsa.key")))

    {:ok, server} = Quic.listen(tls: [cert: [leaf], key: {type, key}, alpn: ["h3"]])
    {_, udp_port} = Quic.local(server)

    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        ip: {127, 0, 0, 1},
        certfile: Path.join(@fixtures, "no-otp-localhost-ecdsa.pem"),
        keyfile: Path.join(@fixtures, "no-otp-localhost-ecdsa.key"),
        versions: [:"tlsv1.3"]
      ])

    {:ok, {_, tcp_port}} = :ssl.sockname(listener)

    on_exit(fn ->
      Cache.clear()
      stop_fixture_clients(udp_port)
      if Process.alive?(server), do: GenServer.stop(server)
      :ssl.close(listener)
    end)

    %{
      server: server,
      udp_port: udp_port,
      listener: listener,
      url: "https://127.0.0.1:#{tcp_port}/resource",
      origin: {"127.0.0.1", tcp_port},
      ssl: [cacerts: [ca]]
    }
  end

  test "H1 response advertising h3 routes the next request to HTTP/3", context do
    serve_h1(context.listener, [{"alt-svc", ~s(h3=":#{context.udp_port}"; ma=60)}], "h1")
    assert %HTTP.Response{http_version: :http1, body: "h1"} = await(fetch(context))
    assert Cache.lookup(context.origin) == {:ok, context.udp_port}

    promise = fetch(context)
    stream = context.server |> accept() |> await_stream(0)
    items = await_fin(stream, [])
    fields = request_fields(items)
    assert {":authority", URI.parse(context.url).authority} in fields
    reply(stream, 200, "h3")
    assert %HTTP.Response{http_version: :http3, status: 200, body: "h3"} = await(promise)
  end

  test "unreachable alternative falls back to TCP within the deadline and marks broken",
       context do
    {:ok, socket} = :gen_udp.open(0, ip: {127, 0, 0, 1})
    {:ok, dead_port} = :inet.port(socket)
    :ok = :gen_udp.close(socket)
    Cache.put(context.origin, ~s(h3=":#{dead_port}"))
    assert Cache.lookup(context.origin) == {:ok, dead_port}

    serve_h1(context.listener, [{"alt-svc", ~s(h3=":#{dead_port}")}], "fallback")
    started = System.monotonic_time(:millisecond)
    response = await(fetch(context, connect_timeout: 300, timeout: 4_000))
    assert %HTTP.Response{http_version: :http1, body: "fallback"} = response
    assert System.monotonic_time(:millisecond) - started < 4_000
    assert Cache.lookup(context.origin) == :none

    Cache.put(context.origin, ~s(h3=":#{context.udp_port}"))
    assert Cache.lookup(context.origin) == :none
  end

  test "failure after H3 connection readiness is returned without TCP replay", context do
    Cache.put(context.origin, ~s(h3=":#{context.udp_port}"))
    promise = fetch(context)
    connection = accept(context.server)
    stream = await_stream(connection, 0)
    await_fin(stream, [])
    Quic.close(connection, 0x101, <<>>)

    assert {:error, _reason} = await(promise)
    assert {:error, :timeout} = :ssl.transport_accept(context.listener, 300)
    assert Cache.lookup(context.origin) == {:ok, context.udp_port}
  end

  test "redirects on an Alt-Svc H3 route re-select per hop", context do
    Cache.put(context.origin, ~s(h3=":#{context.udp_port}"))
    promise = fetch(context)
    connection = accept(context.server)
    first = await_stream(connection, 0)
    await_fin(first, [])
    write(first, headers(302, [{"location", "/next"}]), true)

    second = await_stream(connection, 4)
    assert {":path", "/next"} in request_fields(await_fin(second, []))

    # Only final responses are learned; drop the origin before the next hop.
    Cache.put(context.origin, "clear")
    write(second, headers(307, [{"location", "/tcp"}, {"content-length", "0"}]), true)

    serve_h1(context.listener, [], "tcp hop")

    assert %HTTP.Response{http_version: :http1, body: "tcp hop", redirected: true} =
             await(promise)
  end

  test "TCP-form ex_ssl reference identity is carried onto the H3 route", context do
    Cache.put(context.origin, ~s(h3=":#{context.udp_port}"))

    ssl = context.ssl ++ [ex_ssl: [reference_identity: {:dns_id, "localhost"}]]
    promise = fetch(context, ssl: ssl)
    stream = context.server |> accept() |> await_stream(0)
    _items = await_fin(stream, [])
    reply(stream, 200, "h3 identity")

    assert %HTTP.Response{http_version: :http3, body: "h3 identity"} = await(promise)
  end

  test "ineligible routes ignore cached alternatives", context do
    Cache.put(context.origin, ~s(h3=":#{context.udp_port}"))
    serve_h1(context.listener, [], "explicit backend")

    assert %HTTP.Response{http_version: :http1} =
             await(fetch(context, tls_backend: :ex_ssl))
  end

  defp fetch(context, opts \\ []) do
    HTTP.fetch(
      context.url,
      Keyword.merge(
        [http_version: :auto, alt_svc: true, ssl: context.ssl, timeout: 5_000],
        opts
      )
    )
  end

  defp await(promise), do: HTTP.Promise.await(promise, 10_000)

  defp serve_h1(listener, fields, body) do
    parent = self()

    spawn_link(fn ->
      {:ok, socket} = :ssl.transport_accept(listener, 5_000)
      {:ok, socket} = :ssl.handshake(socket, 5_000)
      request = read_head(socket, "")
      head = Enum.map_join(fields, "", fn {name, value} -> "#{name}: #{value}\r\n" end)

      :ok =
        :ssl.send(
          socket,
          "HTTP/1.1 200 OK\r\n#{head}content-length: #{byte_size(body)}\r\n" <>
            "connection: close\r\n\r\n#{body}"
        )

      send(parent, {:h1_request, request})
      :ssl.close(socket)
    end)
  end

  defp read_head(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      {:ok, data} = :ssl.recv(socket, 0, 5_000)
      read_head(socket, acc <> data)
    end
  end

  defp der(pem) do
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(pem)
    der
  end

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
    :exit, _ -> false
  end

  defp accept(server) do
    assert_receive {:quic_accept, ^server}, 5_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    on_exit(fn -> Quic.close(accepted, 0x100, <<>>) end)
    accepted
  end

  defp await_stream(connection, id, deadline \\ deadline()) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(connection)

    case Enum.find(events, &match?({:stream_open, %StreamHandle{id: ^id}, :bidi}, &1)) do
      {:stream_open, stream, :bidi} -> stream
      nil -> await_stream(connection, id, deadline)
    end
  end

  defp await_fin(stream, acc, deadline \\ deadline()) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc ++ items

    if Enum.any?(items, &match?({:fin, _}, &1)),
      do: acc,
      else: await_fin(stream, acc, deadline)
  end

  defp request_fields(items) do
    wire = for {:data, _, bytes} <- items, into: <<>>, do: bytes
    {:ok, %{type: 1, payload: block}, _rest} = Frame.decode(wire)
    {:ok, fields} = Qpack.decode_header_block(block)
    fields
  end

  defp reply(stream, status, body) do
    write(
      stream,
      headers(status, [{"content-length", Integer.to_string(byte_size(body))}]) <>
        Frame.encode!(:data, body),
      true
    )
  end

  defp deadline, do: System.monotonic_time(:millisecond) + 5_000

  defp headers(status, fields) do
    {:ok, payload} = Qpack.encode_header_block([{":status", Integer.to_string(status)} | fields])
    Frame.encode!(:headers, payload)
  end

  defp write(stream, bytes, fin), do: assert({:ok, _} = Quic.send_stream(stream, bytes, fin))
end
