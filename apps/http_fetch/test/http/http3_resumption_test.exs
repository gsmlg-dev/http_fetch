defmodule HTTP.FetchHTTP3ResumptionTest do
  use ExUnit.Case, async: false
  alias Quic.Runtime.StreamHandle
  alias QuicHttp3.{Frame, Qpack, Settings}

  @moduletag :integration
  @settings [{1, 0}, {6, 16_384}, {7, 0}]

  setup do
    fixture = Path.expand("../../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, server} =
      Quic.listen(
        tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]],
        resumption: [enabled: true, application_profile: "fetch-h3-test"],
        early_data: [enabled: true, application_profile: "fetch-h3-test-early"]
      )

    {_, port} = Quic.local(server)
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    ssl = [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
    %{server: server, port: port, url: "https://127.0.0.1:#{port}/r", ssl: ssl}
  end

  test "a second connection to the origin resumes the TLS session", context do
    first = serve_one(context, fetch(context), 200, "one")

    assert %{status: 200, body: "one", http3: %{resumed: false, early_data: false}} =
             first.response

    refute first.resumed
    await_partition(context.port, false)

    second = serve_one(context, fetch(context), 200, "two")

    assert %{status: 200, body: "two", http3: %{resumed: true, early_data: false}} =
             second.response

    assert second.resumed
    refute second.early
  end

  test "default options neither resume nor report HTTP/3 disposition", context do
    first = serve_one(context, fetch(context, http3_resumption: false), 200, "one")
    assert %{status: 200, http3: nil} = first.response
    second = serve_one(context, fetch(context, http3_resumption: false), 200, "two")
    assert %{status: 200, http3: nil} = second.response
    refute second.resumed
  end

  test "a safe early_data request is carried in accepted 0-RTT", context do
    first = serve_one(context, fetch(context, early_data: true), 200, "full")
    assert %{http3: %{resumed: false, early_data: false}} = first.response
    await_partition(context.port, true)

    second = serve_one(context, fetch(context, early_data: true), 200, "early")
    assert second.resumed and second.early

    assert %{status: 200, body: "early", http3: %{resumed: true, early_data: true}} =
             second.response
  end

  test "425 to a 0-RTT request is retried once after the handshake", context do
    serve_one(context, fetch(context, early_data: true), 200, "full")
    await_partition(context.port, true)

    promise = fetch(context, early_data: true)
    early = serve_connection(context, 425, "too early")
    assert early.early
    retry = serve_connection(context, 200, "retried")
    refute retry.early

    assert %{status: 200, body: "retried", http3: %{early_data: false}} =
             HTTP.Promise.await(promise)
  end

  test "425 to a request sent after the handshake is returned as is", context do
    response = serve_one(context, fetch(context, early_data: true), 425, "first").response
    assert %{status: 425, body: "first", http3: %{early_data: false}} = response
  end

  test "unsafe early_data requests raise at option normalization", context do
    assert_raise ArgumentError, ~r/early_data requires GET/, fn ->
      fetch(context, early_data: true, method: "POST")
    end

    assert_raise ArgumentError, ~r/without a body/, fn ->
      fetch(context, early_data: true, body: "x")
    end
  end

  defp fetch(context, opts \\ []) do
    HTTP.fetch(
      context.url,
      Keyword.merge(
        [
          http_version: :http3,
          ssl: context.ssl,
          timeout: 5_000,
          http3_resumption: true,
          http3_reuse: false
        ],
        opts
      )
    )
  end

  defp serve_one(context, promise, status, body) do
    result = serve_connection(context, status, body)
    Map.put(result, :response, HTTP.Promise.await(promise))
  end

  defp serve_connection(context, status, body) do
    connection = accept(context.server)
    {:ok, info} = Quic.info(connection)
    {:ok, control} = Quic.open_stream(connection, :uni)
    write(control, <<0>> <> Frame.encode!(:settings, Settings.encode!(@settings)), false)
    stream = await_stream(connection, deadline())
    await_fin(stream, deadline())

    write(
      stream,
      headers(status, [{"content-length", Integer.to_string(byte_size(body))}]) <>
        Frame.encode!(:data, body),
      true
    )

    %{resumed: info.resumption.resumed, early: info.resumption.early_data == :accepted}
  end

  # The client keeps the connection until the response completes, so the
  # ticket and SETTINGS of the first connection are recorded before the next.
  defp await_partition(port, early?, deadline \\ deadline()) do
    assert System.monotonic_time(:millisecond) < deadline
    entries = :sys.get_state(HTTP.HTTP3.Resumption).entries

    ready? =
      Enum.any?(entries, fn {_, entry} ->
        tickets =
          case Quic.Endpoint.stats(entry.endpoint.pid) do
            %{resumption: %{tickets: count}} -> count
            _ -> 0
          end

        entry.port == port and entry.early == early? and tickets > 0 and
          (not early? or entry.settings != nil)
      end)

    unless ready? do
      Process.sleep(10)
      await_partition(port, early?, deadline)
    end
  end

  defp deadline, do: System.monotonic_time(:millisecond) + 5_000

  defp accept(server) do
    assert_receive {:quic_accept, ^server}, 5_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    on_exit(fn -> Quic.close(accepted, 0x100, <<>>) end)
    accepted
  end

  defp await_stream(connection, deadline) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(connection)

    case Enum.find(events, &match?({:stream_open, %StreamHandle{}, :bidi}, &1)) do
      {:stream_open, stream, :bidi} -> stream
      nil -> await_stream(connection, deadline)
    end
  end

  defp await_fin(stream, deadline) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    unless Enum.any?(items, &match?({:fin, _}, &1)), do: await_fin(stream, deadline)
  end

  defp headers(status, fields) do
    {:ok, payload} = Qpack.encode_header_block([{":status", Integer.to_string(status)} | fields])
    Frame.encode!(:headers, payload)
  end

  defp write(stream, bytes, fin), do: assert({:ok, _} = Quic.send_stream(stream, bytes, fin))
end
