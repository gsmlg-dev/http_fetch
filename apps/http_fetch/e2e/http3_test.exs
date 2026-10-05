defmodule E2E.HTTP3Test do
  use ExUnit.Case, async: false
  @moduletag :e2e
  alias Quic.Runtime.StreamHandle
  alias QuicHttp3.{Frame, Qpack}

  setup do
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, server} = Quic.listen(tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]])
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {_, port} = Quic.local(server)
    ssl = [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
    %{server: server, url: "https://127.0.0.1:#{port}/events", ssl: ssl}
  end

  test "public Fetch establishes verified native UDP H3 and reports the actual protocol",
       context do
    promise = HTTP.fetch(context.url, http_version: :http3, ssl: context.ssl, timeout: 5_000)
    connection = accept(context.server)
    deadline = System.monotonic_time(:millisecond) + 5_000
    stream = await_stream(connection, 0, deadline)
    await_fin(stream, deadline, [])

    write(
      stream,
      headers(200, [{"content-length", "9"}]) <> Frame.encode!(:data, "native H3"),
      true
    )

    assert %HTTP.Response{http_version: :http3, status: 200, body: "native H3"} =
             HTTP.Promise.await(promise)
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
