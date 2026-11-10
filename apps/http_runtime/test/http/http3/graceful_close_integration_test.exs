defmodule HTTP.HTTP3.GracefulCloseIntegrationTest do
  # Call tracing on the codec is global, so this module runs alone.
  use ExUnit.Case, async: false
  @moduletag :integration
  alias HTTP.HTTP3.{Pool, Stream}
  alias Quic.Cleanup

  # RFC 9114 section 5.2: an orderly client shutdown ends the QUIC connection
  # with an application CONNECTION_CLOSE carrying H3_NO_ERROR.
  @h3_no_error 0x100

  setup do
    directory = Path.expand("../../../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(directory, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(directory, "leaf-key.pem")))

    server =
      start_supervised!(%{
        id: :native_h3_peer,
        start:
          {Quic, :listen,
           [[acceptor: self(), tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]]]]},
        restart: :temporary
      })

    {_, port} = Quic.local(server)
    pool = start_supervised!({Pool, []})
    on_exit(fn -> :erlang.trace_pattern({Quic.Codec, :decode_frames, 2}, false, [:local]) end)

    request = fn reuse, extra ->
      %HTTP.Request{
        url: URI.parse("https://127.0.0.1:#{port}/close"),
        transport_options:
          [
            http3_reuse: reuse,
            timeout: 5_000,
            ssl: [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
          ] ++ extra
      }
    end

    %{server: server, pool: pool, request: request}
  end

  test "an exclusive WebSocket tunnel close sends H3_NO_ERROR before its receipt", ctx do
    receipt = HTTP.ClientCompletion.new()
    tracker = HTTP.ClientCompletion.tracker(receipt)
    :ok = HTTP.RequestLifecycle.enter(tracker, :owner)

    request = %{
      ctx.request.(false, [])
      | method: :connect,
        headers: HTTP.Headers.new([{"sec-websocket-version", "13"}])
    }

    assert {:ok, relay, generation} =
             Stream.start(request, self(),
               pool: ctx.pool,
               purpose: :extended_connect,
               protocol: "websocket",
               request_lifecycle: tracker,
               opening_timeout: 3_000
             )

    assert_receive {:quic_accept, _server}, 2_000
    {:ok, accepted} = Quic.accept(ctx.server)
    :ok = Quic.attach(accepted, self())
    watch_close(accepted)
    {:ok, control} = Quic.open_stream(accepted, :uni)
    settings = QuicHttp3.Frame.encode!(:settings, QuicHttp3.Settings.encode!([{8, 1}]))
    assert {:ok, _} = Quic.send_stream(control, <<0>> <> settings, false)
    connect = incoming(accepted, 0, bound(2_000))
    {:ok, block} = QuicHttp3.Qpack.encode_header_block([{":status", "200"}])
    assert {:ok, _} = Quic.send_stream(connect, QuicHttp3.Frame.encode!(:headers, block), false)

    assert_receive {:http_runtime, ^generation, ^relay, {:opened, %{owner: owner}}}, 2_000

    assert_receive {:http_runtime, ^generation, ^relay, {:headers, [{":status", "200"}], []}},
                   2_000

    %{cleanup: %{handle: handle}} = :sys.get_state(owner)
    HTTP.RequestLifecycle.retire_owner(tracker)
    Stream.close(relay)

    assert_peer_close(accepted, 1_000)
    assert :ok = HTTP.ClientCompletion.await(receipt, 6_000)
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.status(handle)
    refute Process.alive?(owner)
    assert %{leases: 0, pending: 0} = Pool.status(ctx.pool)
  end

  test "a pooled owner retiring its rotated connection sends H3_NO_ERROR", ctx do
    assert {:ok, relay, generation} =
             Stream.start(ctx.request.(true, rotation_after: 2), self(),
               pool: ctx.pool,
               opening_timeout: 3_000
             )

    assert_receive {:quic_accept, _server}, 2_000
    {:ok, accepted} = Quic.accept(ctx.server)
    :ok = Quic.attach(accepted, self())
    watch_close(accepted)
    request_stream = incoming(accepted, 0, bound(2_000))

    {:ok, headers} =
      QuicHttp3.Qpack.encode_header_block([{":status", "200"}, {"content-length", "4"}])

    bytes = QuicHttp3.Frame.encode!(:headers, headers) <> QuicHttp3.Frame.encode!(:data, "done")
    assert {:ok, _} = Quic.send_stream(request_stream, bytes, true)
    assert collect(relay, generation, "") == "done"

    relay_join = Process.monitor(relay)
    assert_peer_close(accepted, 2_000)
    assert_receive {:DOWN, ^relay_join, :process, ^relay, _}, 2_000
    assert %{leases: 0} = Pool.status(ctx.pool)
  end

  # The in-repo server records a peer close only as `:peer_closed`; the decoded
  # frame is the observable carrying the application error code.
  defp watch_close(%{id: connection}) do
    :erlang.trace_pattern({Quic.Codec, :decode_frames, 2}, [{:_, [], [{:return_trace}]}], [
      :local
    ])

    :erlang.trace(connection, true, [:call])
  end

  defp assert_peer_close(%{id: connection}, timeout) do
    deadline = now() + timeout

    assert {:application_close, @h3_no_error} = await_close(connection, deadline)
  end

  defp await_close(connection, deadline) do
    receive do
      {:trace, ^connection, :return_from, {Quic.Codec, :decode_frames, 2}, {:ok, frames, _}} ->
        case Enum.find(frames, &(&1.type in [:application_close, :connection_close])) do
          nil -> await_close(connection, deadline)
          frame -> {frame.type, frame.error_code}
        end

      {:trace, ^connection, _, _, _} ->
        await_close(connection, deadline)

      {:trace, ^connection, _, _, _, _} ->
        await_close(connection, deadline)
    after
      max(deadline - now(), 0) -> :no_peer_close
    end
  end

  defp incoming(connection, id, {:abs_ms, deadline} = bound) do
    assert now() < deadline
    assert {:ok, events} = Quic.events(connection)

    case Enum.find(events, &match?({:stream_open, %{id: ^id}, _}, &1)) do
      {:stream_open, handle, _} ->
        handle

      _ ->
        receive do
        after
          1 -> incoming(connection, id, bound)
        end
    end
  end

  defp collect(relay, generation, acc) do
    receive do
      {:http_runtime, ^generation, ^relay, {:data, bytes, ref}} ->
        Stream.acknowledge(relay, ref)
        collect(relay, generation, acc <> bytes)

      {:http_runtime, ^generation, ^relay, :done} ->
        acc

      {:http_runtime, ^generation, ^relay, {:error, reason}} ->
        flunk(inspect(reason))

      {:http_runtime, ^generation, ^relay, _} ->
        collect(relay, generation, acc)
    after
      2_000 -> flunk("HTTP/3 native response timed out")
    end
  end

  defp bound(timeout), do: {:abs_ms, now() + timeout}
  defp now, do: System.monotonic_time(:millisecond)
end
