defmodule HTTP.WebSocket.HTTP3MigrationTest do
  # In-repo raw Quic server acting as an RFC 9220 WebSocket peer. This exercises
  # client migration end to end; it is not independent interoperability evidence.
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Close, Message, Open}
  alias QuicHttp3.{Frame, Qpack, Settings}

  @fixture Path.expand("../../../../elixir_quic/test/fixtures/tls", __DIR__)

  setup do
    cert = fn name -> der(Path.join(@fixture, name)) end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(@fixture, "leaf-key.pem")))

    {:ok, server} =
      Quic.listen(tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]])

    on_exit(fn -> HTTP.WebSocket.TestStop.quietly(server) end)
    {_, port} = Quic.local(server)

    %{
      server: server,
      url: "wss://127.0.0.1:#{port}/ws",
      ssl: [
        cacertfile: Path.join(@fixture, "root.pem"),
        reference_identity: {:dns_id, "example.test"}
      ]
    }
  end

  # Port migration on loopback; IP migration needs a loopback alias (127.0.0.2)
  # that is not configured by default on macOS.
  test "exclusive HTTP/3 WebSocket migrates to a new local port and keeps exchanging messages",
       ctx do
    {socket, peer} = open(ctx, http3_reuse: false)
    assert {:ok, %{remote: {_, old_port}}} = Quic.info(peer.conn)

    assert :ok = WebSocket.send(socket, "before")
    assert {:text, "before"} = read_ws(peer)

    assert {:ok, %{local: {{127, 0, 0, 1}, new_port} = local}} =
             WebSocket.migrate(socket, local: {{127, 0, 0, 1}, 0}, timeout: 5_000)

    assert new_port != old_port
    assert {:ok, %{remote: ^local}} = Quic.info(peer.conn)

    assert :ok = WebSocket.send(socket, "after-migration")
    assert {:text, "after-migration"} = read_ws(peer)
    send_ws(peer, "migrated-reply")
    assert_receive {WebSocket, ^socket, %Message{data: "migrated-reply"}}, 5_000

    assert {:error, :invalid_local_address} =
             WebSocket.migrate(socket, local: {{0, 0, 0, 0}, 0}, timeout: 1_000)

    assert :ok = WebSocket.send(socket, "still-usable")
    assert {:text, "still-usable"} = read_ws(peer)
  end

  # RFC 9114 section 5.2: once the WebSocket closes cleanly, the exclusive
  # connection ends with CONNECTION_CLOSE(H3_NO_ERROR) instead of idling out.
  test "a clean exclusive HTTP/3 WebSocket close sends H3_NO_ERROR to the peer", ctx do
    {socket, peer} = open(ctx, http3_reuse: false)
    watch_close(peer.conn)

    assert :ok = WebSocket.close(socket, 1000, "done")
    assert {8, <<1000::16, "done">>} = read_ws(peer)
    close = <<1000::16, "done">>

    send!(
      peer.stream,
      Frame.encode!(:data, <<1::1, 0::3, 8::4, 0::1, byte_size(close)::7, close::binary>>),
      true
    )

    assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 5_000
    assert {:application_close, 0x100} = await_close(peer.conn, now() + 2_000)
    assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(socket), 6_000)
  end

  test "a pooled HTTP/3 WebSocket refuses migration explicitly", ctx do
    {socket, peer} = open(ctx, [])

    assert {:error, :not_exclusive_owner} =
             WebSocket.migrate(socket, local: {{127, 0, 0, 1}, 0}, timeout: 1_000)

    assert :ok = WebSocket.send(socket, "unaffected")
    assert {:text, "unaffected"} = read_ws(peer)
  end

  test "migration arguments and opening state are validated", ctx do
    socket = client(ctx, http3_reuse: false)

    assert {:error, :invalid_local_address} = WebSocket.migrate(socket, local: :bad)

    assert {:error, :invalid_timeout} =
             WebSocket.migrate(socket, local: {{127, 0, 0, 1}, 0}, timeout: 0)

    assert {:error, :invalid_state} = WebSocket.migrate(socket, local: {{127, 0, 0, 1}, 0})
  end

  # -- client helpers --------------------------------------------------------

  defp client(ctx, opts) do
    socket =
      WebSocket.new(
        ctx.url,
        [],
        [http_version: :http3, ssl: ctx.ssl, opening_timeout: 5_000, close_timeout: 500] ++
          opts
      )

    assert %WebSocket{} = socket
    on_exit(fn -> WebSocket.close(socket) end)
    socket
  end

  defp open(ctx, opts) do
    socket = client(ctx, opts)
    conn = accept(ctx.server)
    {:ok, control} = Quic.open_stream(conn, :uni)
    send!(control, <<0>> <> Frame.encode!(:settings, Settings.encode!([{8, 1}])), false)
    stream = next_bidi(conn)
    {fields, rest} = read_headers(stream)
    assert {":protocol", "websocket"} in fields
    {:ok, block} = Qpack.encode_header_block([{":status", "200"}])
    send!(stream, Frame.encode!(:headers, block), false)
    assert_receive {WebSocket, ^socket, %Open{}}, 5_000
    {socket, %{conn: conn, stream: stream, buffer: rest}}
  end

  # -- server helpers --------------------------------------------------------

  defp der(path) do
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(File.read!(path))
    der
  end

  defp accept(server) do
    assert_receive {:quic_accept, ^server}, 5_000
    {:ok, conn} = Quic.accept(server)
    :ok = Quic.attach(conn, self())
    on_exit(fn -> Quic.close(conn, 0x100, <<>>) end)
    conn
  end

  # The raw server records a peer close only as `:peer_closed`; the decoded
  # frame is the observable carrying the application error code.
  defp watch_close(%{id: connection}) do
    on_exit(fn -> :erlang.trace_pattern({Quic.Codec, :decode_frames, 2}, false, [:local]) end)

    :erlang.trace_pattern({Quic.Codec, :decode_frames, 2}, [{:_, [], [{:return_trace}]}], [
      :local
    ])

    :erlang.trace(connection, true, [:call])
  end

  defp await_close(%{id: connection} = handle, deadline) do
    receive do
      {:trace, ^connection, :return_from, {Quic.Codec, :decode_frames, 2}, {:ok, frames, _}} ->
        case Enum.find(frames, &(&1.type in [:application_close, :connection_close])) do
          nil -> await_close(handle, deadline)
          frame -> {frame.type, frame.error_code}
        end

      {:trace, ^connection, _, _, _} ->
        await_close(handle, deadline)

      {:trace, ^connection, _, _, _, _} ->
        await_close(handle, deadline)
    after
      max(deadline - now(), 0) -> :no_peer_close
    end
  end

  defp send!(stream, bytes, fin), do: assert({:ok, _} = Quic.send_stream(stream, bytes, fin))

  defp next_bidi(conn, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, events} = Quic.events(conn, 32)

    case Enum.find(events, &match?({:stream_open, _, :bidi}, &1)) do
      {:stream_open, stream, :bidi} ->
        stream

      nil ->
        Process.sleep(5)
        next_bidi(conn, deadline)
    end
  end

  defp read_headers(stream, acc \\ <<>>, deadline \\ now() + 5_000) do
    assert now() < deadline
    acc = acc <> read_bytes(stream)

    case Frame.decode(acc) do
      {:ok, %{type: 1, payload: block}, rest} ->
        {:ok, fields} = Qpack.decode_header_block(block)
        {fields, rest}

      _ ->
        Process.sleep(5)
        read_headers(stream, acc, deadline)
    end
  end

  defp read_bytes(stream) do
    {:ok, items} = Quic.read(stream, 16_384)
    for {:data, _, bytes} <- items, into: <<>>, do: bytes
  end

  # Reads one masked client frame (payload < 126 bytes) carried in H3 DATA.
  defp read_ws(peer, deadline \\ now() + 5_000) do
    assert now() < deadline
    buffer = Process.get(:ws_buffer, peer.buffer) <> read_bytes(peer.stream)

    case data_payloads(buffer, <<>>) do
      {<<_fin::1, 0::3, opcode::4, 1::1, len::7, mask::binary-4, masked::binary-size(len),
         rest::binary>>, h3_rest}
      when len < 126 ->
        Process.put(:ws_buffer, rebuild(rest) <> h3_rest)
        {if(opcode == 1, do: :text, else: opcode), unmask(masked, mask)}

      _ ->
        Process.put(:ws_buffer, buffer)
        Process.sleep(5)
        read_ws(%{peer | buffer: Process.get(:ws_buffer)}, deadline)
    end
  end

  defp data_payloads(bytes, acc) do
    case Frame.decode(bytes) do
      {:ok, %{type: 0, payload: payload}, rest} -> data_payloads(rest, acc <> payload)
      _ -> {acc, bytes}
    end
  end

  defp rebuild(<<>>), do: <<>>
  defp rebuild(ws_bytes), do: Frame.encode!(:data, ws_bytes)

  defp unmask(payload, <<a, b, c, d>>) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {byte, index} -> Bitwise.bxor(byte, elem({a, b, c, d}, rem(index, 4))) end)
    |> :binary.list_to_bin()
  end

  defp send_ws(peer, text) when byte_size(text) < 126,
    do:
      send!(
        peer.stream,
        Frame.encode!(:data, <<1::1, 0::3, 1::4, 0::1, byte_size(text)::7, text::binary>>),
        false
      )

  defp now, do: System.monotonic_time(:millisecond)
end
