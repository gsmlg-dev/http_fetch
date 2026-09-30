defmodule HTTP.Runtime.TunnelCapabilityTest do
  use ExUnit.Case, async: false
  import Bitwise

  alias HTTP.HTTP2.{ConnectionOwner, Pool}
  alias HTTP.Runtime.Stream

  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @enabled <<3::16, 10::32, 8::16, 1::32>>

  test "exclusive CONNECT waits for peer permission and emits exact raw tunnel headers" do
    parent = self()

    {url, peer, port} =
      peer(fn socket ->
        receive do: (:enable -> initial(socket, @enabled))
        {1, 4, id, block} = next(socket, 1)
        send(parent, {:wire_headers, self(), id, decode_literals(block)})
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        assert {3, 0, ^id, <<8::32>>} = next(socket, 3)
        send(parent, {:reset_seen, self()})
      end)

    generation = make_ref()
    {stream, ^generation} = start_stream(url, reuse: false, generation: generation)
    assert_receive {:accepted, ^peer, _settings}, 5_000
    owner = owner_for_port(port)
    awaiting_capability(owner, stream, generation)
    send(stream, {:http2_capability, make_ref(), true})
    premature = Stream.write(stream, "before-permission")

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:write, ^premature, {:error, :extended_connect_not_established}}},
                   5_000

    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
    send(peer, :enable)

    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: ^owner, id: id}}},
                   5_000

    assert_receive {:wire_headers, ^peer, ^id, headers}, 5_000

    assert Enum.take(headers, 5) == [
             {":method", "CONNECT"},
             {":protocol", "websocket"},
             {":scheme", "http"},
             {":authority", "127.0.0.1:#{port}"},
             {":path", "/chat?q=1"}
           ]

    assert Enum.drop(headers, 5) == [
             {"sec-websocket-version", "13"},
             {"origin", "https://origin.test"}
           ]

    refute Enum.any?(
             headers,
             &(elem(&1, 0) in [
                 "connection",
                 "upgrade",
                 "host",
                 "sec-websocket-key",
                 "sec-websocket-accept",
                 "content-length"
               ])
           )

    assert_receive {:http_runtime, ^generation, ^stream, {:headers, _, 4}}, 5_000
    close_stream(stream)
    assert_receive {:reset_seen, ^peer}, 5_000
  end

  test "exclusive cancellation interrupts SETTINGS wait without sending CONNECT" do
    parent = self()

    {url, peer, port} =
      peer(fn socket ->
        no_headers_until_closed(socket)
        send(parent, {:closed_without_connect, self()})
      end)

    {stream, generation} = start_stream(url, reuse: false)
    monitor = Process.monitor(stream)
    assert_receive {:accepted, ^peer, _}, 5_000
    owner = owner_for_port(port)
    owner_monitor = Process.monitor(owner)
    awaiting_capability(owner, stream, generation)
    Stream.close(stream)
    assert_receive {:http_runtime, ^generation, ^stream, {:error, :aborted}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
    assert_receive {:closed_without_connect, ^peer}, 5_000
  end

  test "missing peer capability rejects CONNECT despite local advertisement" do
    parent = self()

    {url, peer, port} =
      peer(fn socket ->
        receive do: (:refuse -> initial(socket, <<3::16, 10::32>>))
        no_headers_until_closed(socket)
        send(parent, {:closed_without_connect, self()})
      end)

    profile = %{id: "local-connect-advertisement", settings: [{2, 0}, {8, 1}]}
    {stream, generation} = start_stream(url, reuse: false, profile: profile)
    monitor = Process.monitor(stream)
    assert_receive {:accepted, ^peer, settings}, 5_000
    assert {8, 1} in for(<<id::16, value::32 <- settings>>, do: {id, value})
    owner = owner_for_port(port)
    awaiting_capability(owner, stream, generation)
    send(peer, :refuse)

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:error, :extended_connect_not_supported}},
                   5_000

    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 5_000
    assert_receive {:closed_without_connect, ^peer}, 5_000
  end

  test "later permission opens on the reused owner while ordinary sibling progresses" do
    parent = self()

    {url, peer, _port} =
      peer(fn socket ->
        initial(socket, <<3::16, 10::32, 8::16, 0::32>>)
        {1, 5, ordinary_id, _} = next(socket, 1)
        :ok = :gen_tcp.send(socket, frame(1, 4, ordinary_id, <<0x88>>))
        receive do: (:prove_refusal -> ping_barrier(socket, "refusal!", [:headers]))
        send(parent, {:refusal_proved, self()})
        receive do: (:enable -> :ok)
        :ok = :gen_tcp.send(socket, frame(4, 0, 0, <<8::16, 1::32>>))
        ping_barrier(socket, "enabled!", [:headers])
        send(parent, {:enabled, self()})
        {1, 4, tunnel_id, block} = next(socket, 1)
        assert List.keyfind(decode_literals(block), ":method", 0) == {":method", "CONNECT"}

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, tunnel_id, <<0x88>>),
            frame(0, 0, ordinary_id, "sibling"),
            frame(0, 0, tunnel_id, "tunnel")
          ])

        reset_ids = for _ <- 1..2, do: elem(next(socket, 3), 2)
        assert Enum.sort(reset_ids) == [ordinary_id, tunnel_id]
        send(parent, {:siblings_cleaned, self()})
      end)

    scope = "capability-#{System.unique_integer([:positive])}"
    {ordinary, ordinary_generation} = start_stream(url, purpose: :request, scope: scope)

    assert_receive {:http_runtime, ^ordinary_generation, ^ordinary,
                    {:opened, %{owner: owner, id: 1}}},
                   5_000

    assert_receive {:http_runtime, ^ordinary_generation, ^ordinary, {:headers, _, 4}}, 5_000
    {refused, refused_generation} = start_stream(url, scope: scope)
    refused_monitor = Process.monitor(refused)

    assert_receive {:http_runtime, ^refused_generation, ^refused,
                    {:error, :extended_connect_not_supported}},
                   5_000

    assert_receive {:DOWN, ^refused_monitor, :process, ^refused, reason}, 5_000
    assert reason in [:normal, :noproc]
    send(peer, :prove_refusal)
    assert_receive {:refusal_proved, ^peer}, 5_000
    send(peer, :enable)
    assert_receive {:enabled, ^peer}, 5_000
    ConnectionOwner.status(owner)
    Pool.stats(Process.whereis(:http_fetch_http2_pool))
    generation = make_ref()
    {tunnel, ^generation} = start_stream(url, scope: scope, generation: generation)

    assert_receive {:http_runtime, ^generation, ^tunnel, {:opened, %{owner: ^owner, id: 3}}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^tunnel, {:headers, _, 4}}, 5_000

    assert_receive {:http_runtime, ^ordinary_generation, ^ordinary,
                    {:data, "sibling", 0, ordinary_ack}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^tunnel, {:data, "tunnel", 0, tunnel_ack}}, 5_000
    Stream.acknowledge(ordinary, ordinary_ack)
    Stream.acknowledge(tunnel, tunnel_ack)
    assert %{active_streams: 2} = ConnectionOwner.status(owner)
    close_stream(ordinary)
    close_stream(tunnel)
    assert_receive {:siblings_cleaned, ^peer}, 5_000
    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
  end

  test "stale generation cannot write onto an established tunnel" do
    parent = self()

    {url, peer, _port} =
      peer(fn socket ->
        initial(socket, @enabled)
        {1, 4, id, _} = next(socket, 1)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        receive do: (:prove_stale -> ping_barrier(socket, "stalegen", [:data]))
        send(parent, {:stale_proved, self()})
        assert {0, 0, ^id, "valid"} = next(socket, 0)
        send(parent, {:valid_seen, self()})
        assert {3, 0, ^id, <<8::32>>} = next(socket, 3)
      end)

    generation = make_ref()
    {stream, ^generation} = start_stream(url, generation: generation)

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:opened, %{owner: owner, id: id, ref: ^generation}}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^stream, {:headers, _, 4}}, 5_000
    send(owner, {:http2_write, id, make_ref(), make_ref(), "stale", false})
    assert %{pending_upload_bytes: 0} = ConnectionOwner.status(owner)
    send(peer, :prove_stale)
    assert_receive {:stale_proved, ^peer}, 5_000
    write = Stream.write(stream, "valid")
    assert_receive {:http_runtime, ^generation, ^stream, {:write, ^write, :done}}, 5_000
    assert_receive {:valid_seen, ^peer}, 5_000
    close_stream(stream)
  end

  defp start_stream(url, opts) do
    request = %HTTP.Request{
      url: URI.parse(url),
      headers:
        HTTP.Headers.new([
          {"Sec-WebSocket-Version", "13"},
          {"Origin", "https://origin.test"}
        ]),
      transport_options: [
        http_version: :h2c,
        tls_backend: :ssl,
        http2_reuse: Keyword.get(opts, :reuse, true),
        http2_profile: Keyword.get(opts, :profile, :native_v1),
        http2_scope: Keyword.get(opts, :scope, "capability-#{System.unique_integer([:positive])}")
      ]
    }

    {:ok, stream, generation} =
      Stream.start(
        request,
        self(),
        [purpose: Keyword.get(opts, :purpose, :extended_connect)] ++
          Keyword.take(opts, [:generation])
      )

    on_exit(fn -> if Process.alive?(stream), do: close_stream(stream) end)
    {stream, generation}
  end

  defp close_stream(stream) do
    monitor = Process.monitor(stream)
    Stream.close(stream)
    assert_receive {:DOWN, ^monitor, :process, ^stream, reason}, 5_000
    assert reason in [:normal, :noproc]
  end

  defp peer(script) do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        assert {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), 5_000)
        assert {4, 0, 0, settings} = receive_frame(socket)
        send(parent, {:accepted, self(), settings})
        script.(socket)
        receive do: (:stop -> :gen_tcp.close(socket))
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)

      for {_, owner, _, _} <-
            DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor),
          is_pid(owner) do
        case owner_socket_port(owner) do
          ^port -> send(owner, :http2_shutdown_exclusive)
          _ -> :ok
        end
      end
    end)

    {"http://127.0.0.1:#{port}/chat?q=1", peer, port}
  end

  defp owner_for_port(port) do
    owners =
      for {_, owner, _, _} <-
            DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor),
          is_pid(owner),
          owner_socket_port(owner) == port,
          do: owner

    assert [owner] = owners
    owner
  end

  defp owner_socket_port(owner) do
    case :inet.peername(:sys.get_state(owner).socket) do
      {:ok, {_, port}} -> port
      _ -> nil
    end
  catch
    :exit, _ -> nil
  end

  defp awaiting_capability(owner, stream, generation) do
    :erlang.trace(owner, true, [:receive, {:tracer, self()}])

    try do
      state = :sys.get_state(owner)

      unless {stream, generation} in Map.values(state.capability_waiters) do
        assert_receive {:trace, ^owner, :receive,
                        {:http2_await_capability, ^stream, ^generation}},
                       5_000

        assert {stream, generation} in Map.values(:sys.get_state(owner).capability_waiters)
      end
    after
      :erlang.trace(owner, false, [:receive])
    end
  end

  defp initial(socket, payload),
    do: :gen_tcp.send(socket, [frame(4, 0, 0, payload), frame(4, 1, 0, "")])

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp receive_frame(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, 5_000)
    payload = if size == 0, do: "", else: recv(socket, size)
    {type, flags, id, payload}
  end

  defp recv(socket, size) do
    assert {:ok, payload} = :gen_tcp.recv(socket, size, 5_000)
    payload
  end

  defp next(socket, type) do
    case receive_frame(socket) do
      {^type, _, _, _} = frame ->
        frame

      {4, 0, 0, _} ->
        :ok = :gen_tcp.send(socket, frame(4, 1, 0, ""))
        next(socket, type)

      _ ->
        next(socket, type)
    end
  end

  defp ping_barrier(socket, marker, forbidden) do
    :ok = :gen_tcp.send(socket, frame(6, 0, 0, marker))
    ping_ack(socket, marker, forbidden)
  end

  defp ping_ack(socket, marker, forbidden) do
    case receive_frame(socket) do
      {6, 1, 0, ^marker} ->
        :ok

      {type, _, _, _} when type in [0, 1] ->
        name = if type == 0, do: :data, else: :headers
        refute name in forbidden
        ping_ack(socket, marker, forbidden)

      _ ->
        ping_ack(socket, marker, forbidden)
    end
  end

  defp no_headers_until_closed(socket) do
    case :gen_tcp.recv(socket, 9, 5_000) do
      {:error, :closed} ->
        :ok

      {:ok, <<size::24, type, _flags, _id::32>>} ->
        refute type == 1
        if size > 0, do: recv(socket, size)
        no_headers_until_closed(socket)

      other ->
        flunk("expected frame or orderly closure: #{inspect(other)}")
    end
  end

  # Independent native-profile oracle: RFC 7541 non-indexed, non-Huffman
  # literals only. It deliberately does not call this package's HPACK codec.
  defp decode_literals(""), do: []

  defp decode_literals(<<prefix, rest::binary>>) when prefix < 32 do
    {index, rest} = integer(prefix &&& 15, 15, rest)

    {name, rest} =
      if index == 0,
        do: string(rest),
        else: {Map.fetch!(%{1 => ":authority", 58 => "user-agent"}, index), rest}

    {value, rest} = string(rest)
    [{name, value} | decode_literals(rest)]
  end

  defp string(<<prefix, rest::binary>>) when prefix < 128 do
    {size, rest} = integer(prefix, 127, rest)
    <<value::binary-size(size), rest::binary>> = rest
    {value, rest}
  end

  defp integer(value, maximum, rest) when value < maximum, do: {value, rest}
  defp integer(value, _maximum, rest), do: integer_tail(rest, value, 0)

  defp integer_tail(<<byte, rest::binary>>, value, shift) do
    value = value + ((byte &&& 127) <<< shift)
    if byte < 128, do: {value, rest}, else: integer_tail(rest, value, shift + 7)
  end
end
