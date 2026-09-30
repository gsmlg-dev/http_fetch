defmodule HTTP.Runtime.TunnelStreamTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP2.ConnectionOwner
  alias HTTP.Runtime.Stream
  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  test "accepted tunnel retains outbound direction through remote EOF and zero credit" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, flags} = request(socket)
        send(parent, {:connect_wire, self(), id, flags})
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        receive do: (:remote_end -> :ok)
        :ok = :gen_tcp.send(socket, frame(0, 1, id, "peer"))
        receive do: (:credit -> :ok)
        :ok = :gen_tcp.send(socket, frame(8, 0, id, <<0::1, 3::31>>))
        assert {0, 0, ^id, "abc"} = next_frame(socket, 0, id)
        assert {0, 1, ^id, ""} = next_frame(socket, 0, id)
        send(parent, {:local_end, self()})
      end)

    {stream, generation} = start_stream(url, self(), purpose: :extended_connect)
    monitor = Process.monitor(stream)
    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000
    assert_receive {:connect_wire, ^peer, id, 4}, 5_000
    assert_receive {:http_runtime, ^generation, ^stream, {:headers, _, 4}}, 5_000
    assert :sys.get_state(owner).streams[id].upload_stopped? == false
    empty = Stream.write(stream, "")
    assert_receive {:http_runtime, ^generation, ^stream, {:write, ^empty, :done}}, 5_000
    write = Stream.write(stream, "abc")
    assert_receive {:http_runtime, ^generation, ^stream, {:write, ^write, :accepted}}, 5_000
    assert %{pending_upload_bytes: 3} = ConnectionOwner.status(owner)
    assert :sys.get_state(owner).connection.streams[id].purpose == :extended_connect
    send(peer, :remote_end)
    assert_receive {:http_runtime, ^generation, ^stream, {:data, "peer", 1, ack}}, 5_000
    Stream.acknowledge(stream, ack)
    assert_receive {:http_runtime, ^generation, ^stream, :remote_end}, 5_000
    assert Process.alive?(stream)
    half_close = Stream.half_close(stream)

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:write, ^half_close, {:error, :write_pending}}},
                   5_000

    send(peer, :credit)
    assert_receive {:http_runtime, ^generation, ^stream, {:write, ^write, {:progress, 3}}}, 5_000
    assert_receive {:http_runtime, ^generation, ^stream, {:write, ^write, :done}}, 5_000
    half_close = Stream.half_close(stream)
    assert_receive {:http_runtime, ^generation, ^stream, {:write, ^half_close, :done}}, 5_000
    assert_receive {:local_end, ^peer}, 5_000
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 5_000
    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
  end

  test "rejected CONNECT denies tunnel data and cancellation remains responsive at zero credit" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, flags} = request(socket)
        assert flags == 4
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x8D>>))
        assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
        send(parent, {:reset, self()})
      end)

    {stream, generation} = start_stream(url, self(), purpose: :extended_connect)
    assert_receive {:http_runtime, ^generation, ^stream, {:headers, _, 4}}, 5_000
    write = Stream.write(stream, "forbidden")

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:write, ^write, {:error, :extended_connect_not_established}}},
                   5_000

    close_stream(stream)
    assert_receive {:reset, ^peer}, 5_000
  end

  test "write admission bounds retained bytes and rejects overlapping writes" do
    {url, _peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
      end)

    {stream, generation} =
      start_stream(url, self(), purpose: :extended_connect, max_write_bytes: 3)

    assert_receive {:http_runtime, ^generation, ^stream, {:headers, _, 4}}, 5_000
    oversized = Stream.write(stream, "four")

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:write, ^oversized, {:error, :write_buffer_full}}},
                   5_000

    first = Stream.write(stream, "abc")
    assert_receive {:http_runtime, ^generation, ^stream, {:write, ^first, :accepted}}, 5_000
    second = Stream.write(stream, "x")

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:write, ^second, {:error, :write_pending}}},
                   5_000

    close_stream(stream)
  end

  test "a zero-credit tunnel does not block ordinary sibling completion or connection controls" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {tunnel_id, 4} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, tunnel_id, <<0x88>>))
        {ordinary_id, 5} = request(socket)

        :ok =
          :gen_tcp.send(socket, [frame(1, 5, ordinary_id, <<0x88>>), frame(6, 0, 0, "duplex!!")])

        assert {6, 1, 0, "duplex!!"} = next_frame(socket, 6, 0)
        send(parent, {:ordinary_completed, self()})
        assert {3, 0, ^tunnel_id, <<8::32>>} = next_frame(socket, 3, tunnel_id)
        send(parent, {:tunnel_cancelled, self()})
      end)

    scope = "tunnel-siblings-#{System.unique_integer([:positive])}"
    {tunnel, generation} = start_stream(url, self(), purpose: :extended_connect, scope: scope)
    assert_receive {:http_runtime, ^generation, ^tunnel, {:opened, %{owner: owner}}}, 5_000
    assert_receive {:http_runtime, ^generation, ^tunnel, {:headers, _, 4}}, 5_000
    ref = Stream.write(tunnel, "blocked")
    assert_receive {:http_runtime, ^generation, ^tunnel, {:write, ^ref, :accepted}}, 5_000
    {ordinary, ordinary_generation} = start_stream(url, self(), scope: scope)
    monitor = Process.monitor(ordinary)

    assert_receive {:http_runtime, ^ordinary_generation, ^ordinary, {:opened, %{owner: ^owner}}},
                   5_000

    assert_receive {:http_runtime, ^ordinary_generation, ^ordinary, :remote_end}, 5_000
    assert_receive {:DOWN, ^monitor, :process, ^ordinary, reason}, 5_000
    assert reason in [:normal, :noproc]
    assert_receive {:ordinary_completed, ^peer}, 5_000
    assert %{active_streams: 1, pending_upload_bytes: 7} = ConnectionOwner.status(owner)
    close_stream(tunnel)
    assert_receive {:tunnel_cancelled, ^peer}, 5_000
    assert %{active_streams: 0, pending_upload_bytes: 0} = ConnectionOwner.status(owner)
  end

  test "malformed writer limits are rejected before admission or opening HEADERS" do
    request = %HTTP.Request{
      url: URI.parse("http://127.0.0.1:9/"),
      transport_options: [http_version: :h2c]
    }

    for value <- [nil, :infinity, "100", 0, -1] do
      assert {:error, :invalid_max_write_bytes} =
               Stream.start(request, self(), max_write_bytes: value)
    end

    {url, _peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
      end)

    {stream, generation} = start_stream(url, self(), purpose: :extended_connect)
    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000

    for value <- [nil, :infinity, "100", 0, -1] do
      assert {:error, :invalid_max_write_bytes} =
               ConnectionOwner.open_stream(owner, [], max_write_bytes: value)
    end

    assert %{active_streams: 1} = ConnectionOwner.status(owner)
    close_stream(stream)
  end

  test "connection-level SETTINGS failure preserves preceding tunnel bytes and reports protocol error" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        receive do: (:malformed_settings -> :ok)

        :ok =
          :gen_tcp.send(socket, [
            frame(0, 0, id, "valid-before-error"),
            frame(4, 0, 0, <<8::16, 2::32>>)
          ])

        assert {7, 0, 0, <<0::1, 0::31, 1::32>>} = next_frame(socket, 7, 0)
        send(parent, {:protocol_goaway, self()})
      end)

    {stream, generation} = start_stream(url, self(), purpose: :extended_connect)
    assert_receive {:http_runtime, ^generation, ^stream, {:headers, _, 4}}, 5_000
    send(peer, :malformed_settings)

    assert_receive {:http_runtime, ^generation, ^stream, {:data, "valid-before-error", 0, _ref}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:terminal, {:http2, :transport_error, :invalid_enable_connect_protocol}}},
                   5_000

    assert_receive {:protocol_goaway, ^peer}, 5_000
  end

  defp start_stream(url, subscriber, opts) do
    request = %HTTP.Request{
      method: Keyword.get(opts, :method, :get),
      url: URI.parse(url),
      body: Keyword.get(opts, :body),
      transport_options: [
        http_version: Keyword.get(opts, :http_version, :h2c),
        http2_scope: Keyword.get(opts, :scope, "stream-#{System.unique_integer([:positive])}"),
        http2_reuse: Keyword.get(opts, :reuse, true),
        connect_timeout: Keyword.get(opts, :connect_timeout, 5_000),
        tls_backend: :ssl
      ]
    }

    {:ok, stream, generation} =
      Stream.start(
        request,
        subscriber,
        Keyword.take(opts, [:generation, :opening_timeout, :purpose, :max_write_bytes])
      )

    on_exit(fn ->
      if Process.alive?(stream), do: close_stream(stream)
    end)

    {stream, generation}
  end

  defp close_stream(stream) do
    monitor = Process.monitor(stream)
    Stream.close(stream)
    Stream.close(stream)
    assert_receive {:DOWN, ^monitor, :process, ^stream, reason}, 5_000
    assert reason in [:normal, :noproc]
  end

  defp peer(script, mode \\ :h2c) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)

        if mode == :h2c do
          assert {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), 5_000)

          :ok =
            :gen_tcp.send(socket, frame(4, 0, 0, <<3::16, 10::32, 8::16, 1::32, 4::16, 0::32>>))
        end

        script.(socket)
        receive do: (:stop -> :gen_tcp.close(socket))
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    scheme = if mode == :h2c, do: "http", else: "https"
    {"#{scheme}://127.0.0.1:#{port}/events", peer}
  end

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp receive_frame(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, 5_000)
    payload = if size == 0, do: <<>>, else: recv_payload(socket, size)
    {type, flags, id, payload}
  end

  defp recv_payload(socket, size) do
    assert {:ok, payload} = :gen_tcp.recv(socket, size, 5_000)
    payload
  end

  defp request(socket) do
    case receive_frame(socket) do
      {1, flags, id, _payload} ->
        {id, flags}

      {4, 0, 0, _payload} ->
        :ok = :gen_tcp.send(socket, frame(4, 1, 0, <<>>))
        request(socket)

      _frame ->
        request(socket)
    end
  end

  defp next_frame(socket, type, id) do
    case receive_frame(socket) do
      {^type, _flags, ^id, _payload} = observed -> observed
      _frame -> next_frame(socket, type, id)
    end
  end
end
