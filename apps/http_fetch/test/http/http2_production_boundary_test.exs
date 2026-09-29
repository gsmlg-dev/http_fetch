defmodule HTTP.HTTP2.ProductionBoundaryTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP2.ConnectionOwner

  defp wire(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp owner do
    parent = self()

    transport = %{
      send: fn _, data ->
        send(parent, {:wire, IO.iodata_to_binary(data)})
        :ok
      end,
      normalize_message: fn
        {:tcp_closed, socket}, socket -> :closed
        _, _ -> :unknown
      end
    }

    {:ok, owner} = ConnectionOwner.start_link(transport: transport, activate?: false)
    assert_receive {:wire, _}
    owner
  end

  defp ready(owner) do
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(4, 0, 0, <<>>))
    assert_receive {:wire, <<0::24, 4, 1, 0::32>>}
  end

  defp open(owner) do
    assert {:ok, %{id: id}} =
             ConnectionOwner.open_stream(owner, [
               {":method", "GET"},
               {":scheme", "http"},
               {":authority", "test"},
               {":path", "/"}
             ])

    assert_receive {:wire, _}
    id
  end

  test "acknowledges PING with exact opaque payload" do
    owner = owner()
    ready(owner)
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(6, 0, 0, "12345678"))
    assert_receive {:wire, <<8::24, 6, 1, 0::32, "12345678">>}
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(6, 1, 0, "12345678"))
    refute_receive {:wire, _}
  end

  test "reset preserves the peer error and isolates its stream" do
    owner = owner()
    ready(owner)
    first = open(owner)
    second = open(owner)
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(3, 0, first, <<7::32>>))
    assert_receive {:http2, ^first, {:http2, :reset, 7}}
    refute_receive {:http2, ^second, _}
  end

  test "reset settles once while late stream traffic and close preserve siblings" do
    owner = owner()
    ready(owner)
    first = open(owner)
    sibling = open(owner)
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(3, 0, first, <<7::32>>))
    assert_receive {:http2, ^first, {:http2, :reset, 7}}
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(3, 0, first, <<8::32>>))
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(0, 0, first, "late"))
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(8, 0, first, <<4::32>>))
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 5, sibling, <<0x88>>))
    assert_receive {:http2, ^sibling, {:http2, :headers, _, _}}
    monitor = Process.monitor(owner)
    send(owner, {:tcp_closed, nil})
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    assert_receive {:http2, ^sibling, {:http2, :transport_closed}}
    refute_receive {:http2, ^first, _}
  end

  test "required write failure notifies existing subscriber exactly once" do
    failure = :atomics.new(1, [])

    transport = %{
      send: fn _, _ ->
        if :atomics.get(failure, 1) == 0, do: :ok, else: {:error, :timeout}
      end
    }

    {:ok, owner} = ConnectionOwner.start_link(transport: transport, activate?: false)
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(4, 0, 0, <<>>))
    assert {:ok, %{id: first}} = ConnectionOwner.open_stream(owner, [{":method", "GET"}])
    :atomics.put(failure, 1, 1)
    monitor = Process.monitor(owner)
    assert {:error, :timeout} = ConnectionOwner.open_stream(owner, [{":method", "GET"}])
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    assert_receive {:http2, ^first, {:http2, :transport_error, :timeout}}
    refute_receive {:http2, ^first, _}
  end

  test "padded DATA and priority HEADERS deliver application bytes only" do
    owner = owner()
    ready(owner)
    id = open(owner)
    headers = <<2, 1::1, 0::31, 15, 0x88, 0, 0>>
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 0x2C, id, headers))
    assert_receive {:http2, ^id, {:http2, :headers, [{":status", "200"}], _}}
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(0, 9, id, <<3, "ok", 0, 0, 0>>))
    assert_receive {:http2, ^id, {:http2, :data, "ok", 9}}
  end

  test "released protocol streams do not turn peer capacity into a lifetime limit" do
    owner = owner()
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(4, 0, 0, <<3::16, 1::32>>))
    assert_receive {:wire, _}
    first = open(owner)
    assert :ok = ConnectionOwner.release_stream(owner, first)
    assert 3 = open(owner)
  end

  test "client receive profile never grants peer send credit" do
    parent = self()

    transport = %{
      send: fn _, data ->
        send(parent, {:wire, IO.iodata_to_binary(data)})
        :ok
      end
    }

    {:ok, owner} =
      ConnectionOwner.start_link(
        transport: transport,
        activate?: false,
        profile: :synthetic_test_v1
      )

    assert_receive {:wire, _}
    state = :sys.get_state(owner)
    assert state.connection.connection_send_window == 65_535
    assert state.connection.connection_receive_window == 131_071
  end

  test "upload chunks make partial progress and SETTINGS resumes pending bytes" do
    owner = owner()
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(4, 0, 0, <<4::16, 1_024::32>>))
    assert_receive {:wire, _}

    assert {:ok, %{id: id}} =
             ConnectionOwner.open_stream(owner, [{":method", "POST"}], body_bridge: self())

    assert_receive {:wire, _}
    ref = make_ref()
    chunk = :binary.copy("x", 2_048)
    assert :ok = ConnectionOwner.send_event(owner, {:body_chunk, self(), chunk, ref})
    assert_receive {:wire, <<1_024::24, 0, 0, 0::1, ^id::31, first::binary>>}
    assert byte_size(first) == 1_024
    refute_receive {:body_ack, ^ref}
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(4, 0, 0, <<4::16, 2_048::32>>))
    assert_receive {:wire, <<0::24, 4, 1, 0::32>>}
    assert_receive {:wire, <<1_024::24, 0, 0, 0::1, ^id::31, _::binary>>}
    assert_receive {:body_ack, ^ref}
  end

  test "stream credit returns on consumption; bounded connection admission counts padding" do
    owner = owner()
    ready(owner)
    id = open(owner)
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 4, id, <<0x88>>))
    assert_receive {:http2, ^id, {:http2, :headers, _, _}}
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(0, 8, id, <<3, "ok", 0, 0, 0>>))
    assert_receive {:http2, ^id, {:http2, :data, "ok", _}}
    assert_receive {:wire, <<4::24, 8, 0, 0::32, 6::32>>}
    refute_receive {:wire, <<4::24, 8, 0, 0::1, ^id::31, _::32>>}
    assert :ok = ConnectionOwner.acknowledge(owner, id)
    assert_receive {:wire, <<4::24, 8, 0, 0::1, ^id::31, 6::32>>}
    assert :sys.get_state(owner).connection.connection_unacknowledged == 0
  end

  test "malformed status fails one stream without raising in shared owner" do
    owner = owner()
    ready(owner)
    first = open(owner)
    second = open(owner)
    # Literal with indexed :status name; independent raw HPACK bytes.
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 5, first, <<8, 4, "oops">>))
    assert_receive {:http2, ^first, {:http2, :stream_error, _}}
    assert Process.alive?(owner)
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 5, second, <<0x88>>))
    assert_receive {:http2, ^second, {:http2, :headers, [{":status", "200"}], 5}}
  end

  test "ambiguous header send failure terminates owner instead of rolling HPACK back" do
    test = self()

    transport = %{
      send: fn _, data ->
        if String.starts_with?(IO.iodata_to_binary(data), "PRI *"),
          do: :ok,
          else: {:error, :timeout}
      end,
      close: fn _ ->
        send(test, :transport_closed)
        :ok
      end
    }

    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport, socket: :socket, activate?: false)

    monitor = Process.monitor(owner)
    assert {:error, :timeout} = ConnectionOwner.open_stream(owner, [{":method", "GET"}])
    assert_receive {:DOWN, ^monitor, :process, ^owner, _}
    assert_receive :transport_closed
  end

  test "paused consumer has finite stream credit while sibling and PING progress" do
    owner = owner()
    ready(owner)
    slow = open(owner)
    sibling = open(owner)

    for id <- [slow, sibling] do
      assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 4, id, <<0x88>>))
      assert_receive {:http2, ^id, {:http2, :headers, _, _}}
    end

    for size <- [16_384, 16_384, 16_384, 16_383] do
      assert :ok = ConnectionOwner.receive_bytes(owner, wire(0, 0, slow, :binary.copy("x", size)))
    end

    assert :ok = ConnectionOwner.receive_bytes(owner, wire(0, 1, sibling, "ok"))
    assert_receive {:http2, ^sibling, {:http2, :data, "ok", 1}}
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(6, 0, 0, "12345678"))
    assert_receive {:wire, <<8::24, 6, 1, 0::32, "12345678">>}
    state = :sys.get_state(owner)
    assert state.connection.streams[slow].receive_window == 0
    assert state.connection.connection_unacknowledged == 65_537

    assert state.connection.connection_unacknowledged + state.connection.connection_receive_window <=
             state.max_receive_buffer_bytes

    refute_receive {:wire, <<4::24, 8, 0, 0::1, ^slow::31, _::32>>}
  end

  test "late DATA and WINDOW_UPDATE after reset preserve sibling connection and credit" do
    owner = owner()
    ready(owner)
    first = open(owner)
    second = open(owner)
    assert :ok = ConnectionOwner.cancel(owner, first)
    assert :ok = ConnectionOwner.release_stream(owner, first)
    before = :sys.get_state(owner).connection.connection_receive_window
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(0, 0, first, "late"))
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(8, 0, first, <<1::32>>))
    assert :sys.get_state(owner).connection.connection_receive_window == before
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 5, second, <<0x88>>))
    assert_receive {:http2, ^second, {:http2, :headers, [{":status", "200"}], 5}}
  end

  test "GOAWAY preserves error and promptly classifies streams above its cutoff" do
    owner = owner()
    ready(owner)
    first = open(owner)
    second = open(owner)
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(7, 0, 0, <<first::32, 11::32>>))
    assert_receive {:http2, ^first, {:http2, :goaway, ^first, 11}}
    assert_receive {:http2, ^second, {:http2, :stream_error, {:goaway, ^first, 11, :unprocessed}}}
    assert {:error, :draining} = ConnectionOwner.open_stream(owner, [{":method", "GET"}])
    assert :ok = ConnectionOwner.receive_bytes(owner, wire(1, 5, first, <<0x88>>))
    assert_receive {:http2, ^first, {:http2, :headers, [{":status", "200"}], 5}}
  end

  test "legal early client HEADERS do not wait for peer SETTINGS" do
    owner = owner()
    assert 1 = open(owner)
    ready(owner)
  end

  test "asynchronous upload DATA write failure removes the owner from reuse" do
    parent = self()

    transport = %{
      send: fn _, bytes ->
        case IO.iodata_to_binary(bytes) do
          <<_length::24, 0, _::binary>> -> {:error, :timeout}
          _ -> :ok
        end
      end,
      close: fn _ ->
        send(parent, :closed)
        :ok
      end
    }

    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport, socket: :socket, activate?: false)

    monitor = Process.monitor(owner)

    assert {:ok, %{id: id}} =
             ConnectionOwner.open_stream(owner, [{":method", "POST"}], body_bridge: self())

    send(owner, {:body_chunk, self(), "payload", make_ref()})
    assert_receive {:http2, ^id, {:http2, :transport_error, :timeout}}
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    assert_receive :closed
  end

  test "CANCEL in the same batch wins over a pending final response delivery" do
    owner = owner()
    ready(owner)
    id = open(owner)
    frames = wire(1, 4, id, <<0x88>>) <> wire(0, 1, id, "done") <> wire(3, 0, id, <<8::32>>)
    assert :ok = ConnectionOwner.receive_bytes(owner, frames)
    assert_receive {:http2, ^id, {:http2, :reset, 8}}
    refute_receive {:http2, ^id, {:http2, :data, _, _}}
  end

  test "NO_ERROR following validated END_STREAM preserves the complete response" do
    owner = owner()
    ready(owner)
    id = open(owner)
    frames = wire(1, 4, id, <<0x88>>) <> wire(0, 1, id, "done") <> wire(3, 0, id, <<0::32>>)
    assert :ok = ConnectionOwner.receive_bytes(owner, frames)
    assert_receive {:http2, ^id, {:http2, :data, "done", 1}}
    refute_receive {:http2, ^id, {:http2, :reset, _}}
  end

  test "closed required DATA writes remain fatal" do
    transport = %{
      send: fn _, bytes ->
        case IO.iodata_to_binary(bytes) do
          <<_length::24, 0, _::binary>> -> {:error, :closed}
          _ -> :ok
        end
      end
    }

    {:ok, owner} = ConnectionOwner.start_link(transport: transport, activate?: false)
    monitor = Process.monitor(owner)

    assert {:ok, %{id: id}} =
             ConnectionOwner.open_stream(owner, [{":method", "POST"}], end_stream: false)

    assert {:error, :closed} = ConnectionOwner.send_data(owner, id, "required", true)
    assert_receive {:http2, ^id, {:http2, :transport_error, :closed}}
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
  end
end
