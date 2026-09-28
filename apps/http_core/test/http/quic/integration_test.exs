defmodule HTTP.QUIC.IntegrationTest do
  use ExUnit.Case, async: false

  alias HTTP.QUIC.ExQuic, as: Adapter

  @moduletag :quic_integration
  @moduletag timeout: 30_000

  @fixtures Path.expand("../../../../http_fetch/test/support/fixtures", __DIR__)
  @alpn "ex-quic-phase1"
  @chunk 16_384

  @moduletag skip: System.get_env("HTTP_QUIC_PHASE1_REAL") != "1"
  test "adapter carries bounded raw streams over a standalone ex_quic endpoint" do
    {:ok, server} = QUIC.listen(tls: server_tls(), streams: stream_limits())
    on_exit(fn -> stop(server) end)

    {:ok, client} = Adapter.client("localhost", client_tls(), streams: stream_limits())
    on_exit(fn -> stop(client) end)

    remote = Adapter.local(server)
    {:ok, client_connection} = Adapter.connect(client, remote, deadline: 5_000)
    :ok = Adapter.attach(client_connection, self())

    server_connection = accept_and_attach(server)
    await_ready(client_connection)
    await_ready(server_connection)

    bidi = for _ <- 1..4, do: open_stream!(client_connection, :bidi)
    uni = for _ <- 1..2, do: open_stream!(client_connection, :uni)
    {:ok, cancelled} = Adapter.open_stream(client_connection, :bidi)
    expired = make_ref()

    assert {:error, :deadline_expired} =
             Adapter.open_stream(client_connection, :bidi, ref: expired, deadline: -1)

    assert %{status: :rejected, result: {:error, :deadline_expired}} =
             Adapter.operation_status(client_connection, expired)

    # Four 256 KiB bidi streams and two 16 KiB unidirectional writes exceed the
    # Phase-1 cumulative-transfer threshold without changing the engine limit.
    expected =
      for sequence <- 0..63, into: <<>> do
        :binary.copy(<<sequence>>, 4_096)
      end

    state =
      Enum.reduce(
        bidi,
        %{
          streams: %{},
          bytes: %{},
          fins: MapSet.new(),
          resets: MapSet.new(),
          stopped: MapSet.new()
        },
        fn stream, state ->
          send_all(stream, expected, server_connection, state)
        end
      )

    state =
      Enum.reduce(uni, state, &send_all(&1, :binary.copy("u", @chunk), server_connection, &2))

    state = send_all(cancelled, "cancel", server_connection, state, false)
    assert {:ok, _ref} = Adapter.reset_stream(cancelled, 0x51, deadline: 5_000)
    assert {:ok, _ref} = Adapter.stop_stream(cancelled, 0x52, deadline: 5_000)

    survivor = open_stream!(client_connection, :bidi)
    state = send_all(survivor, "after cancellation", server_connection, state)

    state =
      collect(server_connection, state, 4 * byte_size(expected) + 2 * @chunk + 18, deadline())

    assert state.bytes[survivor.id] == "after cancellation"
    assert MapSet.member?(state.fins, survivor.id)
    assert MapSet.member?(state.stopped, cancelled.id)

    assert Enum.all?(
             bidi,
             &(state.bytes[&1.id] == expected and MapSet.member?(state.fins, &1.id))
           )

    assert Enum.all?(
             uni,
             &(state.bytes[&1.id] == :binary.copy("u", @chunk) and
                 MapSet.member?(state.fins, &1.id))
           )

    assert MapSet.member?(state.resets, cancelled.id)

    assert {:ok, info} = Adapter.info(client_connection)
    assert info.alpn == @alpn
    assert info.tls_complete

    assert :ok = Adapter.close(client_connection, 0, "phase1-test")
  end

  test "wrong CA, identity, and ALPN close without readiness" do
    Enum.each(
      [
        {:wrong_ca, [cacerts: :public_key.cacerts_get(), alpn: [@alpn]]},
        {:wrong_identity,
         [
           cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
           reference_identity: {:dns_id, "wrong.localhost"},
           alpn: [@alpn]
         ]},
        {:wrong_alpn,
         [cacertfile: Path.join(@fixtures, "localhost-ca.pem"), alpn: ["ex-quic-phase1-wrong"]]}
      ],
      fn {scenario, tls} ->
        {:ok, server} = QUIC.listen(tls: server_tls(), streams: stream_limits())
        on_exit(fn -> stop(server) end)
        {:ok, client} = Adapter.client("localhost", tls, streams: stream_limits())
        on_exit(fn -> stop(client) end)
        {:ok, connection} = Adapter.connect(client, Adapter.local(server), deadline: 2_000)
        :ok = Adapter.attach(connection, self())

        receive do
          {:quic_closed, ^connection, _reason} -> :ok
          {:quic_ready, ^connection, _metadata} -> flunk("#{scenario} handshake became ready")
        after
          12_000 -> flunk("#{scenario} did not terminate within the handshake deadline")
        end
      end
    )
  end

  test "consumer death removes its endpoint and invalidates the connection handle" do
    {:ok, server} = QUIC.listen(tls: server_tls(), streams: stream_limits())
    on_exit(fn -> stop(server) end)
    remote = Adapter.local(server)
    parent = self()

    {owner, owner_ref} =
      spawn_monitor(fn ->
        {:ok, endpoint} = Adapter.client("localhost", client_tls(), streams: stream_limits())
        {:ok, connection} = Adapter.connect(endpoint, remote)
        :ok = Adapter.attach(connection, self())
        await_ready(connection)
        send(parent, {:owned, self(), endpoint, connection})

        receive do
          :finish -> :ok
        after
          5_000 -> exit(:test_barrier_timeout)
        end
      end)

    server_connection = accept_and_attach(server)
    await_ready(server_connection)
    assert_receive {:owned, ^owner, endpoint, connection}, 5_000
    endpoint_ref = Process.monitor(endpoint)
    send(owner, :finish)
    assert_receive {:DOWN, ^owner_ref, :process, ^owner, :normal}, 5_000
    assert_receive {:DOWN, ^endpoint_ref, :process, ^endpoint, _reason}, 5_000
    refute Process.alive?(endpoint)
    assert {:error, :closed} = Adapter.ready(connection)
  end

  defp accept_and_attach(endpoint) do
    receive do
      {:quic_accept, ^endpoint} ->
        assert {:ok, connection} = QUIC.accept(endpoint)
        assert :ok = Adapter.attach(connection, self())
        connection
    after
      5_000 -> flunk("standalone endpoint did not accept the adapter connection")
    end
  end

  defp open_stream!(connection, kind) do
    assert {:ok, stream} = Adapter.open_stream(connection, kind)
    stream
  end

  defp await_ready(connection) do
    receive do
      {:quic_ready, ^connection, %{alpn: @alpn}} -> :ok
    after
      5_000 -> flunk("connection did not become ready")
    end
  end

  defp send_all(stream, bytes, connection, state, fin \\ true),
    do: send_all(stream, bytes, connection, state, fin, deadline())

  defp send_all(_stream, <<>>, _connection, state, _fin, _deadline), do: state

  defp send_all(stream, bytes, connection, state, fin, deadline) do
    size = min(@chunk, byte_size(bytes))
    <<chunk::binary-size(size), rest::binary>> = bytes

    case Adapter.send_stream(stream, chunk, fin and rest == <<>>, deadline: 1_000) do
      {:ok, _ref} ->
        send_all(stream, rest, connection, drain(connection, state), fin, deadline)

      {:blocked, _reason} ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(5)
          send_all(stream, bytes, connection, drain(connection, state), fin, deadline)
        else
          flunk("write remained blocked after bounded peer consumption")
        end

      {:unknown, ref} ->
        flunk("write admission is unknown; refusing retry #{inspect(ref)}")

      other ->
        flunk("unexpected write result: #{inspect(other)}")
    end
  end

  defp collect(connection, state, expected_bytes, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      flunk("timed out after receiving #{received_bytes(state)} bytes")
    end

    state = drain(connection, state)

    if received_bytes(state) >= expected_bytes and MapSet.size(state.fins) == 7 and
         MapSet.size(state.resets) == 1 and MapSet.size(state.stopped) == 1,
       do: state,
       else:
         (
           Process.sleep(5)
           collect(connection, state, expected_bytes, deadline)
         )
  end

  defp drain(connection, state) do
    assert {:ok, events} = Adapter.events(connection, 32, deadline: 1_000)

    state =
      Enum.reduce(events, state, fn
        {:stopped, stream, 0x52}, acc -> update_in(acc.stopped, &MapSet.put(&1, stream.id))
        _event, acc -> acc
      end)

    streams =
      Enum.reduce(events, state.streams, fn
        {:stream_open, stream, _kind}, acc -> Map.put(acc, stream.id, stream)
        _, acc -> acc
      end)

    bytes =
      Enum.reduce(streams, state, fn {_id, stream}, state ->
        case Adapter.read(stream, 1_024, deadline: 1_000) do
          {:ok, items} ->
            Enum.reduce(items, state, &record_item/2)

          {:error, :would_block} ->
            state

          other ->
            flunk("unexpected bounded read result: #{inspect(other)}")
        end
      end)

    %{bytes | streams: streams}
  end

  defp record_item({:data, id, data}, result),
    do: update_in(result.bytes[id], fn value -> (value || <<>>) <> data end)

  defp record_item({:fin, id}, result), do: update_in(result.fins, &MapSet.put(&1, id))

  defp record_item({:reset, id, 0x51, _size}, result),
    do: update_in(result.resets, &MapSet.put(&1, id))

  defp received_bytes(state), do: state.bytes |> Map.values() |> Enum.sum_by(&byte_size/1)

  defp server_tls do
    [{key_type, key, :not_encrypted}] =
      @fixtures |> Path.join("localhost.key") |> File.read!() |> :public_key.pem_decode()

    cert =
      @fixtures
      |> Path.join("localhost.pem")
      |> File.read!()
      |> :public_key.pem_decode()
      |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)

    [cert: cert, key: {key_type, key}, alpn: [@alpn]]
  end

  defp client_tls, do: [cacertfile: Path.join(@fixtures, "localhost-ca.pem"), alpn: [@alpn]]

  defp stream_limits,
    do: [max_data: 16_384, max_stream_data: 16_384, max_buffer: 65_536, max_ready_bytes: 16_384]

  defp deadline, do: System.monotonic_time(:millisecond) + 15_000

  defp stop(endpoint) when is_pid(endpoint) do
    monitor = Process.monitor(endpoint)
    if Process.alive?(endpoint), do: Adapter.stop_endpoint(endpoint)
    assert_receive {:DOWN, ^monitor, :process, ^endpoint, _reason}, 5_000
  catch
    :exit, {:noproc, _call} -> :ok
  end
end
