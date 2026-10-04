defmodule Quic.Phase1PublicTest do
  use ExUnit.Case, async: true
  alias Quic.Endpoint
  alias Quic.Runtime.StreamHandle

  def credentials do
    fixture = Path.expand("../fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-phase1"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-phase1"]
     ]}
  end

  test "public accept and attach order readiness before bounded pull stream data" do
    {server_tls, client_tls} = credentials()

    {:ok, server} =
      Quic.listen(tls: server_tls, streams: [max_data: 32_768, max_stream_data: 16_384])

    {:ok, client} = Quic.client(tls: client_tls)
    on_exit(fn -> for pid <- [server, client], Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, connection} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, metadata}, 2000
    assert metadata.alpn == "ex-quic-phase1"
    assert metadata.local == Endpoint.local(client)
    assert metadata.remote == Endpoint.local(server)
    assert metadata.peer_authenticated
    assert_receive {:quic_accept, ^server}, 2000
    {:ok, accepted} = Quic.accept(server)
    assert Quic.ready(accepted) == :ready
    {:ok, stream} = Quic.open_stream(connection, :bidi)
    {:ok, _ref} = Quic.send_stream(stream, "abcdef", true)

    assert eventually(fn ->
             {:ok, i} = Quic.info(accepted)
             i.resources.ready_bytes == 6
           end)

    assert {:error, :not_consumer} = Quic.events(accepted)
    :ok = Quic.attach(accepted, self())
    assert_receive {:quic_ready, ^accepted, _}, 1000
    {:ok, [ready | events]} = Quic.events(accepted)
    assert match?({:ready, _}, ready)
    assert {:stream_open, %StreamHandle{connection: accepted, id: 0}, :bidi} in events
    incoming = %StreamHandle{connection: accepted, id: 0}
    assert {:ok, [{:data, 0, "ab"}]} = Quic.read(incoming, 2)
    assert {:ok, [{:data, 0, "cdef"}, {:fin, 0}]} = Quic.read(incoming, 4)
    {:ok, info} = Quic.info(accepted)
    assert info.resources.ready_bytes == 0
    assert info.resources.event_count <= 128
    assert {:error, :stale_handle} = Quic.events(%{accepted | generation: make_ref()})
    refute_receive {:quic_stream, _, _, _}, 20
  end

  test "operation deadlines, deduplication, reset and application close are explicit" do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen(tls: server_tls)
    {:ok, client} = Quic.client(tls: client_tls)
    on_exit(fn -> for pid <- [server, client], Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, connection} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2000
    {:ok, stream} = Quic.open_stream(connection, :bidi)
    ref = make_ref()
    :sys.suspend(connection.id)

    assert {:unknown, ^ref} =
             Quic.send_stream(stream, "expired", false, ref: ref, timeout: 1, deadline: 0)

    :sys.resume(connection.id)

    assert %{status: :rejected, result: {:error, :deadline_expired}} =
             Quic.operation_status(connection, ref)

    ref2 = make_ref()
    assert {:ok, ^ref2} = Quic.send_stream(stream, "once", false, ref: ref2)
    assert {:ok, ^ref2} = Quic.send_stream(stream, "once", false, ref: ref2)
    assert {:error, :operation_ref_conflict} = Quic.send_stream(stream, "twice", false, ref: ref2)
    assert {:ok, _} = Quic.reset_stream(stream, 7)
    assert {:ok, other} = Quic.open_stream(connection, :bidi)
    assert {:ok, _} = Quic.send_stream(other, "still works")
    assert :ok = Quic.close(connection, 37, <<255>>)
  end

  test "late local-send completion resolves an admitted timeout and consumer death cleans routes" do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen(tls: server_tls)
    {:ok, client} = Quic.client(tls: client_tls)
    on_exit(fn -> for pid <- [server, client], Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, connection} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2000
    assert_receive {:quic_accept, ^server}, 2000
    {:ok, accepted} = Quic.accept(server)
    {:ok, stream} = Quic.open_stream(connection, :bidi)
    {:established, runtime} = :sys.get_state(connection.id)
    :sys.suspend(runtime.writer)
    ref = make_ref()

    assert {:unknown, ^ref} =
             Quic.send_stream(stream, "admitted", false, ref: ref, timeout: 1, deadline: 5000)

    :sys.resume(runtime.writer)
    assert %{status: :admitted, result: {:ok, ^ref}} = Quic.operation_status(connection, ref)
    parent = self()

    consumer =
      spawn(fn ->
        :ok = Quic.attach(accepted, self())
        send(parent, :attached)

        receive do
          :stop -> :ok
        end
      end)

    assert_receive :attached
    monitor = Process.monitor(accepted.id)
    send(consumer, :stop)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1000
    assert eventually(fn -> Endpoint.stats(server).routes == 0 end)
    assert Process.alive?(server)

    for _ <- 1..270,
        do: assert({:error, :unknown_stream} = Quic.send_stream(%{stream | id: 999}, "x"))

    {:ok, info} = Quic.info(connection)
    assert info.resources.operations == 256
  end

  test "a timed-out destructive read resolves to the exact consumed bytes" do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen(tls: server_tls)
    {:ok, client} = Quic.client(tls: client_tls)
    on_exit(fn -> for pid <- [server, client], Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, connection} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2000
    assert_receive {:quic_accept, ^server}, 2000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    {:ok, stream} = Quic.open_stream(connection, :bidi)
    {:ok, _} = Quic.send_stream(stream, "abcdef", true)

    assert eventually(fn ->
             {:ok, metadata} = Quic.info(accepted)
             metadata.resources.ready_bytes == 6
           end)

    incoming = %StreamHandle{connection: accepted, id: stream.id}
    {:established, runtime} = :sys.get_state(accepted.id)
    :sys.suspend(runtime.writer)
    ref = make_ref()
    assert {:unknown, ^ref} = Quic.read(incoming, 3, ref: ref, timeout: 1, deadline: 5000)
    :sys.resume(runtime.writer)

    assert %{status: :completed, result: {:ok, [{:data, 0, "abc"}]}} =
             Quic.operation_status(accepted, ref)

    assert {:ok, [{:data, 0, "abc"}]} = Quic.read(incoming, 3, ref: ref)
    assert {:ok, [{:data, 0, "def"}, {:fin, 0}]} = Quic.read(incoming, 3)
  end

  test "peer ACKs notify the consumer that bounded send capacity may be writable" do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen(tls: server_tls)
    {:ok, client} = Quic.client(tls: client_tls)
    on_exit(fn -> for pid <- [server, client], Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, connection} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2000
    {:ok, _} = Quic.events(connection)
    {:ok, stream} = Quic.open_stream(connection, :bidi)
    {:ok, _} = Quic.send_stream(stream, "capacity")

    assert eventually(fn ->
             {:ok, events} = Quic.events(connection)
             :writable in events
           end)
  end

  defp eventually(fun, n \\ 200)
  defp eventually(_, 0), do: false

  defp eventually(fun, n),
    do:
      if(fun.(),
        do: true,
        else:
          (
            Process.sleep(5)
            eventually(fun, n - 1)
          )
      )
end
