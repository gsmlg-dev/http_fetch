defmodule Quic.Phase1APIRegressionTest do
  use ExUnit.Case, async: true

  alias Quic.Runtime.{ConnectionHandle, StreamHandle}

  test "public query calls return closed instead of exiting for a retired handle" do
    pid = spawn(fn -> :ok end)
    ref = Process.monitor(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}
    handle = %ConnectionHandle{id: pid, generation: make_ref()}
    stream = %StreamHandle{connection: handle, id: 0}

    assert {:error, :closed} = Quic.ready(handle)
    assert {:error, :closed} = Quic.info(handle)
    assert {:error, :closed} = Quic.events(handle)
    assert {:error, :closed} = Quic.read(stream, 1)
    assert {:error, :closed} = Quic.operation_status(handle, make_ref())
  end

  test "reset and stop expose operation options and preserve their references" do
    pid = spawn(fn -> :ok end)
    ref = Process.monitor(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}
    connection = %ConnectionHandle{id: pid, generation: make_ref()}
    stream = %StreamHandle{connection: connection, id: 0}
    ref = make_ref()

    assert {:error, :closed} = Quic.reset_stream(stream, 7, ref: ref, timeout: 1, deadline: 0)
    assert {:error, :closed} = Quic.stop_stream(stream, 7, ref: ref, timeout: 1, deadline: 0)
  end

  test "endpoint connect and accept expose timeout references for status resolution" do
    {:ok, client} = Quic.client([])
    {:ok, server} = Quic.listen([])

    on_exit(fn ->
      for pid <- [client, server], Process.alive?(pid), do: GenServer.stop(pid)
    end)

    connect_ref = make_ref()
    :sys.suspend(client)

    assert {:unknown, ^connect_ref} =
             Quic.connect(client, {{127, 0, 0, 1}, 4433},
               ref: connect_ref,
               timeout: 1,
               deadline: 0
             )

    :sys.resume(client)

    assert %{status: :rejected, result: {:error, :deadline_expired}} =
             Quic.operation_status(client, connect_ref)

    accept_ref = make_ref()
    :sys.suspend(server)

    assert {:unknown, ^accept_ref} =
             Quic.accept(server, ref: accept_ref, timeout: 1, deadline: 0)

    :sys.resume(server)

    assert %{status: :rejected, result: {:error, :deadline_expired}} =
             Quic.operation_status(server, accept_ref)
  end

  test "public limits reject zero and an attached consumer controls transfer" do
    previous = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous) end)

    assert {:error, :invalid_endpoint_options} = Quic.listen(event_limit: 0)
    assert {:error, :invalid_endpoint_options} = Quic.client(operation_limit: 0)

    {:ok, connection} =
      Quic.Connection.start_link(
        role: :client,
        io: {__MODULE__.Writer, self()},
        remote: {{127, 0, 0, 1}, 4433},
        handshake_timeout: 1_000,
        scheduler: [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: __MODULE__.TLS]
      )

    on_exit(fn -> if Process.alive?(connection), do: Quic.Connection.close(connection) end)

    handle = %ConnectionHandle{
      id: connection,
      generation: Quic.Connection.status(connection).generation
    }

    :ok = Quic.attach(handle, self())

    task = Task.async(fn -> Quic.attach(handle, self()) end)
    assert {:error, :not_consumer} = Task.await(task)
    assert Process.alive?(connection)
  end

  test "process failure during a call reports unknown mutation outcome" do
    doomed = fn ->
      spawn(fn ->
        receive do
          _ -> exit(:failed_during_call)
        end
      end)
    end

    pid = doomed.()
    handle = %ConnectionHandle{id: pid, generation: make_ref()}
    ref = make_ref()

    assert {:unknown, ^ref} =
             Quic.send_stream(%StreamHandle{connection: handle, id: 0}, "x", false, ref: ref)

    pid = doomed.()
    handle = %{handle | id: pid}
    ref = make_ref()
    assert {:unknown, ^ref} = Quic.read(%StreamHandle{connection: handle, id: 0}, 1, ref: ref)
    pid = doomed.()
    ref = make_ref()
    assert {:unknown, ^ref} = Quic.connect(pid, {{127, 0, 0, 1}, 443}, ref: ref)
  end

  defmodule TLS do
    def new(_, _), do: {:ok, 0, [{:emit, :initial, <<1, 2>>}]}
    def info(_), do: %{receive_level: :initial}
    def feed(state, :initial, _), do: {:ok, state + 1, []}
    def abort(state, _), do: state
  end

  defmodule Writer do
    def send(_, _, _), do: {:ok, System.monotonic_time(:microsecond)}
    def monotonic_time, do: System.monotonic_time(:microsecond)
  end
end
