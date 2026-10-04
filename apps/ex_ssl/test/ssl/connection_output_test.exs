defmodule SSL.ConnectionOutputTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.{Connection, Options, Socket}

  @moduletag :integration

  test "termination cancels every retained timer and is safe after partial initialization" do
    {:ok, options} = Options.normalize("exssl.test", Peer.client_options())
    {:ok, deadline} = Options.deadline(60_000)
    status = :atomics.new(1, signed: false)
    {:ok, connection} = Connection.start_link({self(), make_ref(), status, options, deadline})
    {:handoff, initial} = :sys.get_state(connection)
    writer_monitor = Process.monitor(initial.writer)

    # No transport has been attached; termination must still cancel the
    # handshake deadline and release its writer and monitors.
    assert :ok = :sys.terminate(connection, :normal, 1_000)
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert Process.read_timer(initial.handshake_timer) == false

    timers = for _ <- 1..4, do: Process.send_after(self(), :unexpected_timer, 60_000)
    [handshake, output, recv, write] = timers
    monitors = for _ <- 1..3, do: Process.monitor(self())
    [owner_monitor, recv_monitor, write_monitor] = monitors

    state = %Connection.State{
      socket: initial.socket,
      owner_monitor: owner_monitor,
      handshake_timer: handshake,
      output: %{timer: output},
      recv: %{timer: recv, monitor: recv_monitor},
      write: %{timer: write, monitor: write_monitor}
    }

    on_exit(fn -> Enum.each(timers, &Process.cancel_timer/1) end)

    assert :ok = Connection.terminate(:test_failure, :connected, state)
    assert :ok = Connection.terminate(:test_failure, :connected, state)
    assert Enum.map(timers, &Process.read_timer/1) == [false, false, false, false]

    {:ok, tcp} = :gen_tcp.listen(0, active: false)
    assert true = Port.close(tcp)
    assert :ok = Connection.terminate(:test_failure, :connected, %{state | tcp: tcp})

    assert :ok =
             Connection.terminate(:test_failure, :handoff, %Connection.State{
               socket: initial.socket
             })
  end

  test "the handshake deadline cancels a ClientHello blocked in the connection writer" do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])

    {:ok, {_address, port}} = :inet.sockname(listener)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false, packet: :raw])
    {:ok, server} = :gen_tcp.accept(listener, 1_000)
    {:ok, options} = Options.normalize("exssl.test", Peer.client_options())
    {:ok, deadline} = Options.deadline(100)
    ref = make_ref()
    status = :atomics.new(1, signed: false)
    {:ok, connection} = Connection.start_link({self(), ref, status, options, deadline})
    socket = %Socket{pid: connection, ref: ref, status: status}

    on_exit(fn ->
      if Process.alive?(connection), do: Process.exit(connection, :kill)
      :gen_tcp.close(tcp)
      :gen_tcp.close(server)
      :gen_tcp.close(listener)
    end)

    {:handoff, state} = :sys.get_state(connection)
    assert is_pid(state.writer)
    writer_monitor = Process.monitor(state.writer)
    assert true = :erlang.suspend_process(state.writer)
    assert :ok = :gen_tcp.controlling_process(tcp, connection)

    attach =
      Task.async(fn ->
        :gen_statem.call(connection, {ref, {:attach, tcp}}, :infinity)
      end)

    assert {:error, :timeout} = :gen_tcp.recv(server, 0, 25)
    assert {:error, :timeout} = Task.await(attach, 1_000)
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert :econnreset = Socket.terminal_error(socket)
  end

  test "a fatal handshake alert is serialized by the writer before teardown" do
    parent = self()
    before = connection_children()

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])

    {:ok, {_address, port}} = :inet.sockname(listener)

    server =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 1_000)
        assert {:ok, _hello} = :gen_tcp.recv(tcp, 0, 1_000)
        send(parent, {:client_hello, tcp})

        receive do
          :send_invalid_record -> :ok
        end

        :ok = :gen_tcp.send(tcp, <<23, 3, 3, 65_535::16>>)
        result = :gen_tcp.recv(tcp, 7, 1_000)
        :gen_tcp.close(tcp)
        result
      end)

    connect =
      Task.async(fn ->
        result = SSL.connect(~c"127.0.0.1", port, Peer.client_options(), 2_000)
        send(parent, {:connect_result, result})

        receive do
          :finish -> result
        end
      end)

    assert_receive {:client_hello, _tcp}, 1_000
    assert [connection] = Enum.reject(connection_children(), &MapSet.member?(before, &1))
    {_phase, state} = :sys.get_state(connection)
    assert state.output == nil
    assert true = :erlang.suspend_process(state.writer)
    send(server.pid, :send_invalid_record)
    wait_for_output(connection, :fatal_alert)
    assert true = :erlang.resume_process(state.writer)

    assert_receive {:connect_result, {:error, {:tls_alert, {:record_overflow, _}}}}, 1_000
    assert {:ok, <<21, 3, 3, 0, 2, 2, 22>>} = Task.await(server, 1_000)
    send(connect.pid, :finish)
    assert {:error, {:tls_alert, {:record_overflow, _}}} = Task.await(connect, 1_000)
    :gen_tcp.close(listener)
  end

  defp wait_for_output(pid, kind, attempts \\ 200)
  defp wait_for_output(_pid, _kind, 0), do: flunk("expected writer output was not queued")

  defp wait_for_output(pid, kind, attempts) do
    case :sys.get_state(pid) do
      {_phase, %{output: %{kind: ^kind}}} ->
        :ok

      _state ->
        Process.sleep(1)
        wait_for_output(pid, kind, attempts - 1)
    end
  end

  defp connection_children do
    SSL.ConnectionSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.map(fn {_, pid, _, _} -> pid end)
    |> MapSet.new()
  end
end
