defmodule HTTP.HTTP2ActivationTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.ConnectionOwner

  @tag :p3_ex_ssl_h2_unit_red
  test "deferred activation is inert and duplicate activation initializes the wire once" do
    caller = self()

    transport = %{
      send: fn _, bytes ->
        send(caller, {:wire, IO.iodata_to_binary(bytes)})
        :ok
      end,
      setopts: fn _, options ->
        send(caller, {:setopts, options})
        :ok
      end,
      close: fn _ -> :ok end,
      normalize_message: fn _, _ -> :unknown end
    }

    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport, socket: :socket, activate?: false)

    assert %{wrote_preface?: false, lifecycle: :initializing} = ConnectionOwner.status(owner)
    refute_receive {:wire, _}, 0
    refute_receive {:setopts, _}, 0
    assert :ok = ConnectionOwner.activate(owner)
    assert_receive {:wire, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" <> _}
    assert_receive {:setopts, _}
    assert_receive {:setopts, [active: :once]}
    assert :ok = ConnectionOwner.activate(owner)
    refute_receive {:wire, _}, 0
    refute_receive {:setopts, _}, 0
    GenServer.stop(owner)
  end

  test "initial active-once failure is returned and closes the owner" do
    {:ok, owner} =
      ConnectionOwner.start_link(
        transport: transport(fn -> {:error, :einval} end),
        socket: :socket,
        activate?: false
      )

    monitor = Process.monitor(owner)

    assert {:error, :einval} = ConnectionOwner.activate(owner)
    assert_receive {:DOWN, ^monitor, :process, ^owner, _reason}
  end

  test "rearm failure terminates the owner and reports one terminal error" do
    calls = :atomics.new(1, [])

    transport =
      transport(fn ->
        if :atomics.add_get(calls, 1, 1) == 1, do: :ok, else: {:error, :einval}
      end)

    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport, socket: :socket, activate?: false)

    assert :ok = ConnectionOwner.activate(owner)

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, [{":method", "GET"}], subscriber: self())

    monitor = Process.monitor(owner)

    send(owner, {:test_data, <<0::24, 4, 0, 0::32>>})
    assert_receive {:http2, 1, {:http2, :transport_error, :einval}}
    assert_receive {:DOWN, ^monitor, :process, ^owner, _reason}
    refute_receive {:http2, 1, {:http2, :transport_error, :einval}}, 0
  end

  for terminal <- [:deadline, :caller_death] do
    test "queued activation after #{terminal} remains inert" do
      caller = self()

      transport = %{
        send: fn _, bytes ->
          send(caller, {:wire, bytes})
          :ok
        end,
        setopts: fn _, options ->
          send(caller, {:setopts, options})
          :ok
        end,
        close: fn _ ->
          send(caller, :transport_closed)
          :ok
        end,
        normalize_message: fn _, _ -> :unknown end
      }

      owner =
        start_supervised!(
          {ConnectionOwner, transport: transport, socket: :socket, activate?: false}
        )

      assert %{wrote_preface?: false} = ConnectionOwner.status(owner)
      :sys.suspend(owner)
      timeout = if unquote(terminal) == :deadline, do: 30, else: 1_000
      deadline = System.monotonic_time(:millisecond) + timeout

      {worker, down} =
        spawn_monitor(fn ->
          result = ConnectionOwner.activate(owner, deadline)
          send(caller, {:activation_result, result})
        end)

      wait_activation(owner)
      if unquote(terminal) == :caller_death, do: Process.exit(worker, :kill)
      assert_receive {:DOWN, ^down, :process, ^worker, _}, 1_000
      :sys.resume(owner)
      assert %{wrote_preface?: false} = ConnectionOwner.status(owner)
      refute_receive {:wire, _}, 0
      refute_receive {:setopts, _}, 0
      GenServer.stop(owner)
      refute_receive :transport_closed, 0
    end
  end

  for terminal <- [:deadline, :caller_death] do
    @tag :p3_activation_after_setup
    test "activation blocked in setopts rechecks #{terminal} before its preface" do
      caller = self()

      transport = %{
        send: fn _, bytes ->
          send(caller, {:late_wire, bytes})
          :ok
        end,
        setopts: fn _, options ->
          if Keyword.has_key?(options, :send_timeout) do
            send(caller, {:activation_setup, self()})
            receive do: (:release_setup -> :ok)
          else
            send(caller, {:late_active, options})
            :ok
          end
        end,
        close: fn _ ->
          send(caller, :late_transport_closed)
          :ok
        end,
        normalize_message: fn _, _ -> :unknown end
      }

      owner =
        start_supervised!(
          Supervisor.child_spec(
            {ConnectionOwner, transport: transport, socket: :socket, activate?: false},
            restart: :temporary
          )
        )

      deadline =
        System.monotonic_time(:millisecond) +
          if(unquote(terminal) == :deadline, do: 30, else: 1_000)

      {worker, down} = spawn_monitor(fn -> ConnectionOwner.activate(owner, deadline) end)
      assert_receive {:activation_setup, ^owner}, 1_000
      if unquote(terminal) == :caller_death, do: Process.exit(worker, :kill)
      assert_receive {:DOWN, ^down, :process, ^worker, _}, 1_000
      send(owner, :release_setup)
      refute_receive {:late_wire, _}, 100
      refute_receive {:late_active, _}, 0
      stop_supervised(ConnectionOwner)
      refute_receive :late_transport_closed, 0
    end
  end

  defp wait_activation(owner, remaining \\ 1_000)
  defp wait_activation(_owner, 0), do: flunk("activation did not queue")

  defp wait_activation(owner, remaining) do
    {:messages, messages} = Process.info(owner, :messages)

    unless Enum.any?(messages, &match?({:"$gen_call", _, {:activate, _}}, &1)) do
      receive do
      after
        1 -> wait_activation(owner, remaining - 1)
      end
    end
  end

  defp transport(on_active) do
    %{
      send: fn _, _ -> :ok end,
      close: fn _ -> :ok end,
      setopts: fn _, opts ->
        if Keyword.get(opts, :active) == :once, do: on_active.(), else: :ok
      end,
      normalize_message: fn
        {:test_data, data}, :socket -> {:data, data}
        _, _ -> :unknown
      end
    }
  end
end
