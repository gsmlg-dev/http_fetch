defmodule Hell.ReadTimeoutTransitionTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  defmodule Handler do
    use Hell.Handler

    def handle_connection(socket, parent) do
      send(parent, {:connected, self()})

      # Queue the initial owner operation before arming the short idle timer.
      receive do
        :start_reading -> {:continue, %{parent: parent, original_timeout: socket.read_timeout}}
      after
        1_000 -> raise "connection was not started"
      end
    end

    def handle_data(data, socket, state) do
      :ok = Hell.Socket.send(socket, data)
      {:continue, state}
    end

    def handle_call({:set_read_timeout, timeout}, _from, {socket, state}) do
      socket = Hell.Handler.set_read_timeout(socket, timeout)
      {:reply, :ok, {socket, state}}
    end

    def handle_call({:replace_expired_timer, timeout}, _from, {socket, state}) do
      {socket, stale_message} = replace_expired_timer(socket, timeout)
      {:reply, {stale_message, socket.read_timer}, {socket, state}}
    end

    def handle_call(:read_timer, _from, {socket, _state} = state) do
      {:reply, socket.read_timer, state}
    end

    def handle_call(:bounded_recv, _from, {socket, state}) do
      :ok = Hell.Socket.setopts(socket, active: false)
      result = Hell.Socket.recv(socket, 0, 25)
      :ok = Hell.Socket.setopts(socket, active: :once)
      {:reply, result, {socket, state}}
    end

    def handle_call(:send_timeout, _from, {socket, _state} = state) do
      {:reply, Hell.Socket.getopts(socket, [:send_timeout]), state}
    end

    def handle_call(:mailbox_timeout, _from, state), do: {:reply, :ok, state, 0}

    def handle_info({:set_read_timeout, timeout, reference}, {socket, state}) do
      socket = Hell.Handler.set_read_timeout(socket, timeout)
      send(state.parent, {:timeout_changed, reference})
      {:noreply, {socket, state}}
    end

    def handle_info({:replace_expired_timer, timeout, reference}, {socket, state}) do
      {socket, stale_message} = replace_expired_timer(socket, timeout)
      send(state.parent, {:timer_replaced, reference, stale_message, socket.read_timer})
      {:noreply, {socket, state}}
    end

    def handle_info({:application_deadline, reference}, {_socket, state} = owner_state) do
      send(state.parent, {:application_deadline, reference})
      {:noreply, owner_state}
    end

    def handle_info({:timeout, timer, :read_timeout}, {_socket, state} = owner_state) do
      send(state.parent, {:application_read_timeout, timer})
      {:noreply, owner_state}
    end

    def handle_info(:timeout, {_socket, state} = owner_state) do
      send(state.parent, :genserver_timeout)
      {:noreply, owner_state}
    end

    def handle_info(:restore_read_timeout, {socket, state}) do
      socket = Hell.Handler.set_read_timeout(socket, state.original_timeout)
      send(state.parent, :timeout_restored)
      {:noreply, {socket, state}}
    end

    def handle_timeout(_socket, state), do: send(state.parent, {:read_timeout, self()})

    defp replace_expired_timer(socket, timeout) do
      socket = Hell.Handler.set_read_timeout(socket, 0)
      timer = socket.read_timer

      # Hold the owner callback until the real timer has delivered, then leave
      # duplicate expired notifications queued while replacing its policy.
      receive do
        {:timeout, ^timer, :hell_read_timeout} = message ->
          send(self(), message)
          send(self(), message)
          {Hell.Handler.set_read_timeout(socket, timeout), message}
      after
        1_000 -> raise "read timer did not deliver"
      end
    end
  end

  for transport <- [:tcp, :tls], callback <- [:call, :info] do
    @transport transport
    @transition_callback callback

    test "#{transport} owner can disable and restore idle timeout from handle_#{callback}" do
      {client, socket, handler} = start_handler(@transport)
      change_timeout(handler, @transition_callback, :infinity)

      # Quiet wire time exceeds the original finite policy.
      assert client.recv(socket, 0, 100) == {:error, :timeout}
      assert :ok = client.send(socket, "echo")
      assert client.recv(socket, 4, 1_000) == {:ok, "echo"}
      assert client.recv(socket, 0, 100) == {:error, :timeout}

      assert GenServer.call(handler, :bounded_recv) == {:error, :timeout}
      assert GenServer.call(handler, :send_timeout) == {:ok, [send_timeout: 75]}
      assert GenServer.call(handler, :mailbox_timeout) == :ok
      assert_receive :genserver_timeout, 1_000
      reference = make_ref()
      _ = Process.send_after(handler, {:application_deadline, reference}, 0)
      assert_receive {:application_deadline, ^reference}, 1_000
      application_timer = :erlang.start_timer(0, handler, :read_timeout)
      assert_receive {:application_read_timeout, ^application_timer}, 1_000

      monitor = Process.monitor(handler)
      send(handler, :restore_read_timeout)
      assert_receive :timeout_restored, 1_000
      assert client.recv(socket, 0, 2_000) == {:error, :closed}
      assert_receive {:read_timeout, ^handler}, 1_000
      assert_receive {:DOWN, ^monitor, :process, ^handler, {:shutdown, :read_timeout}}, 1_000
    end
  end

  for callback <- [:call, :info], timeout <- [:infinity, 1_000] do
    @transition_callback callback
    @replacement_timeout timeout

    test "handle_#{callback} invalidates queued and late stale timers when replacing with #{timeout}" do
      {client, socket, handler} = start_handler(:tcp, read_timeout: 5_000)
      send(handler, :start_reading)

      {stale_message, current_timer} =
        case @transition_callback do
          :call ->
            GenServer.call(handler, {:replace_expired_timer, @replacement_timeout})

          :info ->
            reference = make_ref()
            send(handler, {:replace_expired_timer, @replacement_timeout, reference})
            assert_receive {:timer_replaced, ^reference, stale_message, current_timer}, 1_000
            {stale_message, current_timer}
        end

      # These arrived after replacement. They must not re-arm or clear the new timer.
      send(handler, stale_message)
      send(handler, stale_message)
      assert GenServer.call(handler, :read_timer) == current_timer
      assert client.recv(socket, 0, 100) == {:error, :timeout}
      assert :ok = client.send(socket, "echo")
      assert client.recv(socket, 4, 1_000) == {:ok, "echo"}

      if @replacement_timeout == :infinity do
        assert current_timer == nil
      else
        assert is_reference(current_timer)
        assert client.recv(socket, 0, 2_000) == {:error, :closed}
        assert_receive {:read_timeout, ^handler}, 1_000
      end
    end
  end

  test "a finite transition can shorten the armed deadline" do
    {client, socket, handler} = start_handler(:tcp, read_timeout: 5_000)
    change_timeout(handler, :call, 0)
    assert client.recv(socket, 0, 1_000) == {:error, :closed}
    assert_receive {:read_timeout, ^handler}, 1_000
  end

  for transport <- [:tcp, :tls] do
    @transport transport

    test "#{transport} ordinary connections retain the configured idle timeout" do
      {client, socket, handler} = start_handler(@transport)
      send(handler, :start_reading)
      assert client.recv(socket, 0, 2_000) == {:error, :closed}
      assert_receive {:read_timeout, ^handler}, 1_000
    end
  end

  defp change_timeout(handler, :call, timeout) do
    request = :gen_server.send_request(handler, {:set_read_timeout, timeout})
    send(handler, :start_reading)
    assert :gen_server.receive_response(request, 1_000) == {:reply, :ok}
  end

  defp change_timeout(handler, :info, timeout) do
    reference = make_ref()
    send(handler, {:set_read_timeout, timeout, reference})
    send(handler, :start_reading)
    assert_receive {:timeout_changed, ^reference}, 1_000
  end

  defp start_handler(transport, options \\ []) do
    {client, client_options, server_options} =
      case transport do
        :tcp ->
          {:gen_tcp, [:binary, active: false], [transport_options: [send_timeout: 75]]}

        :tls ->
          {:ssl,
           [
             :binary,
             active: false,
             verify: :verify_peer,
             cacertfile: Path.expand("../support/ca.pem", __DIR__)
           ],
           [
             transport_module: Hell.Transports.SSL,
             transport_options: [
               send_timeout: 75,
               certfile: Path.expand("../support/cert.pem", __DIR__),
               keyfile: Path.expand("../support/key.pem", __DIR__)
             ]
           ]}
      end

    server =
      start_supervised!(
        {Hell,
         Keyword.merge(
           [
             port: 0,
             num_acceptors: 1,
             handler_module: Handler,
             handler_options: self(),
             read_timeout: 50
           ] ++ server_options,
           options
         )}
      )

    {:ok, {_ip, port}} = Hell.listener_info(server)
    {:ok, socket} = client.connect(~c"localhost", port, client_options, 1_000)
    on_exit(fn -> client.close(socket) end)
    assert_receive {:connected, handler}, 1_000
    {client, socket, handler}
  end
end
