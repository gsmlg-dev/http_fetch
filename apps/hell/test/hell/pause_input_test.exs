defmodule Hell.PauseInputTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  @certfile Path.expand("../support/cert.pem", __DIR__)
  @keyfile Path.expand("../support/key.pem", __DIR__)
  @cacertfile Path.expand("../support/ca.pem", __DIR__)

  @chunk_size 16 * 1024
  @read_timeout 300

  defmodule Handler do
    use Hell.Handler

    @impl Hell.Handler
    def handle_connection(_socket, parent) do
      send(parent, {:connected, self()})
      {:continue, %{parent: parent, paused: false, pause_next: false}}
    end

    @impl Hell.Handler
    def handle_data(data, _socket, state) do
      if state.paused, do: send(state.parent, {:violation, byte_size(data)})
      send(state.parent, {:data, data})

      if state.pause_next do
        {:pause, %{state | paused: true, pause_next: false}, {:continue, :paused_by_result}}
      else
        {:continue, state}
      end
    end

    @impl GenServer
    def handle_continue(:paused_by_result, {socket, state}) do
      send(state.parent, :paused)
      {:noreply, {socket, state}}
    end

    @impl GenServer
    def handle_info(:pause, {socket, state}) do
      socket = Hell.Handler.pause_input(socket)
      send(state.parent, :paused)
      {:noreply, {socket, %{state | paused: true}}}
    end

    # Reproduces the race from a pause requested while a chunk is already in the mailbox
    def handle_info(:pause_with_queued_chunk, {socket, state}) do
      await_queued_chunk(socket.socket)
      handle_info(:pause, {socket, state})
    end

    def handle_info(:pause_next, {socket, state}) do
      {:noreply, {socket, %{state | pause_next: true}}}
    end

    def handle_info(:resume, {socket, state}) do
      retained = length(socket.paused_input)
      socket = Hell.Handler.resume_input(socket)
      send(state.parent, {:resumed, retained})
      {:noreply, {socket, %{state | paused: false}}}
    end

    def handle_info({:set_read_timeout, timeout}, {socket, state}) do
      {:noreply, {Hell.Handler.set_read_timeout(socket, timeout), state}}
    end

    defp await_queued_chunk(raw_socket) do
      {:messages, messages} = Process.info(self(), :messages)

      unless Enum.any?(messages, &match?({tag, ^raw_socket, _} when tag in [:tcp, :ssl], &1)) do
        Process.sleep(1)
        await_queued_chunk(raw_socket)
      end
    end
  end

  for {transport, client} <- [{Hell.Transports.TCP, :gen_tcp}, {Hell.Transports.SSL, :ssl}] do
    describe "#{inspect(transport)}" do
      test "pause stops handle_data and resume delivers every byte once, in order" do
        {handler, sender} = start_stream(unquote(transport), unquote(client))
        ref = Process.monitor(handler)

        # Pause from handle_info while the client streams; no handle_data call may follow
        received = await_bytes(<<>>, 4 * @chunk_size)
        send(handler, :pause)
        received = await_paused(received)

        for _window <- 1..3 do
          refute_receive {:data, _}, 2 * @read_timeout
          assert Process.alive?(handler)
        end

        # Many mid-stream toggles: handle_info pauses (with and without a chunk already queued
        # in the handler's mailbox) and `{:pause, ...}` results
        pauses = [:pause_with_queued_chunk, :pause, :pause_next]

        {received, retained} =
          Enum.reduce(1..42, {received, 0}, fn toggle, {received, retained} ->
            send(handler, :resume)
            assert_receive {:resumed, count}, 5_000
            received = await_bytes(received, byte_size(received) + 1)
            send(handler, Enum.at(pauses, rem(toggle, 3)))
            received = await_paused(received)
            refute_receive {:data, _}, 20
            {received, retained + count}
          end)

        assert retained > 0

        send(handler, :resume)
        assert_receive {:resumed, _count}, 5_000
        _received = await_complete_stream(received, sender)
        refute_received {:violation, _}

        # The persistent read-idle timeout is restored after resume
        assert_receive {:DOWN, ^ref, :process, ^handler, {:shutdown, :read_timeout}},
                       10 * @read_timeout
      end

      test "a paused connection outlives its read timeout and records new timeouts" do
        {handler, sender} = start_stream(unquote(transport), unquote(client))
        ref = Process.monitor(handler)

        received = await_bytes(<<>>, @chunk_size)
        send(handler, :pause)
        received = await_paused(received)
        send(handler, {:set_read_timeout, 150})
        refute_receive {:DOWN, ^ref, _, _, _}, 4 * @read_timeout

        send(handler, :resume)
        assert_receive {:resumed, _count}, 5_000
        _received = await_complete_stream(received, sender)

        # The value set while paused applies once the stream goes idle
        assert_receive {:DOWN, ^ref, :process, ^handler, {:shutdown, :read_timeout}},
                       2 * @read_timeout
      end
    end
  end

  defp start_stream(transport, client_module) do
    tls_options = [certfile: @certfile, keyfile: @keyfile]

    {:ok, server} =
      start_supervised(
        {Hell,
         port: 0,
         num_acceptors: 1,
         read_timeout: @read_timeout,
         transport_module: transport,
         transport_options: if(transport == Hell.Transports.SSL, do: tls_options, else: []),
         handler_module: Handler,
         handler_options: self()}
      )

    {:ok, {_address, port}} = Hell.listener_info(server)

    client_options =
      if client_module == :ssl,
        do: [:binary, active: false, verify: :verify_peer, cacertfile: @cacertfile],
        else: [:binary, active: false]

    {:ok, client} = client_module.connect(~c"localhost", port, client_options, 5_000)
    {:ok, sender} = Task.start(fn -> stream(client_module, client) end)
    :ok = client_module.controlling_process(client, sender)
    send(sender, :go)

    on_exit(fn ->
      Process.exit(sender, :kill)
      client_module.close(client)
    end)

    assert_receive {:connected, handler}, 5_000
    {handler, sender}
  end

  defp stream(client_module, client) do
    receive do
      :go -> :ok
    end

    stream(client_module, client, 0)
  end

  # Streams continuously until asked to stop, then keeps the connection open (and idle) until
  # the server times it out
  defp stream(client_module, client, index) do
    receive do
      {:stop, test} ->
        send(test, {:sent, index})
        Process.sleep(:infinity)
    after
      0 ->
        :ok = client_module.send(client, chunk(index))
        stream(client_module, client, index + 1)
    end
  end

  defp chunk(index), do: :binary.copy(<<index::32>>, div(@chunk_size, 4))

  defp await_complete_stream(received, sender) do
    send(sender, {:stop, self()})
    assert_receive {:sent, chunks}, 5_000
    received = await_bytes(received, chunks * @chunk_size)

    assert byte_size(received) == chunks * @chunk_size
    assert received == Enum.map_join(0..(chunks - 1), &chunk/1)
    received
  end

  defp await_bytes(received, wanted) when byte_size(received) >= wanted, do: received

  defp await_bytes(received, wanted) do
    assert_receive {:data, data}, 5_000
    await_bytes(received <> data, wanted)
  end

  # Data sent before the pause acknowledgement is legitimate; nothing may follow it
  defp await_paused(received) do
    receive do
      {:data, data} -> await_paused(received <> data)
      :paused -> received
    after
      5_000 -> flunk("handler did not pause")
    end
  end
end
