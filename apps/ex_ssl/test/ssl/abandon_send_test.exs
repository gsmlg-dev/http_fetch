defmodule SSL.AbandonSendTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer

  @moduletag :integration
  @payload :binary.copy("x", 16 * 1_048_576)

  for abandon? <- [false, true] do
    test "explicit abandon=#{abandon?} preserves the default sender-death boundary" do
      parent = self()

      {:ok, peer} =
        Peer.start(fn socket ->
          send(parent, :peer_ready)

          receive do
            :respond ->
              assert :ok = :ssl.send(socket, "retained-response")
          end

          receive do
            :finish -> :ok
          end
        end)

      {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())

      on_exit(fn ->
        if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
        if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
        :ssl.close(peer.listener)
      end)

      options = [:binary | Keyword.merge(tl(Peer.client_options()), send_timeout: 5_000)]
      {:ok, socket} = SSL.connect(~c"127.0.0.1", proxy.port, options, 5_000)
      connection_monitor = Process.monitor(socket.pid)
      assert_receive :peer_ready, 5_000
      :ok = Peer.pause_client_to_server(proxy, self())
      proxy_ref = proxy.ref
      assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000

      {sender, sender_monitor} =
        spawn_monitor(fn -> send(parent, {:send_result, SSL.send(socket, @payload)}) end)

      state = pending_record(socket.pid, System.monotonic_time(:millisecond) + 2_000)
      assert state.output.size <= 16_406

      if unquote(abandon?) do
        assert :ok = SSL.abandon_send(socket)
        assert_receive {:send_result, {:error, :write_abandoned}}, 1_000
        assert_receive {:DOWN, ^sender_monitor, :process, ^sender, :normal}, 1_000
        {:connected, abandoned} = :sys.get_state(socket.pid)
        assert abandoned.write_abandoned?
        assert abandoned.write == nil
        assert abandoned.output == state.output
        assert Process.read_timer(state.write.timer) == false
        assert is_integer(Process.read_timer(state.output.timer))
        assert {:error, :closed} = SSL.send(socket, "must-never-write")
        outsider = Task.async(fn -> SSL.abandon_send(socket) end)
        assert {:error, :not_owner} = Task.await(outsider)
        send(peer.task.pid, :respond)
        assert {:ok, "retained-response"} = SSL.recv(socket, 0, 1_000)
        # No pending-record completion was needed to authenticate these bytes.
        {:connected, read_state} = :sys.get_state(socket.pid)
        assert read_state.output == state.output
        assert :ok = SSL.close(socket)
      else
        Process.exit(sender, :kill)
        assert_receive {:DOWN, ^sender_monitor, :process, ^sender, :killed}, 1_000
      end

      assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
      assert :erlang.port_info(state.tcp) == :undefined
      expected = if unquote(abandon?), do: :closed, else: :econnreset
      assert {:error, ^expected} = SSL.recv(socket, 0, 1_000)
    end
  end

  test "duplex admission is owner-only, idempotent and requires finite future sends" do
    {socket, _peer} = held_peer()
    outsider = Task.async(fn -> SSL.enable_duplex_reads(socket) end)
    assert {:error, :not_owner} = Task.await(outsider)
    assert :ok = SSL.setopts(socket, send_timeout: :infinity)
    assert {:error, :infinite_send_timeout} = SSL.enable_duplex_reads(socket)
    assert :ok = SSL.setopts(socket, send_timeout: 2_000)
    assert :ok = SSL.enable_duplex_reads(socket)
    assert :ok = SSL.enable_duplex_reads(socket)
    assert :ok = SSL.setopts(socket, send_timeout: :infinity)
    assert {:error, :infinite_send_timeout} = SSL.send(socket, "forbidden")
    assert :ok = SSL.abandon_send(socket)
    assert :ok = SSL.abandon_send(socket)
    assert {:error, :closed} = SSL.enable_duplex_reads(socket)
    assert {:error, :closed} = SSL.send(socket, "still-forbidden")
  end

  for {request, payload_size} <- [{:write, 65_536}, {:read_write, 65_536}, {:read_write, 16_384}] do
    test "duplex receives KeyUpdate #{request} with #{payload_size} application bytes held" do
      {socket, peer} = held_peer()
      assert :ok = SSL.enable_duplex_reads(socket)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert :erlang.suspend_process(initial.writer)
      sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", unquote(payload_size))) end)
      pending = held_output(socket.pid, System.monotonic_time(:millisecond) + 1_000)
      send(peer.task.pid, {:update, unquote(request), {unquote(payload_size), true}})

      if unquote(request) == :write do
        assert {:ok, "after-update"} = SSL.recv(socket, 0, 1_000)
        {:connected, received} = :sys.get_state(socket.pid)
        assert received.output == pending.output
        assert received.machine.read_state.generation == initial.machine.read_state.generation + 1
        assert received.machine.write_state == pending.machine.write_state
        assert :ok = SSL.abandon_send(socket)
        assert {:error, :write_abandoned} = Task.await(sender, 1_000)
        assert :ok = SSL.close(socket)
      else
        queued = queued_control(socket.pid, System.monotonic_time(:millisecond) + 1_000)
        assert queued.output == pending.output
        assert queued.pending_control.kind == :control
        assert queued.pending_control.size == 27
        assert_control_ciphertext(queued.pending_control, pending.machine.write_state)
        assert queued.pending_control.deadline <= queued.output.deadline
        assert queued.pending_control.deadline <= queued.write.deadline
        assert queued.machine.read_state.generation == initial.machine.read_state.generation + 1
        assert queued.machine.write_state.generation == initial.machine.write_state.generation + 1
        assert queued.machine.write_state.sequence == 0
        assert Task.yield(sender, 0) == nil

        send(socket.pid, {:writer_result, pending.writer, make_ref(), :ok})
        send(socket.pid, {:output_timeout, make_ref()})
        {:connected, unchanged} = :sys.get_state(socket.pid)
        assert unchanged.output == pending.output
        assert unchanged.pending_control == queued.pending_control
        assert unchanged.machine == queued.machine

        dispatch_held_control(socket, queued)
        assert Task.yield(sender, 0) == nil
        assert true = :erlang.resume_process(initial.writer)
        assert :ok = Task.await(sender, 1_000)
        assert :ok = SSL.send(socket, "client-after-update")
        assert {:ok, "after-update"} = SSL.recv(socket, 0, 1_000)
        assert :ok = SSL.close(socket)
      end
    end
  end

  for timing <- [:before_update, :after_update] do
    test "abandon #{timing} retains the mandatory protected update without replay" do
      {socket, peer} = held_peer()
      assert :ok = SSL.enable_duplex_reads(socket)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(initial.writer)
      sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 65_536)) end)
      held = held_output(socket.pid, System.monotonic_time(:millisecond) + 1_000)

      if unquote(timing) == :before_update do
        assert :ok = SSL.abandon_send(socket)
        assert {:error, :write_abandoned} = Task.await(sender, 1_000)
      end

      send(peer.task.pid, {:update, :read_write, {16_384, false}})
      queued = queued_control(socket.pid, System.monotonic_time(:millisecond) + 1_000)
      assert queued.output == held.output
      assert_control_ciphertext(queued.pending_control, held.machine.write_state)

      if unquote(timing) == :after_update do
        assert :ok = SSL.abandon_send(socket)
        assert {:error, :write_abandoned} = Task.await(sender, 1_000)
      end

      {:connected, abandoned} = :sys.get_state(socket.pid)
      assert abandoned.write == nil
      assert abandoned.write_abandoned?
      assert abandoned.output == held.output
      assert abandoned.pending_control == queued.pending_control
      assert abandoned.machine == queued.machine
      assert Process.read_timer(held.write.timer) == false
      assert {:error, :closed} = SSL.send(socket, "must-not-replay")

      active = dispatch_held_control(socket, queued)
      assert active.machine.write_state == queued.machine.write_state
      assert :ok = SSL.abandon_send(socket)
      assert true = :erlang.resume_process(initial.writer)
      assert {:ok, "after-update"} = SSL.recv(socket, 0, 1_000)
      assert {:error, :closed} = SSL.send(socket, "still-forbidden")
      assert :ok = SSL.close(socket)
    end
  end

  for abandon? <- [false, true] do
    test "queued update retains its original deadline after timeout mutation abandon=#{abandon?}" do
      {socket, peer} = held_peer()
      assert :ok = SSL.setopts(socket, send_timeout: 250)
      assert :ok = SSL.enable_duplex_reads(socket)
      {:connected, initial} = :sys.get_state(socket.pid)
      monitor = Process.monitor(socket.pid)
      assert true = :erlang.suspend_process(initial.writer)
      sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 65_536)) end)
      held = held_output(socket.pid, System.monotonic_time(:millisecond) + 1_000)
      send(peer.task.pid, {:update, :read_write, {16_384, false}})
      queued = queued_control(socket.pid, System.monotonic_time(:millisecond) + 1_000)
      assert queued.pending_control.deadline <= held.write.deadline
      assert queued.output == held.output

      if unquote(abandon?) do
        assert :ok = SSL.abandon_send(socket)
        assert {:error, :write_abandoned} = Task.await(sender, 1_000)
      end

      assert :ok = SSL.setopts(socket, send_timeout: 10_000)
      assert_receive {:DOWN, ^monitor, :process, _, :normal}, 750
      unless unquote(abandon?), do: assert({:error, :timeout} == Task.await(sender, 1_000))
      assert Process.read_timer(queued.pending_control.timer) == false
      assert Process.read_timer(held.output.timer) == false
      assert Port.info(held.tcp) == nil
    end
  end

  test "abandon rejects retaining an output with no finite timer" do
    {socket, _peer} = held_peer()
    assert :ok = SSL.setopts(socket, send_timeout: :infinity)
    {:connected, initial} = :sys.get_state(socket.pid)
    assert :erlang.suspend_process(initial.writer)
    sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 65_536)) end)
    pending = held_output(socket.pid, System.monotonic_time(:millisecond) + 1_000)
    assert pending.output.timer == nil
    assert :ok = SSL.setopts(socket, send_timeout: 2_000)
    assert {:error, :infinite_send_timeout} = SSL.enable_duplex_reads(socket)
    assert {:error, :infinite_send_timeout} = SSL.abandon_send(socket)
    {:connected, unchanged} = :sys.get_state(socket.pid)
    assert unchanged.output == pending.output
    refute unchanged.write_abandoned?
    assert :ok = SSL.close(socket)
    assert {:error, :closed} = Task.await(sender, 1_000)
  end

  defp held_peer do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          {:update, mode, {size, marker?}} ->
            assert :ok = :ssl.update_keys(socket, mode)

            if mode == :read_write do
              prefix = :binary.copy("x", 16_384)
              assert {:ok, ^prefix} = :ssl.recv(socket, byte_size(prefix), 2_000)
              send(parent, :original_record_received)

              if size > byte_size(prefix) do
                rest = :binary.copy("x", size - byte_size(prefix))
                assert {:ok, ^rest} = :ssl.recv(socket, byte_size(rest), 2_000)
              end

              if marker? do
                assert {:ok, "client-after-update"} = :ssl.recv(socket, 19, 2_000)
              else
                # Process the reciprocal control without accepting replayed
                # application bytes from the abandoned logical cursor.
                assert {:error, :timeout} = :ssl.recv(socket, 0, 50)
              end
            end

            assert :ok = :ssl.send(socket, "after-update")

          :finish ->
            :ok
        end

        receive do
          :finish -> :ok
        end
      end)

    options = [:binary | Keyword.merge(tl(Peer.client_options()), send_timeout: 2_000)]
    {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)

    on_exit(fn ->
      if Process.alive?(socket.pid), do: SSL.close(socket)
      if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end)

    {socket, peer}
  end

  defp assert_control_ciphertext(control, write) do
    cipher =
      case write.cipher_suite do
        :tls_aes_128_gcm_sha256 -> :aes_128_gcm
        :tls_aes_256_gcm_sha384 -> :aes_256_gcm
        :tls_chacha20_poly1305_sha256 -> :chacha20_poly1305
      end

    nonce = :crypto.exor(write.iv, <<0::32, write.sequence::64>>)
    header = <<23, 3, 3, 0, 22>>
    # Independently protect the exact RFC KeyUpdate(update_not_requested)
    # handshake and inner content type with the pre-update old write state.
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        cipher,
        write.key,
        nonce,
        <<24, 0, 0, 1, 0, 22>>,
        header,
        16,
        true
      )

    assert IO.iodata_to_binary(control.bytes) ==
             <<header::binary, ciphertext::binary, tag::binary>>
  end

  defp dispatch_held_control(socket, queued) do
    writer = queued.writer
    assert :ok = :sys.suspend(socket.pid)
    assert true = :erlang.resume_process(writer)
    assert_receive :original_record_received, 500
    wait_writer_idle(writer, System.monotonic_time(:millisecond) + 500)
    assert true = :erlang.suspend_process(writer)
    assert :ok = :sys.resume(socket.pid)

    active =
      wait_active_control(
        socket.pid,
        queued.pending_control.token,
        System.monotonic_time(:millisecond) + 500
      )

    assert active.pending_control == nil
    assert active.output == Map.delete(queued.pending_control, :bytes)
    assert active.output.timer == queued.pending_control.timer
    assert is_integer(Process.read_timer(active.output.timer))
    active
  end

  defp wait_writer_idle(writer, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case Process.info(writer, [:status, :current_function]) do
      [status: :waiting, current_function: {SSL.ConnectionWriter, :loop, 2}] ->
        :ok

      _ ->
        receive do
        after
          1 -> wait_writer_idle(writer, deadline)
        end
    end
  end

  defp wait_active_control(pid, token, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case :sys.get_state(pid) do
      {:connected, %{output: %{token: ^token}} = state} ->
        state

      _ ->
        receive do
        after
          1 -> wait_active_control(pid, token, deadline)
        end
    end
  end

  defp queued_control(pid, deadline) do
    assert System.monotonic_time(:millisecond) < deadline,
           "mandatory control never queued behind the original application job"

    case :sys.get_state(pid) do
      {:connected, %{pending_control: %{kind: :control}} = state} ->
        state

      _ ->
        receive do
        after
          1 -> queued_control(pid, deadline)
        end
    end
  end

  defp held_output(pid, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case :sys.get_state(pid) do
      {:connected, %{output: %{kind: :application}} = state} ->
        state

      _ ->
        receive do
        after
          1 -> held_output(pid, deadline)
        end
    end
  end

  defp pending_record(pid, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case :sys.get_state(pid) do
      {:connected, %{output: %{kind: :application} = output} = state} ->
        case :inet.getstat(state.tcp, [:send_pend]) do
          {:ok, [{:send_pend, count}]} when count > 0 ->
            token = output.token

            receive do
            after
              20 -> :ok
            end

            case :sys.get_state(pid) do
              {:connected, %{output: %{token: ^token}}} -> state
              _ -> pending_record(pid, deadline)
            end

          _ ->
            receive do
            after
              1 -> pending_record(pid, deadline)
            end
        end

      _ ->
        receive do
        after
          1 -> pending_record(pid, deadline)
        end
    end
  end
end
