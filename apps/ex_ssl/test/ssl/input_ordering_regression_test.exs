defmodule SSL.InputOrderingRegressionTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer

  @moduletag :integration

  test "raw TCP is rearmed between records of one long logical write" do
    parent = self()
    payload = :binary.copy("l", 16 * 1_048_576)

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send_first -> :ok
        end

        assert :ok = :ssl.send(socket, "first")
        send(parent, :first_progress_record_sent)

        receive do
          :send_second -> :ok
        end

        assert :ok = :ssl.send(socket, "second")
        send(parent, :second_progress_record_sent)

        receive do
          :send_key_update -> :ok
        end

        assert :ok = :ssl.update_keys(socket, :read_write)
        assert :ok = :ssl.send(socket, "after-key-update")
        send(parent, :progress_key_update_sent)
        send(parent, {:progress_peer_payload, :ssl.recv(socket, byte_size(payload), 30_000)})
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer.port, send_timeout: :infinity)

    on_exit(fn ->
      if Process.alive?(socket.pid), do: SSL.close(socket)
      stop_peer_on_failure(peer)
    end)

    {:connected, state} = :sys.get_state(socket.pid)
    writer = state.writer
    assert true = :erlang.suspend_process(writer)
    sender = Task.async(fn -> SSL.send(socket, payload) end)
    wait_for_writer(socket.pid)

    first_receive = Task.async(fn -> SSL.recv(socket, 5, 5_000) end)
    send(peer.task.pid, :send_first)
    assert_receive :first_progress_record_sent, 1_000
    wait_for_deferred_input(socket.pid)
    assert true = :erlang.resume_process(writer)
    assert {:ok, "first"} = Task.await(first_receive, 5_000)
    assert true = :erlang.suspend_process(writer)
    assert Task.yield(sender, 0) == nil
    wait_for_writer(socket.pid)

    second_receive = Task.async(fn -> SSL.recv(socket, 6, 5_000) end)
    send(peer.task.pid, :send_second)
    assert_receive :second_progress_record_sent, 1_000
    wait_for_deferred_input(socket.pid)
    assert true = :erlang.resume_process(writer)
    assert {:ok, "second"} = Task.await(second_receive, 5_000)
    assert true = :erlang.suspend_process(writer)
    assert Task.yield(sender, 0) == nil
    wait_for_writer(socket.pid)

    key_update_receive = Task.async(fn -> SSL.recv(socket, 16, 5_000) end)
    send(peer.task.pid, :send_key_update)
    assert_receive :progress_key_update_sent, 1_000
    wait_for_deferred_input(socket.pid)
    assert true = :erlang.resume_process(writer)
    assert {:ok, "after-key-update"} = Task.await(key_update_receive, 5_000)
    assert Task.yield(sender, 0) == nil

    assert :ok = Task.await(sender, 30_000)
    assert_receive {:progress_peer_payload, {:ok, ^payload}}, 30_000
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "a deferred KeyUpdate is consumed before a rearmed later record" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send_key_update -> :ok
        end

        assert :ok = :ssl.update_keys(socket, :read_write)
        send(parent, :key_update_sent)

        receive do
          :send_application -> :ok
        end

        assert :ok = :ssl.send(socket, "after-update")
        send(parent, {:peer_payload, :ssl.recv(socket, 32_768, 5_000)})
        send(parent, {:peer_received, :ssl.recv(socket, 19, 5_000)})
      end)

    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      {:connected, state} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(state.writer)

      sender = Task.async(fn -> SSL.send(socket, :binary.copy("w", 32_768)) end)
      wait_for_writer(socket.pid)
      assert :ok = Peer.gate_server_records(proxy)

      send(peer.task.pid, :send_key_update)
      assert_receive :key_update_sent, 1_000
      assert_receive {:tls_record_proxy, ^proxy_ref, :queued, 1}, 1_000
      assert :ok = Peer.release_server_record(proxy)
      assert_receive {:tls_record_proxy, ^proxy_ref, :released, 1}, 1_000
      wait_for_deferred_input(socket.pid)

      # This public call used to rearm raw TCP while the KeyUpdate was held in
      # `deferred_tcp`, allowing the next record to overtake the epoch change.
      assert :ok = SSL.setopts(socket, active: :once)

      send(peer.task.pid, :send_application)
      assert_receive {:tls_record_proxy, ^proxy_ref, :queued, 1}, 1_000
      assert :ok = Peer.release_server_record(proxy)
      assert_receive {:tls_record_proxy, ^proxy_ref, :released, 1}, 1_000

      assert true = :erlang.resume_process(state.writer)

      assert {:ok, :ok} =
               Task.yield(sender, 5_000) ||
                 flunk("send stayed pending: #{inspect(:sys.get_state(socket.pid))}")

      assert_receive {:ssl, ^socket, "after-update"}, 5_000
      assert_receive {:peer_payload, {:ok, payload}}, 5_000
      assert payload == :binary.copy("w", 32_768)
      assert :ok = SSL.send(socket, "client-after-update")
      assert_receive {:peer_received, {:ok, "client-after-update"}}, 5_000
      assert :ok = SSL.close(socket)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)

      if Process.alive?(peer.task.pid) do
        _ = :ssl.close(peer.listener)
        _ = Task.shutdown(peer.task, 1_000)
      end
    end
  end

  test "a passive receive timeout cannot rearm past older deferred TLS input" do
    parent = self()
    payload = :binary.copy("t", 32_768)

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send_key_update -> :ok
        end

        assert :ok = :ssl.update_keys(socket, :read_write)
        send(parent, :timeout_key_update_sent)

        receive do
          :send_application -> :ok
        end

        assert :ok = :ssl.send(socket, "after-timeout")
        send(parent, {:timeout_peer_payload, :ssl.recv(socket, byte_size(payload), 5_000)})
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      {:connected, state} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(state.writer)
      sender = Task.async(fn -> SSL.send(socket, payload) end)
      wait_for_writer(socket.pid)
      assert :ok = Peer.gate_server_records(proxy)
      send(peer.task.pid, :send_key_update)
      assert_receive :timeout_key_update_sent, 1_000
      assert_receive {:tls_record_proxy, ^proxy_ref, :queued, 1}, 1_000
      assert :ok = Peer.release_server_record(proxy)
      wait_for_deferred_input(socket.pid)

      receiver = Task.async(fn -> SSL.recv(socket, 13, 30) end)
      receiver_ref = receiver.ref
      assert {:error, :timeout} = Task.await(receiver, 1_000)
      refute_receive {^receiver_ref, _reply}, 20

      send(peer.task.pid, :send_application)
      assert_receive {:tls_record_proxy, ^proxy_ref, :queued, 1}, 1_000
      assert :ok = Peer.release_server_record(proxy)
      assert true = :erlang.resume_process(state.writer)
      assert :ok = Task.await(sender, 5_000)
      assert {:ok, "after-timeout"} = SSL.recv(socket, 13, 5_000)
      assert_receive {:timeout_peer_payload, {:ok, ^payload}}, 5_000
      assert :ok = SSL.close(socket)
      assert :ok = Peer.stop(peer)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  test "queued fragmented and coalesced records drain before writer progress" do
    parent = self()
    payload = :binary.copy("q", 32_768)

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send_records -> :ok
        end

        assert :ok = :ssl.send(socket, "fragmented")
        assert :ok = :ssl.send(socket, "coalesced-a")
        assert :ok = :ssl.send(socket, "coalesced-b")
        send(parent, {:queued_peer_payload, :ssl.recv(socket, byte_size(payload), 5_000)})
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      {:connected, state} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(state.writer)
      sender = Task.async(fn -> SSL.send(socket, payload) end)
      wait_for_writer(socket.pid)
      assert :ok = Peer.gate_server_records(proxy)
      send(peer.task.pid, :send_records)

      records =
        for count <- 1..3 do
          assert_receive {:tls_record_proxy, ^proxy_ref, :queued, ^count}, 1_000
          assert_receive {:tls_record_proxy, ^proxy_ref, :record, record}, 1_000
          record
        end

      [first, second, third] = records
      split = div(byte_size(first), 2)
      <<first_half::binary-size(^split), second_half::binary>> = first
      send(socket.pid, {:tcp, state.tcp, first_half})
      assert :ok = SSL.setopts(socket, active: :once)
      send(socket.pid, {:tcp, state.tcp, second_half})
      send(socket.pid, {:tcp, state.tcp, second <> third})
      assert true = :erlang.resume_process(state.writer)

      assert :ok = Task.await(sender, 5_000)
      assert_receive {:ssl, ^socket, "fragmented"}, 5_000
      assert :ok = SSL.setopts(socket, active: :once)
      assert_receive {:ssl, ^socket, "coalesced-acoalesced-b"}, 5_000
      assert_receive {:queued_peer_payload, {:ok, ^payload}}, 5_000
      assert :ok = SSL.close(socket)
      assert :ok = Peer.stop(peer)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  test "authenticated data and close_notify drain before a queued TCP EOF" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :finish -> :ok
        end

        assert :ok = :ssl.send(socket, "final-data")
        send(parent, :final_data_sent)
        :ssl.close(socket)
      end)

    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      {:connected, state} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(state.writer)
      sender = Task.async(fn -> SSL.send(socket, "pending-output") end)
      wait_for_writer(socket.pid)
      assert :ok = Peer.gate_server_records(proxy)
      send(peer.task.pid, :finish)
      assert_receive :final_data_sent, 1_000

      records =
        for count <- 1..2 do
          assert_receive {:tls_record_proxy, ^proxy_ref, :queued, ^count}, 1_000
          assert_receive {:tls_record_proxy, ^proxy_ref, :record, record}, 1_000
          record
        end

      assert :ok = SSL.setopts(socket, active: :once)
      Enum.each(records, &send(socket.pid, {:tcp, state.tcp, &1}))
      send(socket.pid, {:tcp_closed, state.tcp})
      assert true = :erlang.resume_process(state.writer)

      assert :ok = Task.await(sender, 5_000)
      assert_receive {:ssl, ^socket, "final-data"}, 5_000
      assert_receive {:ssl_closed, ^socket}, 5_000
      refute_receive {:ssl_error, ^socket, _reason}, 20
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  test "application data before a queued abrupt EOF is delivered before one error" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send_final -> :ok
        end

        assert :ok = :ssl.send(socket, "before-abrupt-eof")
        send(parent, :abrupt_data_sent)
        assert {:ok, "pending-output"} = :ssl.recv(socket, 0, 5_000)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      {:connected, state} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(state.writer)
      sender = Task.async(fn -> SSL.send(socket, "pending-output") end)
      wait_for_writer(socket.pid)
      assert :ok = Peer.gate_server_records(proxy)
      send(peer.task.pid, :send_final)
      assert_receive :abrupt_data_sent, 1_000
      assert_receive {:tls_record_proxy, ^proxy_ref, :queued, 1}, 1_000
      assert_receive {:tls_record_proxy, ^proxy_ref, :record, record}, 1_000

      assert :ok = SSL.setopts(socket, active: :once)
      send(socket.pid, {:tcp, state.tcp, record})
      send(socket.pid, {:tcp_closed, state.tcp})
      assert true = :erlang.resume_process(state.writer)

      assert :ok = Task.await(sender, 5_000)
      assert_receive {:ssl, ^socket, "before-abrupt-eof"}, 5_000
      assert_receive {:ssl_error, ^socket, :econnreset}, 5_000
      refute_receive {:ssl_error, ^socket, _reason}, 20
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  defp connect(port, extra_options) do
    options = [:binary | Keyword.merge(tl(Peer.client_options()), extra_options)]
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", port, options, 5_000)
    socket
  end

  defp wait_for_writer(pid, attempts \\ 200)
  defp wait_for_writer(_pid, 0), do: flunk("writer did not become pending")

  defp wait_for_writer(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{write: %{waiting: waiting}}} when not is_nil(waiting) ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_writer(pid, attempts - 1)
    end
  end

  defp wait_for_deferred_input(pid, attempts \\ 200)
  defp wait_for_deferred_input(_pid, 0), do: flunk("KeyUpdate was not deferred")

  defp wait_for_deferred_input(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{deferred_tcp: bytes}} when is_binary(bytes) and byte_size(bytes) > 0 ->
        :ok

      {:connected, %{input_size: size}} when is_integer(size) and size > 0 ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_deferred_input(pid, attempts - 1)
    end
  end

  defp stop_peer_on_failure(peer) do
    if Process.alive?(peer.task.pid) do
      _ = :ssl.close(peer.listener)
      _ = Task.shutdown(peer.task, 1_000)
    end
  end
end
