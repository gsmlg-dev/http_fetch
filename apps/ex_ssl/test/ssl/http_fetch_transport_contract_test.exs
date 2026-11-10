defmodule SSL.HTTPFetchTransportContractTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer

  @moduletag :integration

  test "connect worker transfers ownership, exits, and task callers can send" do
    parent = self()

    {:ok, peer} =
      Peer.start(
        fn socket ->
          assert {:ok, "request"} = :ssl.recv(socket, 7, 5_000)
          assert :ok = :ssl.send(socket, "response")
          send(parent, :response_sent)
          assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
          :ok
        end,
        ssl_options: [alpn_preferred_protocols: ["http/1.1"]]
      )

    worker =
      spawn(fn ->
        options =
          [
            :binary
            | Keyword.put(
                tl(Peer.client_options()),
                :alpn_advertised_protocols,
                ["h2", "http/1.1"]
              )
          ]

        {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
        send(parent, {:worker_connected, self(), socket})

        receive do
          {:transfer_socket, owner} ->
            send(parent, {:ownership_result, SSL.controlling_process(socket, owner)})
        end
      end)

    worker_monitor = Process.monitor(worker)
    assert_receive {:worker_connected, ^worker, socket}, 5_000
    send(worker, {:transfer_socket, self()})
    assert_receive {:ownership_result, :ok}, 1_000
    assert_receive {:DOWN, ^worker_monitor, :process, ^worker, :normal}
    assert Process.alive?(socket.pid)
    assert {:ok, "http/1.1"} = SSL.negotiated_protocol(socket)

    sender = Task.async(fn -> SSL.send(socket, ["req", ~c"uest"]) end)
    assert :ok = Task.await(sender, 5_000)
    assert_receive :response_sent, 5_000
    assert :ok = SSL.setopts(socket, active: :once)
    assert_receive {:ssl, ^socket, "response"}, 1_000
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "ownership transfer rejects non-owners and dead targets without changing the owner" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:ok, "still-live"} = :ssl.recv(socket, 10, 5_000)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer)
    assert :ok = SSL.controlling_process(socket, self())

    non_owner = Task.async(fn -> SSL.controlling_process(socket, self()) end)
    assert {:error, :not_owner} = Task.await(non_owner)

    dead =
      spawn(fn ->
        receive do
          :exit -> :ok
        end
      end)

    dead_monitor = Process.monitor(dead)
    send(dead, :exit)
    assert_receive {:DOWN, ^dead_monitor, :process, ^dead, :normal}
    assert {:error, :noproc} = SSL.controlling_process(socket, dead)

    assert :ok = SSL.send(socket, "still-live")
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "repeated transfers replace the owner monitor and new owner death cleans up" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        send(parent, :peer_closed)
        :ok
      end)

    socket = connect(peer)

    final_owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    middle_owner =
      spawn(fn ->
        receive do
          {:take, socket, final_owner} ->
            result = SSL.controlling_process(socket, final_owner)
            send(parent, {:second_transfer, result})
        end
      end)

    assert :ok = SSL.controlling_process(socket, middle_owner)
    middle_monitor = Process.monitor(middle_owner)
    send(middle_owner, {:take, socket, final_owner})
    assert_receive {:second_transfer, :ok}, 1_000
    assert_receive {:DOWN, ^middle_monitor, :process, ^middle_owner, :normal}
    assert Process.alive?(socket.pid)

    connection_monitor = Process.monitor(socket.pid)
    send(final_owner, :stop)
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert_receive :peer_closed, 1_000
    assert {:error, :closed} = SSL.send(socket, "not replayed")
    assert :ok = Peer.stop(peer)
  end

  test "ownership transfer racing close has one terminal outcome and no surviving connection" do
    for _iteration <- 1..5 do
      {:ok, peer} =
        Peer.start(fn socket ->
          assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
          :ok
        end)

      socket = connect(peer)
      connection_monitor = Process.monitor(socket.pid)

      target =
        spawn(fn ->
          receive do
            :stop -> :ok
          end
        end)

      closer =
        Task.async(fn ->
          receive do
            :close -> SSL.close(socket)
          end
        end)

      send(closer.pid, :close)
      transfer_result = SSL.controlling_process(socket, target)

      assert transfer_result in [:ok, {:error, :closed}, {:error, :econnreset}]
      assert :ok = Task.await(closer, 1_000)
      assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000

      send(target, :stop)
      assert :ok = Peer.stop(peer)
    end
  end

  test "active once drains prebuffered data one activation at a time and reports graceful close" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :first -> :ok
        end

        :ok = :ssl.send(socket, "first")
        send(parent, :first_sent)

        receive do
          :second -> :ok
        end

        :ok = :ssl.send(socket, "second")
        send(parent, :second_sent)

        receive do
          :close -> :ok
        end

        :ok = :ssl.close(socket)
      end)

    socket = connect(peer)
    send(peer.task.pid, :first)
    assert_receive :first_sent
    wait_for_buffered(socket.pid, 5)

    assert :ok = SSL.setopts(socket, active: :once)
    assert_receive {:ssl, ^socket, "first"}, 1_000
    refute_receive {:ssl_passive, ^socket}, 20

    send(peer.task.pid, :second)
    assert_receive :second_sent
    wait_for_buffered(socket.pid, 6)
    refute_receive {:ssl, ^socket, _}, 20

    assert :ok = SSL.setopts(socket, active: :once)
    assert_receive {:ssl, ^socket, "second"}, 1_000
    refute_receive {:ssl_passive, ^socket}, 20

    send(peer.task.pid, :close)
    assert_receive {:ssl_closed, ^socket}, 1_000
    refute_receive {:ssl_closed, ^socket}, 20
    assert :ok = Peer.stop(peer)
  end

  test "setopts validates atomically and does not steal a pending passive receive" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send -> :ok
        end

        :ok = :ssl.send(socket, "passive")
        send(parent, :passive_sent)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer)
    receiver = Task.async(fn -> SSL.recv(socket, 7, 5_000) end)
    wait_for_pending_receiver(socket.pid)

    assert {:error, :einval} = SSL.setopts(socket, active: :once)
    assert {:error, {:options, _}} = SSL.setopts(socket, active: :once, packet: :line)

    send(peer.task.pid, :send)
    assert_receive :passive_sent
    assert {:ok, "passive"} = Task.await(receiver)
    refute_receive {:ssl, ^socket, _}, 20
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "passive recv is rejected while active once is armed without consuming its credit" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send -> :ok
        end

        assert :ok = :ssl.send(socket, "active-credit")
        send(parent, :active_credit_sent)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer)
    assert :ok = SSL.setopts(socket, active: :once)
    assert {:error, :einval} = SSL.recv(socket, 13, 1_000)

    send(peer.task.pid, :send)
    assert_receive :active_credit_sent
    assert_receive {:ssl, ^socket, "active-credit"}, 1_000
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "switching active once back to passive retains bytes for recv" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send -> :ok
        end

        :ok = :ssl.send(socket, "retained")
        send(parent, :retained_sent)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer)
    assert :ok = SSL.setopts(socket, active: :once)
    assert :ok = SSL.setopts(socket, active: false)
    send(peer.task.pid, :send)
    assert_receive :retained_sent
    wait_for_buffered(socket.pid, 8)
    refute_receive {:ssl, ^socket, _}, 20
    assert {:ok, "retained"} = SSL.recv(socket, 8, 1_000)
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "one logical write one byte above 1 MiB is transmitted exactly" do
    payload = :binary.copy("x", 1_048_577)

    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:ok, ^payload} = :ssl.recv(socket, byte_size(payload), 15_000)
        assert :ok = :ssl.send(socket, "accepted")
      end)

    socket = connect(peer, send_timeout: 15_000)
    assert :ok = SSL.send(socket, payload)
    assert {:ok, "accepted"} = SSL.recv(socket, 8, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "several MiB of mixed iodata is written exactly once in order" do
    chunks = for index <- 0..511, do: [<<rem(index, 251)>>, :binary.copy(<<index::16>>, 2_048)]
    payload = IO.iodata_to_binary(chunks)
    assert byte_size(payload) > 2 * 1_048_576

    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:ok, ^payload} = :ssl.recv(socket, byte_size(payload), 15_000)
        assert :ok = :ssl.send(socket, "accepted")
      end)

    socket = connect(peer, send_timeout: 15_000)
    assert :ok = SSL.send(socket, chunks)
    assert {:ok, "accepted"} = SSL.recv(socket, 8, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "response larger than the passive buffer is consumed with repeated active once" do
    payload = :binary.copy("response-block-", 100_000)
    assert byte_size(payload) > 1_048_576
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        for <<chunk::binary-size(16_000) <- payload>> do
          :ok = :ssl.send(socket, chunk)
        end

        remainder_size = rem(byte_size(payload), 16_000)

        if remainder_size > 0 do
          offset = byte_size(payload) - remainder_size
          :ok = :ssl.send(socket, binary_part(payload, offset, remainder_size))
        end

        send(parent, :large_response_sent)
        assert {:error, :closed} = :ssl.recv(socket, 0, 15_000)
        :ok
      end)

    socket = connect(peer)
    received = receive_active(socket, byte_size(payload), [])
    assert IO.iodata_to_binary(Enum.reverse(received)) == payload
    assert_receive :large_response_sent, 5_000
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  for protocol <- ["h2", "http/1.1"] do
    test "negotiated_protocol returns authenticated #{protocol} after ownership transfer" do
      protocol = unquote(protocol)

      {:ok, peer} =
        Peer.start(
          fn socket ->
            assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
            :ok
          end,
          ssl_options: [alpn_preferred_protocols: [protocol]]
        )

      socket =
        connect(peer,
          alpn_advertised_protocols: ["h2", "http/1.1"]
        )

      owner = self()
      assert :ok = SSL.controlling_process(socket, owner)
      assert {:ok, ^protocol} = SSL.negotiated_protocol(socket)
      assert :ok = SSL.close(socket)
      assert :ok = Peer.stop(peer)
    end
  end

  test "negotiated_protocol reports an absent ALPN selection" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer, alpn_advertised_protocols: ["h2", "http/1.1"])
    assert {:error, :protocol_not_negotiated} = SSL.negotiated_protocol(socket)
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "a conflicting explicit-profile ALPN is rejected before TCP connect" do
    assert {:ok, %{profile: profile}} =
             SSL.Options.normalize("exssl.test", alpn_advertised_protocols: ["h2"])

    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)

    options =
      [:binary]
      |> Kernel.++(tl(Peer.client_options()))
      |> Keyword.put(:ex_ssl, profile: profile)
      |> Keyword.put(:alpn_advertised_protocols, ["http/1.1"])

    assert {:error, {:options, {:alpn_advertised_protocols, :profile_conflict}}} =
             SSL.connect(~c"127.0.0.1", port, options, 1_000)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
    assert :ok = :gen_tcp.close(listener)
  end

  test "logical send timeout closes an in-flight write without extending per record" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer, send_timeout: 30)
    {:connected, state} = :sys.get_state(socket.pid)
    writer_monitor = Process.monitor(state.writer)
    connection_monitor = Process.monitor(socket.pid)
    assert true = :erlang.suspend_process(state.writer)

    sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 64_000)) end)
    wait_for_admitted_write(socket.pid)
    assert {:error, :timeout} = Task.await(sender, 1_000)
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert {:error, :econnreset} = SSL.send(socket, "no retry")
    assert :ok = Peer.stop(peer)
  end

  test "infinite-timeout write remains cancellable by close and releases its writer" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer, send_timeout: :infinity)
    {:connected, state} = :sys.get_state(socket.pid)
    writer_monitor = Process.monitor(state.writer)
    assert true = :erlang.suspend_process(state.writer)

    sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 64_000)) end)
    wait_for_admitted_write(socket.pid)
    assert :ok = SSL.close(socket)
    assert {:error, :closed} = Task.await(sender, 1_000)
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert :ok = Peer.stop(peer)
  end

  test "peer close settles an unfinished infinite-timeout send before buffered response drainage" do
    assert_peer_close_settles_unfinished_send(:infinity, :complete_shutdown)
  end

  test "peer close settles an unfinished send before its finite deadline" do
    assert_peer_close_settles_unfinished_send(5_000, :kill_shutdown_writer)
  end

  for mode <- [:passive, :once], outcome <- [:complete, :deadline, :local_close] do
    test "#{mode} drainage before pending peer shutdown uses bounded #{outcome} cleanup" do
      assert_peer_close_settles_unfinished_send(
        :infinity,
        {:drain_first, unquote(mode), unquote(outcome)}
      )
    end
  end

  test "peer close settles a send after active-once credit is consumed with response buffered" do
    parent = self()
    first = "rejected"
    buffered = "response remains buffered"
    payload = :binary.copy("unfinished-active-upload-", 32_768)

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :reject_upload -> :ok
        end

        assert :ok = :ssl.send(socket, first)
        assert :ok = :ssl.send(socket, buffered)
        send(parent, :active_rejection_sent)
        assert :ok = :ssl.close(socket)
      end)

    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self())
    proxy_ref = proxy.ref

    on_exit(fn ->
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)

      if Process.alive?(peer.task.pid) do
        _ = :ssl.close(peer.listener)
        _ = Task.shutdown(peer.task, 1_000)
      end
    end)

    socket = connect(proxy, send_timeout: :infinity, active: :once)
    {:connected, initial_state} = :sys.get_state(socket.pid)
    writer = initial_state.writer
    assert true = :erlang.suspend_process(writer)

    try do
      sender = Task.async(fn -> SSL.send(socket, payload) end)
      pending = wait_for_admitted_write(socket.pid)
      assert :erlang.iolist_size(pending.write.cursor) > 3 * 16_384
      assert :ok = Peer.gate_server_records(proxy)
      assert_receive {:tls_record_proxy, ^proxy_ref, :gated}, 1_000

      send(peer.task.pid, :reject_upload)
      assert_receive :active_rejection_sent, 1_000

      records =
        for count <- 1..3 do
          assert_receive {:tls_record_proxy, ^proxy_ref, :queued, ^count}, 1_000
          assert_receive {:tls_record_proxy, ^proxy_ref, :record, record}, 1_000
          record
        end

      Enum.each(records, &send(socket.pid, {:tcp, initial_state.tcp, &1}))
      wait_for_deferred_input(socket.pid, 3)

      assert :ok = :sys.suspend(socket.pid)
      assert true = :erlang.resume_process(writer)
      wait_for_writer_idle(writer)
      assert true = :erlang.suspend_process(writer)
      assert :ok = :sys.resume(socket.pid)

      assert {:ok, {:error, :closed}} =
               Task.yield(sender, 1_000) ||
                 flunk("send stayed pending after active-once credit was consumed")

      assert_receive {:ssl, ^socket, ^first}, 1_000
      refute_receive {:ssl, ^socket, _bytes}, 20
      refute_receive {:ssl_closed, ^socket}, 20

      assert {:connected, settled} = :sys.get_state(socket.pid)
      assert settled.active == false
      assert settled.write == nil
      assert is_port(settled.tcp)
      assert settled.output.kind == :close_notify
      assert settled.size == byte_size(buffered)

      assert true = :erlang.resume_process(writer)
      settled = wait_for_peer_shutdown(socket.pid)
      assert settled.tcp == nil
      assert settled.output == nil
      assert settled.size == byte_size(buffered)

      writer_monitor = Process.monitor(writer)
      Process.exit(writer, :kill)
      assert_receive {:DOWN, ^writer_monitor, :process, ^writer, :killed}, 1_000
      settled = wait_for_closed_writer_cleanup(socket.pid)
      assert settled.size == byte_size(buffered)

      # Virtual TLS options remain usable while authenticated bytes outlive TCP.
      assert :ok = SSL.setopts(socket, send_timeout: 123)
      assert {:error, :closed} = SSL.setopts(socket, nodelay: true)

      connection_monitor = Process.monitor(socket.pid)
      assert {:ok, ^buffered} = SSL.recv(socket, byte_size(buffered), 1_000)
      assert_receive {:ssl_closed, ^socket}, 1_000
      assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
      assert {:error, :closed} = SSL.recv(socket, 0, 1_000)
      assert :ok = Peer.stop(peer)
    after
      resume_connection(socket.pid)
      resume_if_suspended(writer)
    end
  end

  test "owner death during an admitted write fails closed and cleans up the writer" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer, send_timeout: :infinity)
    {:connected, state} = :sys.get_state(socket.pid)
    assert true = :erlang.suspend_process(state.writer)

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    assert :ok = SSL.controlling_process(socket, owner)
    connection_monitor = Process.monitor(socket.pid)
    writer_monitor = Process.monitor(state.writer)
    sender = Task.async(fn -> SSL.send(socket, :binary.copy("owner-write-", 8_000)) end)
    wait_for_admitted_write(socket.pid)

    Process.exit(owner, :kill)

    assert {:error, :closed} = Task.await(sender, 1_000)
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert :ok = Peer.stop(peer)
  end

  test "sender death before and during transmission releases or fails closed deterministically" do
    parent = self()

    {:ok, first_peer} =
      Peer.start(fn socket ->
        assert {:ok, "after-cancel"} = :ssl.recv(socket, 12, 5_000)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    first_socket = connect(first_peer)

    reserver =
      spawn(fn ->
        {:ok, _token} =
          :gen_statem.call(first_socket.pid, {first_socket.ref, :reserve_write}, :infinity)

        send(parent, {:reserved, self()})
        Process.sleep(:infinity)
      end)

    reserver_monitor = Process.monitor(reserver)
    assert_receive {:reserved, ^reserver}
    Process.exit(reserver, :kill)
    assert_receive {:DOWN, ^reserver_monitor, :process, ^reserver, :killed}
    wait_for_write_release(first_socket.pid)
    assert :ok = SSL.send(first_socket, "after-cancel")
    assert :ok = SSL.close(first_socket)
    assert :ok = Peer.stop(first_peer)

    {:ok, second_peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    second_socket = connect(second_peer, send_timeout: :infinity)
    {:connected, second_state} = :sys.get_state(second_socket.pid)
    assert true = :erlang.suspend_process(second_state.writer)
    connection_monitor = Process.monitor(second_socket.pid)

    sender = spawn(fn -> SSL.send(second_socket, :binary.copy("y", 64_000)) end)
    wait_for_admitted_write(second_socket.pid)
    sender_monitor = Process.monitor(sender)
    Process.exit(sender, :kill)
    assert_receive {:DOWN, ^sender_monitor, :process, ^sender, :killed}
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert {:error, :econnreset} = SSL.send(second_socket, "must not replay")
    assert :ok = Peer.stop(second_peer)
  end

  test "active once is accepted at connect and abrupt transport loss emits one ssl_error" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert :ok = :ssl.send(socket, "connected-active")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, proxy} = Peer.start_fragmenting_proxy(peer.port, self())

    try do
      options = [:binary | Keyword.put(tl(Peer.client_options()), :active, :once)]
      assert {:ok, socket} = SSL.connect(~c"127.0.0.1", proxy.port, options, 5_000)
      assert_receive {:ssl, ^socket, "connected-active"}, 1_000

      Peer.stop_fragmenting_proxy(proxy)
      assert_receive {:ssl_error, ^socket, :econnreset}, 1_000
      refute_receive {:ssl_error, ^socket, _}, 20
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_fragmenting_proxy(proxy)
      assert :ok = Peer.stop(peer)
    end
  end

  test "single-writer admission rejects a concurrent logical write without retaining it" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer, send_timeout: :infinity)
    {:connected, state} = :sys.get_state(socket.pid)
    assert true = :erlang.suspend_process(state.writer)

    first = Task.async(fn -> SSL.send(socket, :binary.copy("a", 64_000)) end)
    wait_for_admitted_write(socket.pid)
    assert {:error, :busy} = SSL.send(socket, :binary.copy("b", 64_000))
    assert :ok = SSL.close(socket)
    assert {:error, :closed} = Task.await(first, 1_000)
    assert :ok = Peer.stop(peer)
  end

  test "peer KeyUpdate during a multi-record logical write preserves exact ordering" do
    parent = self()
    payload = :binary.copy("key-update-write-", 90_000)

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :update -> :ok
        end

        assert :ok = :ssl.update_keys(socket, :write)
        assert {:ok, ^payload} = :ssl.recv(socket, byte_size(payload), 15_000)
        assert :ok = :ssl.send(socket, "ordered")
        send(parent, :key_update_exchange_done)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer, send_timeout: :infinity)
    {:connected, state} = :sys.get_state(socket.pid)
    assert true = :erlang.suspend_process(state.writer)
    sender = Task.async(fn -> SSL.send(socket, payload) end)
    wait_for_admitted_write(socket.pid)
    send(peer.task.pid, :update)
    assert true = :erlang.resume_process(state.writer)

    assert :ok = Task.await(sender, 15_000)
    assert {:ok, "ordered"} = SSL.recv(socket, 7, 5_000)
    assert_receive :key_update_exchange_done, 5_000
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  defp receive_active(_socket, 0, chunks), do: chunks

  defp receive_active(socket, remaining, chunks) do
    assert :ok = SSL.setopts(socket, active: :once)

    receive do
      {:ssl, ^socket, bytes} ->
        assert byte_size(bytes) <= remaining
        receive_active(socket, remaining - byte_size(bytes), [bytes | chunks])
    after
      5_000 -> flunk("active-once response stalled with #{remaining} bytes remaining")
    end
  end

  defp connect(peer, extra_options \\ []) do
    options = [:binary | Keyword.merge(tl(Peer.client_options()), extra_options)]
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
    socket
  end

  defp assert_peer_close_settles_unfinished_send(send_timeout, shutdown_outcome) do
    parent = self()
    response = "request rejected"
    payload = :binary.copy("unfinished-upload-", 32_768)

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :reject_upload -> :ok
        end

        assert :ok = :ssl.send(socket, response)
        send(parent, :early_response_sent)
        assert :ok = :ssl.close(socket)
      end)

    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self())
    proxy_ref = proxy.ref

    on_exit(fn ->
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)

      if Process.alive?(peer.task.pid) do
        _ = :ssl.close(peer.listener)
        _ = Task.shutdown(peer.task, 1_000)
      end
    end)

    socket = connect(proxy, send_timeout: send_timeout)
    {:connected, initial_state} = :sys.get_state(socket.pid)
    writer = initial_state.writer
    assert true = :erlang.suspend_process(writer)

    try do
      sender = Task.async(fn -> SSL.send(socket, payload) end)
      pending = wait_for_admitted_write(socket.pid)
      assert pending.write.size == byte_size(payload)
      assert :erlang.iolist_size(pending.write.cursor) > 16_384
      assert pending.output.kind == :application
      assert :ok = Peer.gate_server_records(proxy)
      assert_receive {:tls_record_proxy, ^proxy_ref, :gated}, 1_000

      send(peer.task.pid, :reject_upload)
      assert_receive :early_response_sent, 1_000

      records =
        for count <- 1..2 do
          assert_receive {:tls_record_proxy, ^proxy_ref, :queued, ^count}, 1_000
          assert_receive {:tls_record_proxy, ^proxy_ref, :record, record}, 1_000
          record
        end

      Enum.each(records, &send(socket.pid, {:tcp, initial_state.tcp, &1}))
      wait_for_deferred_input(socket.pid, 2)
      started_at = System.monotonic_time(:millisecond)
      assert :ok = :sys.suspend(socket.pid)
      assert true = :erlang.resume_process(writer)
      wait_for_writer_idle(writer)
      assert true = :erlang.suspend_process(writer)
      assert :ok = :sys.resume(socket.pid)

      assert {:ok, {:error, :closed}} =
               Task.yield(sender, 1_000) ||
                 flunk("send stayed pending before response drainage")

      elapsed = System.monotonic_time(:millisecond) - started_at
      if is_integer(send_timeout), do: assert(elapsed < send_timeout)
      if pending.write.timer, do: assert(Process.read_timer(pending.write.timer) == false)

      assert {:connected, settled} = :sys.get_state(socket.pid)
      assert settled.closed
      assert is_port(settled.tcp)
      assert settled.output.kind == :close_notify
      assert settled.write == nil
      assert settled.size == byte_size(response)

      {:monitors, monitors} = Process.info(socket.pid, :monitors)
      refute {:process, sender.pid} in monitors

      send(socket.pid, {:writer_result, writer, pending.output.token, :ok})
      send(socket.pid, {:output_timeout, pending.output.token})
      send(socket.pid, {:write_timeout, pending.write.token})
      send(socket.pid, {:DOWN, pending.write.monitor, :process, sender.pid, :normal})

      assert {:connected, after_stale} = :sys.get_state(socket.pid)
      assert after_stale.write == nil
      assert after_stale.output.kind == :close_notify
      assert after_stale.size == byte_size(response)

      assert_shutdown_and_drain(socket, writer, response, shutdown_outcome)
      assert :ok = Peer.stop(peer)
    after
      resume_connection(socket.pid)
      resume_if_suspended(writer)
    end
  end

  defp assert_shutdown_and_drain(socket, writer, response, {:drain_first, mode, outcome}) do
    watchdog =
      spawn(fn ->
        receive do
          :done -> :ok
        after
          2_000 ->
            Process.exit(socket.pid, :kill)
            Process.exit(writer, :kill)
        end
      end)

    on_exit(fn ->
      send(watchdog, :done)
      if Process.alive?(socket.pid), do: Process.exit(socket.pid, :kill)
      if Process.alive?(writer), do: Process.exit(writer, :kill)
    end)

    connection_monitor = Process.monitor(socket.pid)
    writer_monitor = Process.monitor(writer)
    {:connected, before_drain} = :sys.get_state(socket.pid)
    shutdown = before_drain.output
    tcp = before_drain.tcp
    started = System.monotonic_time(:millisecond)

    case mode do
      :passive ->
        assert {:ok, ^response} = SSL.recv(socket, byte_size(response), 1_000)

      :once ->
        assert :ok = SSL.setopts(socket, active: :once)
        assert_receive {:ssl, ^socket, ^response}, 1_000
    end

    # Draining the last byte must leave the shutdown deadline serviceable.
    assert {:connected, drained} = :sys.get_state(socket.pid)
    assert drained.size == 0
    assert drained.write == nil
    assert drained.output.token == shutdown.token
    assert is_integer(Process.read_timer(shutdown.timer))

    case outcome do
      :complete -> assert true = :erlang.resume_process(writer)
      :deadline -> :ok
      :local_close -> assert :ok = SSL.close(socket)
    end

    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert System.monotonic_time(:millisecond) - started < 1_000
    assert Port.info(tcp) == nil
    assert Process.read_timer(shutdown.timer) == false
    assert {:error, :closed} = SSL.recv(socket, 0, 0)
    assert :ok = SSL.close(socket)
    assert :ok = SSL.close(socket)
    send(watchdog, :done)

    if mode == :once and outcome != :local_close do
      assert_receive {:ssl_closed, ^socket}, 1_000
      refute_receive {:ssl, ^socket, _}, 0
      refute_receive {:ssl_closed, ^socket}, 0
    end
  end

  defp assert_shutdown_and_drain(socket, writer, response, shutdown_outcome) do
    writer_cleanup = finish_test_peer_shutdown(writer, shutdown_outcome)
    after_shutdown = wait_for_peer_shutdown(socket.pid)
    assert after_shutdown.tcp == nil
    assert after_shutdown.output == nil
    assert after_shutdown.size == byte_size(response)
    if shutdown_outcome == :kill_shutdown_writer, do: assert(after_shutdown.writer == nil)

    connection_monitor = Process.monitor(socket.pid)
    assert {:ok, ^response} = SSL.recv(socket, byte_size(response), 1_000)
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000

    if writer_cleanup do
      assert_receive {:DOWN, ^writer_cleanup, :process, _, :killed}, 1_000
    end

    assert {:error, :closed} = SSL.recv(socket, 0, 1_000)
  end

  defp resume_if_suspended(pid) do
    if Process.alive?(pid), do: :erlang.resume_process(pid)
  rescue
    ArgumentError -> :ok
  end

  defp resume_connection(pid) do
    if Process.alive?(pid), do: :sys.resume(pid, 50)
  catch
    :exit, _reason -> :ok
  end

  defp finish_test_peer_shutdown(writer, :complete_shutdown) do
    monitor = Process.monitor(writer)
    assert true = :erlang.resume_process(writer)
    monitor
  end

  defp finish_test_peer_shutdown(writer, :kill_shutdown_writer) do
    monitor = Process.monitor(writer)
    Process.exit(writer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^writer, :killed}, 1_000
    nil
  end

  defp wait_for_buffered(pid, minimum, attempts \\ 200)
  defp wait_for_buffered(_pid, _minimum, 0), do: flunk("plaintext was not buffered")

  defp wait_for_buffered(pid, minimum, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{size: size}} when size >= minimum ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_buffered(pid, minimum, attempts - 1)
    end
  end

  defp wait_for_pending_receiver(pid, attempts \\ 200)
  defp wait_for_pending_receiver(_pid, 0), do: flunk("receiver did not become pending")

  defp wait_for_pending_receiver(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{recv: %{} = _receiver}} ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_pending_receiver(pid, attempts - 1)
    end
  end

  defp wait_for_admitted_write(pid, attempts \\ 200)
  defp wait_for_admitted_write(_pid, 0), do: flunk("write was not admitted")

  defp wait_for_admitted_write(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{write: %{from: from, waiting: waiting}} = state}
      when not is_nil(from) and not is_nil(waiting) ->
        state

      _ ->
        Process.sleep(1)
        wait_for_admitted_write(pid, attempts - 1)
    end
  end

  defp wait_for_deferred_input(pid, minimum_events, attempts \\ 200)
  defp wait_for_deferred_input(_pid, _minimum_events, 0), do: flunk("TLS input was not deferred")

  defp wait_for_deferred_input(pid, minimum_events, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{input: input}} ->
        if :queue.len(input) >= minimum_events do
          :ok
        else
          Process.sleep(1)
          wait_for_deferred_input(pid, minimum_events, attempts - 1)
        end

      _ ->
        Process.sleep(1)
        wait_for_deferred_input(pid, minimum_events, attempts - 1)
    end
  end

  defp wait_for_writer_idle(writer, attempts \\ 200)
  defp wait_for_writer_idle(_writer, 0), do: flunk("application writer did not finish its output")

  defp wait_for_writer_idle(writer, attempts) do
    case Process.info(writer, [:status, :current_function, :messages]) do
      [status: :waiting, current_function: {SSL.ConnectionWriter, :loop, 2}, messages: []] ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_writer_idle(writer, attempts - 1)
    end
  end

  defp wait_for_peer_shutdown(pid, attempts \\ 200)
  defp wait_for_peer_shutdown(_pid, 0), do: flunk("peer shutdown did not finish")

  defp wait_for_peer_shutdown(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{closed: true, tcp: nil, output: nil} = state} ->
        state

      _ ->
        Process.sleep(1)
        wait_for_peer_shutdown(pid, attempts - 1)
    end
  end

  defp wait_for_closed_writer_cleanup(pid, attempts \\ 200)
  defp wait_for_closed_writer_cleanup(_pid, 0), do: flunk("closed writer was not cleaned up")

  defp wait_for_closed_writer_cleanup(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{closed: true, writer: nil, writer_monitor: nil} = state} ->
        state

      _ ->
        Process.sleep(1)
        wait_for_closed_writer_cleanup(pid, attempts - 1)
    end
  end

  defp wait_for_write_release(pid, attempts \\ 200)
  defp wait_for_write_release(_pid, 0), do: flunk("write reservation was not released")

  defp wait_for_write_release(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{write: nil}} ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_write_release(pid, attempts - 1)
    end
  end
end
