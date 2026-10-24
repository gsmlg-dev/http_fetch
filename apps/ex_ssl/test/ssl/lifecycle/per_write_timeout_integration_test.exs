defmodule SSL.Lifecycle.PerWriteTimeoutIntegrationTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{LocalTLSPeer, OpenSSLPeer}
  alias SSL.Lifecycle

  @moduletag :integration
  @payload :binary.copy("x", 65_536)
  @cipher %{key_exchange: :ecdhe_rsa, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    @version version

    test "#{version} non-owner sends have a budget without owner mutation" do
      {socket, _peer, handle, _lease} = fixture(@version)
      outsider = Task.async(fn -> SSL.setopts(socket, send_timeout: 1) end)
      assert {:error, :not_owner} = Task.await(outsider)
      frame = <<4::32, "ping">>
      sender = Task.async(fn -> SSL.send(socket, frame, deadline(1_000)) end)
      assert :ok = Task.await(sender, 2_000)
      assert {:ok, ^frame} = SSL.recv(socket, byte_size(frame), 2_000)
      {:connected, state} = :sys.get_state(socket.pid)
      assert state.owner == self()
      assert state.send_timeout == 2_000
      assert :ok = SSL.close(socket)
      confirmed(handle)
    end

    test "#{version} invalid, expired and queued-past-deadline sends emit no bytes" do
      {socket, _peer, handle, _lease} = fixture(@version)
      assert {:error, :badarg} = SSL.send(socket, "invalid", :infinity)
      assert {:error, :badarg} = SSL.send(socket, "invalid", {:abs_ms, :invalid})

      assert {:error, :badarg} =
               SSL.send(socket, "invalid", {:abs_ms, 1_000_000_000_000_000_000_000})

      assert {:error, :timeout} = SSL.send(socket, "expired", deadline(-1))
      assert true = :erlang.suspend_process(socket.pid)
      sender = Task.async(fn -> SSL.send(socket, "queued", deadline(80)) end)

      try do
        await_queued(sender.pid, monotonic() + 1_000)

        receive do
        after
          100 -> :ok
        end
      after
        assert true = :erlang.resume_process(socket.pid)
      end

      assert {:error, :timeout} = Task.await(sender, 1_000)
      frame = <<5::32, "fresh">>
      assert :ok = SSL.send(socket, frame, deadline(1_000))
      assert {:ok, ^frame} = SSL.recv(socket, byte_size(frame), 2_000)
      assert :ok = SSL.close(socket)
      confirmed(handle)
    end

    test "#{version} a shorter owner timeout caps a longer supplied deadline" do
      {socket, _peer, handle, _lease} = fixture(@version, 200)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(initial.writer)
      entered = monotonic()
      sender = Task.async(fn -> SSL.send(socket, @payload, deadline(2_000)) end)
      pending = pending(socket.pid, monotonic() + 1_000)
      assert pending.write.deadline <= entered + 250
      assert pending.output.deadline <= pending.write.deadline
      assert pending.send_timeout == 200
      assert {:error, :timeout} = Task.await(sender, 1_000)
      assert monotonic() - entered < 1_000
      confirmed(handle)
    end

    test "#{version} legacy zero-timeout send retains fail-close and busy precedence" do
      {socket, _peer, handle, _lease} = fixture(@version)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(initial.writer)
      sender = Task.async(fn -> SSL.send(socket, @payload, deadline(1_500)) end)
      pending(socket.pid, monotonic() + 1_000)
      assert :ok = SSL.setopts(socket, send_timeout: 0)
      assert {:error, :busy} = SSL.send(socket, "busy")
      assert :ok = SSL.close(socket)
      assert {:error, _} = Task.await(sender, 1_000)
      confirmed(handle)

      {zero_socket, _peer, zero_handle, _lease} = fixture(@version)
      assert :ok = SSL.setopts(zero_socket, send_timeout: 0)
      assert {:error, :timeout} = SSL.send(zero_socket, "zero")
      confirmed(zero_handle)
    end

    test "#{version} queued protected records keep the original per-send deadline" do
      {socket, _peer, handle, _lease} = fixture(@version)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(initial.writer)
      absolute = deadline(250)
      sender = Task.async(fn -> SSL.send(socket, @payload, absolute) end)
      pending = pending(socket.pid, monotonic() + 1_000)
      assert pending.write.deadline == elem(absolute, 1)
      assert pending.output.deadline == elem(absolute, 1)
      assert :ok = SSL.setopts(socket, send_timeout: 10_000)
      assert {:error, :timeout} = Task.await(sender, 1_000)
      confirmed(handle)
    end

    test "#{version} bounded non-owner output retains duplex reads and abandon" do
      {socket, _peer, handle, _lease} = fixture(@version)
      assert :ok = SSL.enable_duplex_reads(socket)
      frame = <<8::32, "response">>
      assert :ok = SSL.send(socket, frame)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert true = :erlang.suspend_process(initial.writer)
      sender = Task.async(fn -> SSL.send(socket, @payload, deadline(1_500)) end)
      held = pending(socket.pid, monotonic() + 1_000)
      assert {:error, :busy} = SSL.send(socket, "competing", deadline(500))
      assert {:ok, ^frame} = SSL.recv(socket, byte_size(frame), 1_000)
      {:connected, read} = :sys.get_state(socket.pid)
      assert read.output == held.output
      assert :ok = SSL.abandon_send(socket)
      assert {:error, :write_abandoned} = Task.await(sender, 1_000)
      {:connected, abandoned} = :sys.get_state(socket.pid)
      assert abandoned.output == held.output
      assert abandoned.write == nil
      assert :ok = SSL.close(socket)
      confirmed(handle)
    end

    for action <- [:cancel, :sender_death] do
      test "#{version} #{action} joins a pending bounded send" do
        {socket, _peer, handle, lease} = fixture(@version)
        {:connected, initial} = :sys.get_state(socket.pid)
        assert true = :erlang.suspend_process(initial.writer)
        parent = self()

        {sender, monitor} =
          spawn_monitor(fn ->
            send(parent, {:send_result, SSL.send(socket, @payload, deadline(1_500))})
          end)

        pending(socket.pid, monotonic() + 1_000)

        case unquote(action) do
          :cancel ->
            assert :ok = Lifecycle.cancel(lease, deadline(1_000))
            assert_receive {:send_result, {:error, _}}, 1_000
            assert_receive {:DOWN, ^monitor, :process, ^sender, :normal}, 1_000

          :sender_death ->
            Process.exit(sender, :kill)
            assert_receive {:DOWN, ^monitor, :process, ^sender, :killed}, 1_000
        end

        confirmed(handle)
      end
    end
  end

  defp fixture(version, timeout \\ 2_000) do
    tls_options = if version == :"tlsv1.2", do: [ciphers: [@cipher]], else: []
    peer_version = if version == :"tlsv1.2", do: :tls12, else: :tls13

    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: Path.expand("../../fixtures/server_flight/leaf-rsa.pem", __DIR__),
        keyfile: Path.expand("../../fixtures/server_flight/leaf-rsa-key.pem", __DIR__),
        min_version: peer_version,
        max_version: peer_version,
        delay_ms: 300
      )

    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)

    options =
      [
        :binary
        | Keyword.merge(tl(LocalTLSPeer.client_options()),
            versions: [version],
            send_timeout: timeout,
            server_name_indication: ~c"example.test",
            cacerts: [
              LocalTLSPeer.certificate_from_pem!(
                Path.expand("../../fixtures/server_flight/root.pem", __DIR__)
              )
            ]
          )
      ] ++
        tls_options ++
        [ex_ssl: [lifecycle: {handle, lease}]]

    {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 3_000)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(1_000))
      Lifecycle.await(handle, deadline(2_000))
      OpenSSLPeer.stop(peer)
    end)

    {socket, peer, handle, lease}
  end

  defp pending(pid, deadline) do
    case :sys.get_state(pid, max(deadline - monotonic(), 1)) do
      {:connected, %{output: %{kind: :application}, write: %{from: from}} = state}
      when not is_nil(from) ->
        state

      _ ->
        assert monotonic() < deadline

        receive do
        after
          1 -> pending(pid, deadline)
        end
    end
  end

  defp await_queued(sender, deadline) do
    if Process.info(sender, :current_function) == {:current_function, {:gen, :do_call, 4}} and
         Process.info(sender, :status) == {:status, :waiting} do
      :ok
    else
      assert monotonic() < deadline

      receive do
      after
        1 -> await_queued(sender, deadline)
      end
    end
  end

  defp confirmed(handle) do
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
  end

  defp monotonic, do: System.monotonic_time(:millisecond)
  defp deadline(ms), do: {:abs_ms, monotonic() + ms}
end
