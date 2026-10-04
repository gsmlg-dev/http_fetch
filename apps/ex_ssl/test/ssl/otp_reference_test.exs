defmodule SSL.OTPReferenceTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer

  @moduletag :otp_reference
  @moduletag :integration

  test "OTP ssl recv with a positive length preserves the surplus" do
    {:ok, peer} = LocalTLSPeer.start(fn socket -> :ok = :ssl.send(socket, "abcdef") end)
    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:ok, "abc"} = :ssl.recv(socket, 3, 1_000)
    assert {:ok, "def"} = :ssl.recv(socket, 3, 1_000)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl recv zero returns decrypted application bytes" do
    {:ok, peer} = LocalTLSPeer.start(fn socket -> :ok = :ssl.send(socket, "available") end)
    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:ok, "available"} = :ssl.recv(socket, 0, 1_000)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl recv exact-length timeout does not return partial plaintext" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        :ok = :ssl.send(socket, "abc")
        Process.sleep(150)
        :ok = :ssl.send(socket, "def")
      end)

    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:error, :timeout} = :ssl.recv(socket, 6, 25)
    assert {:ok, "abcdef"} = :ssl.recv(socket, 6, 1_000)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  @tag capture_log: true
  test "OTP timer edge accepts durations beyond 32 bits but rejects an unrepresentable deadline" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        :ok = :ssl.send(socket, "a")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)
    assert {:ok, "a"} = :ssl.recv(socket, 1, 4_294_967_296)

    end_time =
      :erlang.system_info(:end_time)
      |> :erlang.convert_time_unit(:native, :millisecond)

    unrepresentable_timeout = end_time - System.monotonic_time(:millisecond) + 1_000
    assert catch_exit(:ssl.recv(socket, 1, unrepresentable_timeout))
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl serializes concurrent passive receives" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        Process.sleep(50)
        :ok = :ssl.send(socket, "one")
        :ok = :ssl.send(socket, "two")
      end)

    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)
    parent = self()

    pids =
      for label <- [:first, :second] do
        spawn(fn -> send(parent, {label, :ssl.recv(socket, 3, 1_000)}) end)
      end

    assert_receive {label, {:ok, "one"}}, 1_500
    other_label = if label == :first, do: :second, else: :first
    refute_receive {^other_label, _result}, 100

    assert :ok = :ssl.close(socket)
    assert_receive {^other_label, {:error, :closed}}, 1_500
    assert Enum.all?(pids, &(!Process.alive?(&1)))
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ssl closed-socket operations include its send shutdown race" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, socket} = :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = :ssl.close(socket)
    # OTP's sender can still be shutting down when close/1 returns. OTP 28 CI
    # independently observes :einval here; after sender exit it returns :closed.
    assert :ssl.send(socket, "after-close") in [{:error, :closed}, {:error, :einval}]
    assert {:error, :closed} = :ssl.recv(socket, 0, 0)
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP active once delivers one message without ssl_passive" do
    parent = self()

    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        receive do
          :send -> :ok
        end

        :ok = :ssl.send(socket, "active-once")
        send(parent, :otp_active_sent)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, socket} =
      :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = :ssl.setopts(socket, active: :once)
    assert {:error, :einval} = :ssl.recv(socket, 1, 0)
    send(peer.task.pid, :send)
    assert_receive :otp_active_sent
    assert_receive {:ssl, ^socket, "active-once"}, 1_000
    refute_receive {:ssl_passive, ^socket}, 20
    assert :ok = :ssl.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "OTP ownership probe permits a non-owner no-op and may admit a dead target" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        drain_until_closed(socket)
      end)

    {:ok, socket} =
      :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    owner = self()
    non_owner = Task.async(fn -> :ssl.controlling_process(socket, owner) end)

    # OTP 28 permits this call even though the task is not the owner. ex_ssl
    # deliberately enforces the task contract's stricter current-owner rule.
    assert :ok = Task.await(non_owner)

    dead =
      spawn(fn ->
        receive do
          :exit -> :ok
        end
      end)

    monitor = Process.monitor(dead)
    send(dead, :exit)
    assert_receive {:DOWN, ^monitor, :process, ^dead, :normal}

    # OTP 28 returns :ok and then closes asynchronously; some later OTP builds
    # reject the target before committing. ex_ssl deliberately uses the latter,
    # deterministic behavior while leaving the live socket untouched.
    case :ssl.controlling_process(socket, dead) do
      :ok -> assert eventually_closed(socket)
      {:error, :noproc} -> assert :ok = :ssl.close(socket)
    end

    assert :ok = LocalTLSPeer.stop(peer)
  end

  defp eventually_closed(socket, attempts \\ 100)
  defp eventually_closed(_socket, 0), do: false

  defp eventually_closed(socket, attempts) do
    case :ssl.send(socket, "probe") do
      {:error, _reason} ->
        true

      :ok ->
        Process.sleep(1)
        eventually_closed(socket, attempts - 1)
    end
  end

  defp drain_until_closed(socket) do
    case :ssl.recv(socket, 0, 5_000) do
      {:ok, _bytes} -> drain_until_closed(socket)
      {:error, :closed} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end
