defmodule SSL.TransportCloseDeliveryTest do
  # Regression coverage for #158: a peer that ends TCP without close_notify must
  # not discard authenticated plaintext the client has decrypted but not read.
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  @moduletag :integration

  @chunks for index <- 1..12, do: String.duplicate(<<?a + rem(index, 26)>>, 1_000 + index)
  @body IO.iodata_to_binary(@chunks)

  describe "TCP close without close_notify" do
    test "passive recv drains every buffered byte before {:error, :closed}" do
      {socket, peer} = connect_and_close(:fin)
      await_transport_terminal(socket)

      assert @body == recv_all(socket, [])
      assert {:error, :closed} = SSL.recv(socket, 0, 0)
      assert :ok = SSL.close(socket)
      stop_peer(peer)
    end

    test "a pending recv receives data then :closed" do
      {socket, peer} = connect_and_close(:fin)
      assert @body == recv_all(socket, [], 5_000)
      assert {:error, :closed} = SSL.recv(socket, 0, 0)
      stop_peer(peer)
    end

    test "active once delivers buffered bytes before {:ssl_closed, socket}" do
      {socket, peer} = connect_and_close(:fin)
      await_transport_terminal(socket)

      assert :ok = SSL.setopts(socket, active: :once)
      assert_receive {:ssl, ^socket, bytes}, 5_000
      assert bytes == @body
      assert_receive {:ssl_closed, ^socket}, 5_000
      refute_receive {:ssl_error, ^socket, _}, 20
      assert {:error, :closed} = SSL.recv(socket, 0, 0)
      stop_peer(peer)
    end

    test "writes fail after the transport closed instead of retrying" do
      {socket, peer} = connect_and_close(:fin)
      await_transport_terminal(socket)

      assert {:error, :closed} = SSL.send(socket, "no write on a dead transport")
      assert @body == recv_all(socket, [])
      stop_peer(peer)
    end
  end

  describe "TCP reset after data" do
    test "a real reset still delivers bytes already decrypted" do
      {socket, peer} = connect_and_close(:buffered_reset)
      await_transport_terminal(socket)

      assert @body == recv_all(socket, [])
      assert {:error, reason} = SSL.recv(socket, 0, 0)
      assert reason in [:closed, :econnreset]
      stop_peer(peer)
    end

    test "a transport error reports its reason after buffered plaintext" do
      {socket, peer} = connect_and_close(:none)
      await_buffered(socket, byte_size(@body))
      {:connected, %{tcp: tcp}} = :sys.get_state(socket.pid)
      send(socket.pid, {:tcp_error, tcp, :econnreset})
      await_transport_terminal(socket)

      assert @body == recv_all(socket, [])
      assert {:error, :econnreset} = SSL.recv(socket, 0, 0)
      stop_peer(peer)
    end

    test "active once reports the transport error after delivering buffered bytes" do
      {socket, peer} = connect_and_close(:none)
      await_buffered(socket, byte_size(@body))
      {:connected, %{tcp: tcp}} = :sys.get_state(socket.pid)
      send(socket.pid, {:tcp_error, tcp, :econnreset})
      await_transport_terminal(socket)

      assert :ok = SSL.setopts(socket, active: :once)
      assert_receive {:ssl, ^socket, bytes}, 5_000
      assert bytes == @body
      assert_receive {:ssl_error, ^socket, :econnreset}, 5_000
      refute_receive {:ssl_closed, ^socket}, 20
      stop_peer(peer)
    end
  end

  defp connect_and_close(mode) do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)
    %{certfile: certfile, keyfile: keyfile} = Peer.certificates()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 5_000)

        {:ok, tls} =
          :ssl.handshake(
            tcp,
            [
              certfile: String.to_charlist(certfile),
              keyfile: String.to_charlist(keyfile),
              versions: [:"tlsv1.3"],
              verify: :verify_none,
              active: false,
              mode: :binary,
              packet: :raw
            ],
            5_000
          )

        Enum.each(@chunks, &(:ok = :ssl.send(tls, &1)))
        send(parent, {:peer_sent, self()})

        receive do
          {:close, :none} ->
            receive do
              :stop -> :ok
            end

          {:close, how} ->
            # Close the carrier underneath :ssl so no close_notify is sent.
            if how == :reset, do: :ok = :inet.setopts(tcp, linger: {true, 0})
            :ok = :gen_tcp.close(tcp)
        end

        :gen_tcp.close(listener)
      end)

    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", port, Peer.client_options(), 5_000)
    assert_receive {:peer_sent, peer_pid}, 5_000

    case mode do
      :fin ->
        send(peer_pid, {:close, :fin})

      :buffered_reset ->
        await_buffered(socket, byte_size(@body))
        send(peer_pid, {:close, :reset})

      :none ->
        send(peer_pid, {:close, :none})
    end

    {socket, task}
  end

  defp stop_peer(task) do
    send(task.pid, :stop)
    Task.await(task, 5_000)
  end

  defp recv_all(socket, acc, timeout \\ 0) do
    case SSL.recv(socket, 0, timeout) do
      {:ok, bytes} -> recv_all(socket, [acc | bytes], timeout)
      {:error, _reason} -> IO.iodata_to_binary(acc)
    end
  end

  # Wait until the connection has observed the transport terminal, so reads
  # happen strictly after the close without relying on timing.
  defp await_transport_terminal(socket, attempts \\ 500)
  defp await_transport_terminal(_socket, 0), do: flunk("transport terminal was not observed")

  defp await_transport_terminal(socket, attempts) do
    case connection_state(socket) do
      %{closed: true} ->
        :ok

      :down ->
        :ok

      _ ->
        Process.sleep(2)
        await_transport_terminal(socket, attempts - 1)
    end
  end

  defp await_buffered(socket, size, attempts \\ 500)
  defp await_buffered(_socket, _size, 0), do: flunk("plaintext was not buffered")

  defp await_buffered(socket, size, attempts) do
    case connection_state(socket) do
      %{size: ^size} ->
        :ok

      _ ->
        Process.sleep(2)
        await_buffered(socket, size, attempts - 1)
    end
  end

  defp connection_state(socket) do
    {_phase, state} = :sys.get_state(socket.pid)
    state
  catch
    :exit, _ -> :down
  end
end
