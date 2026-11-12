defmodule SSL.ClientCloseRecvTest do
  # #164: client side of #163. After the peer closes, an exact-length recv larger
  # than the buffered plaintext must not report a terminal that hides it.
  use ExUnit.Case, async: true

  @dir Path.expand("../support/server", __DIR__)
  @total 8189

  # OTP 28 :ssl.shutdown(s, :write) on TLS 1.3 half-closes TCP without sending
  # close_notify, so the issue's reproduction is an unclean close.
  test "an unclean close keeps every byte before the unclean terminal" do
    s = closed_after_send(&:ssl.shutdown(&1, :write))

    assert SSL.recv(s, 16_384, 0) == {:error, :timeout}
    assert drain(s, 0) == {@total, {:error, :econnreset}}
    assert SSL.recv(s, 16_384, 200) == {:error, :econnreset}
  end

  test "a close_notify drains the buffer and then reports closed" do
    s = closed_after_send(&:ssl.close/1)

    assert SSL.recv(s, 16_384, 0) == {:error, :timeout}
    assert drain(s, 0) == {@total, {:error, :closed}}
    assert SSL.recv(s, 0, 200) == {:error, :closed}
  end

  for timeout <- [200, :infinity] do
    test "an unsatisfiable exact read with timeout #{timeout} returns promptly" do
      s = closed_after_send(&:ssl.close/1)

      task = Task.async(fn -> SSL.recv(s, 16_384, unquote(timeout)) end)
      assert Task.await(task, 1000) == {:error, :timeout}
      assert SSL.recv(s, @total, 0) == {:ok, :binary.copy("x", @total)}
      assert SSL.recv(s, 1, 0) == {:error, :closed}
    end
  end

  test "a pending exact read is released by the close without losing bytes" do
    {listen, port} = listen()
    test = self()

    peer =
      Task.async(fn ->
        {:ok, c} = :ssl.transport_accept(listen, 5000)
        {:ok, c} = :ssl.handshake(c, 5000)
        receive do: (:go -> :ok)
        :ok = :ssl.send(c, :binary.copy("x", @total))
        :ok = :ssl.close(c)
        send(test, :sent)
      end)

    {:ok, s} = connect(port)
    task = Task.async(fn -> SSL.recv(s, 16_384, 5000) end)
    await_state(s, &match?({_, %{recv: %{}}}, &1))
    send(peer.pid, :go)
    assert_receive :sent, 2000
    assert Task.await(task, 1000) == {:error, :timeout}
    assert SSL.recv(s, 0, 0) == {:ok, :binary.copy("x", @total)}
    assert SSL.recv(s, 0, 0) == {:error, :closed}
    Task.await(peer)
    :ssl.close(listen)
  end

  test "active once still delivers the buffered bytes before ssl_closed" do
    s = closed_after_send(&:ssl.close/1)

    assert :ok = SSL.setopts(s, active: :once)
    assert_receive {:ssl, ^s, bytes}, 1000
    assert byte_size(bytes) == @total
    assert_receive {:ssl_closed, ^s}, 1000
  end

  # The peer sends @total bytes and closes with `close`; returns the client
  # socket once it has buffered every byte and processed the close.
  defp closed_after_send(close) do
    {listen, port} = listen()
    on_exit(fn -> :ssl.close(listen) end)

    peer =
      Task.async(fn ->
        {:ok, c} = :ssl.transport_accept(listen, 5000)
        {:ok, c} = :ssl.handshake(c, 5000)
        :ok = :ssl.send(c, :binary.copy("x", @total))
        :ok = close.(c)
      end)

    {:ok, s} = connect(port)
    Task.await(peer)
    await_state(s, &match?({_, %{size: @total, closed: true}}, &1))
    s
  end

  defp drain(s, acc) do
    case SSL.recv(s, 1, 0) do
      {:ok, bytes} -> drain(s, acc + byte_size(bytes))
      other -> {acc, other}
    end
  end

  defp listen do
    {:ok, listen} =
      :ssl.listen(0,
        mode: :binary,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1},
        certfile: Path.join(@dir, "cert.pem") |> String.to_charlist(),
        keyfile: Path.join(@dir, "key.pem") |> String.to_charlist(),
        log_level: :none
      )

    {:ok, {_, port}} = :ssl.sockname(listen)
    {listen, port}
  end

  defp connect(port),
    do: SSL.connect(~c"127.0.0.1", port, [verify: :verify_none, active: false], 5000)

  defp await_state(s, match?, attempts \\ 1000)
  defp await_state(_s, _match?, 0), do: flunk("client did not reach the expected state")

  defp await_state(s, match?, attempts) do
    if match?.(:sys.get_state(s.pid)) do
      :ok
    else
      Process.sleep(2)
      await_state(s, match?, attempts - 1)
    end
  end
end
