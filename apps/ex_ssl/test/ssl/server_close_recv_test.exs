defmodule SSL.ServerCloseRecvTest do
  # #163: after the peer closes, an exact-length recv larger than the buffered
  # plaintext must not report a terminal that hides that plaintext.
  use ExUnit.Case, async: true

  @dir Path.expand("../support/server", __DIR__)
  @server [
    certfile: Path.join(@dir, "cert.pem"),
    keyfile: Path.join(@dir, "key.pem"),
    ip: {127, 0, 0, 1}
  ]
  @total 8189

  setup do
    {:ok, _} = Application.ensure_all_started(:ssl)
    {:ok, listen} = SSL.listen(0, @server)
    on_exit(fn -> SSL.close(listen) end)
    {:ok, {_, port}} = SSL.sockname(listen)
    %{listen: listen, port: port}
  end

  # OTP 28 :ssl.shutdown(c, :write) on TLS 1.3 half-closes TCP without sending
  # close_notify, so the issue's reproduction is an unclean close.
  test "the issue reproduction keeps every byte before the unclean terminal", ctx do
    s = closed_after_send(ctx, &:ssl.shutdown(&1, :write))

    assert SSL.recv(s, 16_384, 0) == {:error, :timeout}
    assert drain(s, 0) == {@total, {:error, :econnreset}}
    assert SSL.recv(s, 16_384, 200) == {:error, :econnreset}
  end

  test "a close_notify drains the buffer and then reports closed", ctx do
    s = closed_after_send(ctx, &:ssl.close/1)

    assert SSL.recv(s, 16_384, 0) == {:error, :timeout}
    assert drain(s, 0) == {@total, {:error, :closed}}
    assert SSL.recv(s, 0, 200) == {:error, :closed}
  end

  for timeout <- [200, :infinity] do
    test "an unsatisfiable exact read with timeout #{timeout} returns promptly", ctx do
      s = closed_after_send(ctx, &:ssl.close/1)

      task = Task.async(fn -> SSL.recv(s, 16_384, unquote(timeout)) end)
      assert Task.await(task, 1000) == {:error, :timeout}
      assert SSL.recv(s, @total, 0) == {:ok, :binary.copy("x", @total)}
      assert SSL.recv(s, 1, 0) == {:error, :closed}
    end
  end

  test "a pending exact read is released by the close without losing bytes", ctx do
    test = self()

    client =
      client(ctx.port, fn c ->
        receive do: (:go -> :ok)
        :ok = :ssl.send(c, :binary.copy("x", @total))
        :ok = :ssl.close(c)
        send(test, :sent)
      end)

    s = accept(ctx.listen)
    task = Task.async(fn -> SSL.recv(s, 16_384, 5000) end)
    await_state(s, &match?({:connected, %{recv: %{}}}, &1))
    send(client.pid, :go)
    assert_receive :sent, 2000
    assert Task.await(task, 1000) == {:error, :timeout}
    assert SSL.recv(s, 0, 0) == {:ok, :binary.copy("x", @total)}
    assert SSL.recv(s, 0, 0) == {:error, :closed}
    Task.await(client)
  end

  test "active once still delivers the buffered bytes before ssl_closed", ctx do
    s = closed_after_send(ctx, &:ssl.close/1)

    assert :ok = SSL.setopts(s, active: :once)
    assert_receive {:ssl, ^s, bytes}, 1000
    assert byte_size(bytes) == @total
    assert_receive {:ssl_closed, ^s}, 1000
  end

  # Sends @total bytes, closes with `close`, and returns the accepted server
  # socket once it has buffered every byte and processed the close.
  defp closed_after_send(ctx, close) do
    client =
      client(ctx.port, fn c ->
        :ok = :ssl.send(c, :binary.copy("x", @total))
        :ok = close.(c)
      end)

    s = accept(ctx.listen)
    await_state(s, &match?({:closing, %{size: @total}}, &1))
    Task.await(client)
    s
  end

  defp drain(s, acc) do
    case SSL.recv(s, 1, 0) do
      {:ok, bytes} -> drain(s, acc + byte_size(bytes))
      other -> {acc, other}
    end
  end

  defp accept(listen) do
    {:ok, s} = SSL.transport_accept(listen, 5000)
    {:ok, s} = SSL.handshake(s, 5000)
    s
  end

  defp client(port, script) do
    Task.async(fn ->
      {:ok, c} =
        :ssl.connect(
          {127, 0, 0, 1},
          port,
          [mode: :binary, active: false, verify: :verify_none, log_level: :none],
          5000
        )

      script.(c)
    end)
  end

  defp await_state(s, match?, attempts \\ 1000)
  defp await_state(_s, _match?, 0), do: flunk("server did not reach the expected state")

  defp await_state(s, match?, attempts) do
    if match?.(:sys.get_state(s.pid)) do
      :ok
    else
      Process.sleep(2)
      await_state(s, match?, attempts - 1)
    end
  end
end
