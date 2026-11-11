defmodule SSL.ServerBlockedWriteTest do
  # #161: a server application write blocked by a peer that does not read must
  # not stop receive delivery or control calls; only the writer waits.
  use ExUnit.Case, async: true

  @dir Path.expand("../support/server", __DIR__)
  @server [
    certfile: Path.join(@dir, "cert.pem"),
    keyfile: Path.join(@dir, "key.pem"),
    ip: {127, 0, 0, 1},
    sndbuf: 4096
  ]
  @chunk :binary.copy("w", 65_536)
  @prompt 1000

  setup do
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  test "input is delivered and control calls answer while a write is blocked" do
    %{server: s, client: client} = connect([])
    writer = blocked_writer(s)

    assert :ok = on_client(client, &:ssl.send(&1, "ping-while-writer-blocked"))
    assert prompt(fn -> SSL.setopts(s, active: :once) end) == :ok
    assert_receive {:ssl, ^s, "ping-while-writer-blocked"}, 2000

    assert prompt(fn -> SSL.peercert(s) end) == {:error, :no_peercert}

    assert {:ok, [active: false, sndbuf: _]} =
             prompt(fn -> SSL.getopts(s, [:active, :sndbuf]) end)

    assert {:ok, {{127, 0, 0, 1}, _}} = prompt(fn -> SSL.peername(s) end)
    assert prompt(fn -> SSL.setopts(s, active: false) end) == :ok

    assert :ok = on_client(client, &:ssl.send(&1, "passive"))
    assert prompt(fn -> SSL.recv(s, 7, 2000) end) == {:ok, "passive"}

    assert prompt(fn -> SSL.close(s) end) == :ok
    assert_receive {:writer_done, ^writer, {:error, :closed}}, @prompt
    stop_client(client)
  end

  test "a peer KeyUpdate during a blocked write keeps both directions in order" do
    %{server: s, client: client} = connect([])
    writer = blocked_writer(s, 64)

    assert :ok = on_client(client, &:ssl.update_keys(&1, :read_write))
    assert :ok = on_client(client, &:ssl.send(&1, "after-update"))
    assert prompt(fn -> SSL.recv(s, 12, 2000) end) == {:ok, "after-update"}

    # The server's KeyUpdate reply is queued after the records already protected
    # under the old key, so the client decrypts every byte in order.
    expected = 64 * byte_size(@chunk)
    assert on_client(client, &read_all(&1, expected, 0)) == {:ok, expected}
    assert_receive {:writer_done, ^writer, :all_sent}, 5000

    assert :ok = SSL.send(s, "server-after")
    assert on_client(client, &:ssl.recv(&1, 12, 2000)) == {:ok, "server-after"}
    SSL.close(s)
    stop_client(client)
  end

  test "a concurrent reservation waits for the in-flight write and follows it" do
    %{server: s, client: client} = connect([])
    test = self()
    big = :binary.copy("w", 64 * 1_048_576)
    spawn_link(fn -> send(test, {:first, SSL.send(s, big)}) end)
    await_application_job(s)

    spawn_link(fn -> send(test, {:second, SSL.send(s, "tail")}) end)
    refute_receive {:second, _}, 300
    await_application_job(s)

    total = byte_size(big) + 4
    assert {:ok, bytes} = on_client(client, &read_bytes(&1, total, []))
    assert binary_part(bytes, total - 4, 4) == "tail"
    assert_receive {:first, :ok}, 5000
    assert_receive {:second, :ok}, 5000
    SSL.close(s)
    stop_client(client)
  end

  test "the carrier send_timeout still bounds the blocked writer" do
    %{server: s, client: client} = connect(send_timeout: 300)
    test = self()
    started = System.monotonic_time(:millisecond)
    spawn_link(fn -> send(test, {:result, write_until_error(s)}) end)

    assert :ok = on_client(client, &:ssl.send(&1, "early"))
    assert prompt(fn -> SSL.recv(s, 5, 2000) end) == {:ok, "early"}
    assert_receive {:result, {:error, :timeout}}, 5000
    assert System.monotonic_time(:millisecond) - started >= 300
    assert {:error, _} = SSL.recv(s, 0, 200)
    stop_client(client)
  end

  test "a send deadline bounds the blocked write" do
    %{server: s, client: client} = connect([])
    test = self()

    spawn_link(fn ->
      deadline = System.monotonic_time(:millisecond) + 300
      send(test, {:result, send_until_error(s, {:abs_ms, deadline})})
    end)

    assert_receive {:result, {:error, :timeout}}, 5000
    assert {:error, _} = SSL.recv(s, 0, 200)
    stop_client(client)
  end

  test "a peer close_notify settles the blocked write as closed after earlier input" do
    %{server: s, client: client} = connect([])
    writer = blocked_writer(s)

    assert :ok = on_client(client, &:ssl.send(&1, "bye"))
    assert :ok = on_client(client, &:ssl.close/1)
    assert_receive {:writer_done, ^writer, {:error, :closed}}, 2000
    assert SSL.recv(s, 3, 1000) == {:ok, "bye"}
    assert SSL.recv(s, 0, 1000) == {:error, :closed}
    stop_client(client)
  end

  test "owner death during a blocked write releases the writer" do
    %{server: s, client: client} = connect([])

    owner =
      spawn(fn ->
        receive do: (:stop -> :ok)
      end)

    assert :ok = SSL.controlling_process(s, owner)
    writer = blocked_writer(s)
    monitor = Process.monitor(s.pid)
    send(owner, :stop)
    assert_receive {:writer_done, ^writer, {:error, :closed}}, @prompt
    assert_receive {:DOWN, ^monitor, :process, _, _}, @prompt
    stop_client(client)
  end

  defp connect(extra) do
    {:ok, listen} = SSL.listen(0, Keyword.merge(@server, extra))
    on_exit(fn -> SSL.close(listen) end)
    {:ok, {_, port}} = SSL.sockname(listen)
    client = client(port)
    {:ok, s} = SSL.transport_accept(listen, 5000)
    {:ok, s} = SSL.handshake(s, 5000)
    %{server: s, client: client}
  end

  # Writes @chunk until a write blocks for 300 ms, then returns the writer pid;
  # it reports {:writer_done, pid, result} when a write fails or `count` succeed.
  defp blocked_writer(s, count \\ 1000) do
    test = self()

    writer =
      spawn_link(fn ->
        result =
          Enum.reduce_while(1..count, :all_sent, fn _, acc ->
            case SSL.send(s, @chunk) do
              :ok ->
                send(test, {:wrote, self()})
                {:cont, acc}

              error ->
                {:halt, error}
            end
          end)

        send(test, {:writer_done, self(), result})
      end)

    await_stall(writer)
    await_application_job(s)
    writer
  end

  defp await_stall(writer) do
    receive do
      {:wrote, ^writer} -> await_stall(writer)
    after
      300 -> :ok
    end
  end

  defp await_application_job(s, attempts \\ 500)
  defp await_application_job(_s, 0), do: flunk("no application write in flight")

  defp await_application_job(s, attempts) do
    {_name, data} = :sys.get_state(s.pid)

    if Enum.any?(:queue.to_list(data.jobs), &(&1.kind == :application)) do
      :ok
    else
      Process.sleep(5)
      await_application_job(s, attempts - 1)
    end
  end

  defp write_until_error(s) do
    case SSL.send(s, @chunk) do
      :ok -> write_until_error(s)
      error -> error
    end
  end

  defp send_until_error(s, deadline) do
    case SSL.send(s, @chunk, deadline) do
      :ok -> send_until_error(s, deadline)
      error -> error
    end
  end

  defp prompt(fun) do
    task = Task.async(fun)

    case Task.yield(task, @prompt) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      nil -> flunk("server call did not return within #{@prompt} ms")
    end
  end

  # A passive OTP client with a small receive buffer that reads only on request.
  defp client(port) do
    Task.async(fn ->
      {:ok, c} =
        :ssl.connect(
          {127, 0, 0, 1},
          port,
          [
            mode: :binary,
            active: false,
            verify: :verify_none,
            recbuf: 4096,
            log_level: :none
          ],
          5000
        )

      client_loop(c)
    end)
  end

  defp client_loop(c) do
    receive do
      {:run, from, fun} ->
        send(from, {:ran, fun.(c)})
        client_loop(c)

      :stop ->
        :ok
    end
  end

  defp on_client(client, fun) do
    send(client.pid, {:run, self(), fun})
    assert_receive {:ran, result}, 10_000
    result
  end

  defp stop_client(client) do
    send(client.pid, :stop)
    Task.await(client)
  end

  defp read_all(_c, expected, total) when total >= expected, do: {:ok, total}

  defp read_all(c, expected, total) do
    case :ssl.recv(c, 0, 5000) do
      {:ok, bytes} ->
        if bytes == :binary.copy("w", byte_size(bytes)),
          do: read_all(c, expected, total + byte_size(bytes)),
          else: {:error, :corrupt}

      error ->
        error
    end
  end

  defp read_bytes(_c, remaining, acc) when remaining <= 0,
    do: {:ok, IO.iodata_to_binary(Enum.reverse(acc))}

  defp read_bytes(c, remaining, acc) do
    case :ssl.recv(c, 0, 5000) do
      {:ok, bytes} -> read_bytes(c, remaining - byte_size(bytes), [bytes | acc])
      error -> error
    end
  end
end
