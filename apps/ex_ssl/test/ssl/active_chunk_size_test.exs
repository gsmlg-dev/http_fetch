defmodule SSL.ActiveChunkSizeTest do
  # Bounded plaintext per active-once message (#169).
  use ExUnit.Case, async: true

  @dir Path.expand("../support/server", __DIR__)
  @cert Path.join(@dir, "cert.pem")
  @key Path.join(@dir, "key.pem")
  @ca Path.join(@dir, "ca.pem")
  @server [certfile: @cert, keyfile: @key, ip: {127, 0, 0, 1}]
  @payload :crypto.strong_rand_bytes(300_000)

  setup do
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  test "listen and setopts validate active_chunk_size" do
    for value <- [0, -1, :bogus, 1.5] do
      assert SSL.listen(0, @server ++ [active_chunk_size: value]) ==
               {:error, {:invalid_option, :active_chunk_size}}
    end

    {listen, port} = listen(active_chunk_size: :infinity)
    client = otp_client(port, fn _c -> :ok end)
    {:ok, s} = accept(listen)

    assert {:error, {:options, {:active_chunk_size, :unsupported_or_invalid}}} =
             SSL.setopts(s, active_chunk_size: 0)

    assert :ok = SSL.setopts(s, active_chunk_size: 1024)
    finish(client)
    SSL.close(s)
  end

  test "a slow active-once server owner never receives more than active_chunk_size" do
    {listen, port} = listen(active_chunk_size: 16_384)
    client = otp_client(port, &send_pipelined/1)
    {:ok, s} = accept(listen)

    # The owner is slow: everything the client pipelined is buffered first.
    Process.sleep(300)
    chunks = collect_active(s, byte_size(@payload), [])

    assert Enum.all?(chunks, &(byte_size(&1) <= 16_384))
    assert Enum.any?(chunks, &(byte_size(&1) == 16_384))
    assert IO.iodata_to_binary(chunks) == @payload
    finish(client)
    SSL.close(s)
  end

  test "setopts changes the bound and recv/3 stays unbounded" do
    {listen, port} = listen([])
    client = otp_client(port, &send_pipelined/1)
    {:ok, s} = accept(listen)
    Process.sleep(300)

    assert :ok = SSL.setopts(s, active_chunk_size: 1_000)
    first = collect_active(s, 5_000, [])
    assert Enum.map(first, &byte_size/1) == List.duplicate(1_000, 5)

    {:ok, rest} = recv_all(s, byte_size(@payload) - 5_000, [])
    assert Enum.any?(rest, &(byte_size(&1) > 1_000))
    assert IO.iodata_to_binary([first | rest]) == @payload
    finish(client)
    SSL.close(s)
  end

  test "a client socket bounds active-once delivery after setopts" do
    {listen, port} = listen([])

    server =
      Task.async(fn ->
        {:ok, s} = accept(listen)
        send_pipelined_ex(s)
        receive do: (:finish -> SSL.close(s))
      end)

    {:ok, c} =
      SSL.connect(~c"localhost", port,
        verify: :verify_peer,
        cacertfile: @ca,
        server_name_indication: ~c"localhost"
      )

    assert :ok = SSL.setopts(c, active_chunk_size: 4_096)
    Process.sleep(300)
    chunks = collect_active(c, byte_size(@payload), [])

    assert Enum.all?(chunks, &(byte_size(&1) <= 4_096))
    assert IO.iodata_to_binary(chunks) == @payload
    SSL.close(c)
    finish(server)
  end

  defp send_pipelined(c) do
    for <<part::binary-size(1_000) <- @payload>>, do: :ok = :ssl.send(c, part)
    :ok
  end

  defp send_pipelined_ex(s) do
    for <<part::binary-size(1_000) <- @payload>>, do: :ok = SSL.send(s, part)
    :ok
  end

  defp collect_active(_s, remaining, acc) when remaining <= 0, do: Enum.reverse(acc)

  defp collect_active(s, remaining, acc) do
    :ok = SSL.setopts(s, active: :once)

    receive do
      {:ssl, ^s, bytes} -> collect_active(s, remaining - byte_size(bytes), [bytes | acc])
    after
      5_000 -> flunk("no active delivery with #{remaining} bytes outstanding")
    end
  end

  defp recv_all(_s, remaining, acc) when remaining <= 0, do: {:ok, Enum.reverse(acc)}

  defp recv_all(s, remaining, acc) do
    with {:ok, bytes} <- SSL.recv(s, 0, 5_000),
         do: recv_all(s, remaining - byte_size(bytes), [bytes | acc])
  end

  defp listen(extra) do
    {:ok, listen} = SSL.listen(0, @server ++ extra)
    on_exit(fn -> SSL.close(listen) end)
    {:ok, {_, port}} = SSL.sockname(listen)
    {listen, port}
  end

  defp accept(listen) do
    with {:ok, s} <- SSL.transport_accept(listen, 5000), do: SSL.handshake(s, 5000)
  end

  defp otp_client(port, script) do
    Task.async(fn ->
      {:ok, c} =
        :ssl.connect(
          {127, 0, 0, 1},
          port,
          [
            mode: :binary,
            active: false,
            versions: [:"tlsv1.3"],
            verify: :verify_peer,
            cacertfile: @ca,
            server_name_indication: ~c"localhost",
            log_level: :none
          ],
          5000
        )

      result = script.(c)
      receive do: (:finish -> :ssl.close(c))
      result
    end)
  end

  defp finish(task) do
    send(task.pid, :finish)
    Task.await(task)
  end
end
