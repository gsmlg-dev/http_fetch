defmodule HTTP.HTTP2BlockedWriterTest do
  use ExUnit.Case, async: false

  alias HTTP.HTTP2.Pool
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  test "a peer that stops reading cannot hold the public upload writer indefinitely" do
    parent = self()

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true, recbuf: 1024])

    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        :gen_tcp.close(listener)
        {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)

        :ok =
          :gen_tcp.send(socket, [
            Peer.frame(4, 0, 0, <<4::16, 67_108_864::32>>),
            Peer.frame(8, 0, 0, <<67_108_864::32>>)
          ])

        {id, false} = Peer.request(socket)
        send(parent, {:request_headers, self(), id})

        receive do
          :close -> :gen_tcp.close(socket)
        after
          10_000 -> :gen_tcp.close(socket)
        end
      end)

    on_exit(fn -> send(peer, :close) end)

    body = :binary.copy("x", 64 * 1024 * 1024)
    started = System.monotonic_time(:millisecond)

    promise =
      HTTP.fetch("http://localhost:#{port}/blocked",
        method: :post,
        body: body,
        http_version: :h2c,
        timeout: 6_000,
        socket_opts: [sndbuf: 1024]
      )

    assert_receive {:request_headers, ^peer, 1}, 2_000

    owner =
      :http_fetch_http2_pool
      |> :sys.get_state()
      |> Map.fetch!(:entries)
      |> Enum.find_value(fn {key, entry} ->
        if key.port == port, do: entry.connections |> Map.keys() |> List.first()
      end)

    assert is_pid(owner)
    monitor = Process.monitor(owner)

    assert {:error, {:transport_error, :timeout}} = HTTP.Promise.await(promise)
    assert System.monotonic_time(:millisecond) - started < 5_000
    assert_receive {:DOWN, ^monitor, :process, ^owner, _reason}, 2_000

    refute Enum.any?(Pool.stats(:http_fetch_http2_pool), fn {key, _} ->
             key.port == port
           end)
  end
end
