defmodule HTTP.HTTP2.SlowConsumerTest do
  use ExUnit.Case, async: false
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  test "real public paused consumer bounds all delivery processes and preserves sibling progress" do
    parent = self()

    {url, peer} =
      Peer.start(parent, fn socket ->
        {slow, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, slow, <<0x88>>))

        for size <- [16_384, 16_384, 16_384, 16_383] do
          :ok = :gen_tcp.send(socket, Peer.frame(0, 0, slow, :binary.copy("x", size)))
        end

        {sibling, true} = Peer.request(socket)
        :ok = Peer.response(socket, sibling, "sibling")
        :ok = :gen_tcp.send(socket, Peer.frame(6, 0, 0, "12345678"))
        wait_ping(socket)
        send(parent, {:paused_barrier, self(), slow})

        receive do
          :finish_slow -> :ok = :gen_tcp.send(socket, Peer.frame(0, 1, slow, ""))
        after
          5_000 -> raise "consumer test barrier timeout"
        end
      end)

    opts = [http_version: :h2c, http2_profile: :native_v1, timeout: 5_000]
    response = HTTP.fetch(url, opts) |> HTTP.Promise.await()
    assert is_pid(response.body)
    sibling = HTTP.fetch(url, opts) |> HTTP.Promise.await()
    assert HTTP.Response.read_all(sibling) == "sibling"
    assert_receive {:paused_barrier, ^peer, slow}, 1_000
    port = URI.parse(url).port

    {_, entry} =
      Enum.find(:sys.get_state(:http_fetch_http2_pool).entries, fn {key, _} ->
        key.port == port
      end)

    [owner] = Map.keys(entry.connections)
    state = :sys.get_state(owner)
    coordinator = state.streams[slow].pid
    assert state.connection.streams[slow].receive_window == 0
    assert state.connection.streams[slow].unacknowledged == 65_535

    assert state.connection.connection_unacknowledged + state.connection.connection_receive_window <=
             state.max_receive_buffer_bytes

    samples =
      for {role, pid} <- [owner: owner, coordinator: coordinator, response: response.body] do
        {:message_queue_len, messages} = Process.info(pid, :message_queue_len)
        assert messages <= 8
        {:memory, memory} = Process.info(pid, :memory)
        assert memory <= 2_000_000
        {:binary, binaries} = Process.info(pid, :binary)
        retained = Enum.sum(for {_, size, _} <- binaries, do: size)
        assert retained <= 1_048_576
        %{role: role, messages: messages, memory_bytes: memory, referenced_binary_bytes: retained}
      end

    IO.puts(
      JSON.encode!(%{
        gate: "paused_consumer",
        samples: samples,
        pending_wire_bytes: state.connection.connection_unacknowledged,
        global_receive_budget: state.max_receive_buffer_bytes
      })
    )

    send(peer, :finish_slow)
    assert HTTP.Response.read_all(response) == :binary.copy("x", 65_535)
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  defp wait_ping(socket) do
    case Peer.recv(socket) do
      {6, 1, 0, "12345678"} -> :ok
      _ -> wait_ping(socket)
    end
  end
end
