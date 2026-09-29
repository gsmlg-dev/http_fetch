defmodule HTTP.HTTP2RouteTest do
  use ExUnit.Case, async: false

  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  test "h2c without a profile uses a supervised reusable owner" do
    test_pid = self()

    {url, peer} =
      Peer.start(test_pid, fn socket ->
        {id, true} = Peer.request(socket)
        send(test_pid, {:request_seen, id})

        receive do
          :respond -> :ok
        end

        Peer.response(socket, id, "ok")
      end)

    promise = HTTP.fetch(url, http_version: :h2c, timeout: 3_000)
    assert_receive {:request_seen, 1}, 2_000
    port = URI.parse(url).port

    owner =
      :http_fetch_http2_pool
      |> :sys.get_state()
      |> Map.fetch!(:entries)
      |> Enum.find_value(fn {key, entry} ->
        if key.port == port, do: entry.connections |> Map.keys() |> List.first()
      end)

    assert is_pid(owner)

    assert Enum.any?(DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor), fn
             {_, ^owner, _, _} -> true
             _ -> false
           end)

    send(peer, :respond)
    response = HTTP.Promise.await(promise)
    assert response.status == 200
    assert HTTP.Response.read_all(response) == "ok"
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "h2c without a profile streams an upload beyond initial flow-control credit" do
    bytes = :binary.copy("0123456789abcdef", 8192)

    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, false} = Peer.request(socket)
        assert Peer.body(socket, id) == bytes
        Peer.response(socket, id, "done")
      end)

    chunks = for <<chunk::binary-size(16_384) <- bytes>>, do: chunk
    {:ok, stream} = HTTP.Stream.from_enumerable(chunks)

    response =
      HTTP.fetch(url,
        method: :post,
        body: stream,
        duplex: "half",
        http_version: :h2c,
        timeout: 3_000
      )
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "done"
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end
end
