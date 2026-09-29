defmodule HTTP.HTTP2ProductionSemanticsTest do
  use ExUnit.Case, async: true

  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @status_100 <<0x08, 0x03, "100">>
  @status_200 <<0x88>>
  @status_302 <<0x08, 0x03, "302">>

  defp fetch(url, opts \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge([http_version: :h2c, http2_profile: :native_v1, timeout: 2_000], opts)
    )
    |> HTTP.Promise.await()
  end

  test "ignores informational headers and finishes a body on trailers" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            Peer.frame(1, 4, id, @status_100),
            Peer.frame(1, 4, id, @status_200),
            Peer.frame(0, 0, id, "ok"),
            Peer.frame(1, 5, id, <<0, 0x09, "x-trailer", 0x03, "yes">>)
          ])
      end)

    response = fetch(url)
    assert response.status == 200
    assert HTTP.Response.read_all(response) == "ok"
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "follows a redirect with the original deadline and marks the final response" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {first, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(
            socket,
            Peer.frame(1, 5, first, @status_302 <> <<0, 8, "location", 5, "/next">>)
          )

        {second, true} = Peer.request(socket)
        assert second > first
        :ok = :gen_tcp.send(socket, Peer.frame(1, 5, second, @status_200))
      end)

    response = fetch(url)
    assert response.status == 200
    assert response.redirected
    assert HTTP.Response.read_all(response) == ""
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  for {mode, result} <- [manual: 302, error: {:error, :redirect}] do
    test "redirect #{mode} returns the configured result" do
      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, true} = Peer.request(socket)

          :ok =
            :gen_tcp.send(
              socket,
              Peer.frame(1, 5, id, @status_302 <> <<0, 8, "location", 5, "/next">>)
            )
        end)

      response = fetch(url, redirect: unquote(mode))

      case unquote(Macro.escape(result)) do
        302 -> assert response.status == 302
        error -> assert response == error
      end

      assert_receive {:peer_complete, ^peer}
      send(peer, :close)
    end
  end

  test "invalid status fails the promise without crashing its task" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 5, id, <<0x08, 0x03, "abc">>))
      end)

    assert {:error, _reason} = fetch(url)
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end
end
