defmodule HTTP.HTTP2.ProductionFlowTest do
  use ExUnit.Case, async: true
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  for kind <- [:binary, :stream] do
    test "public native-profile #{kind} upload crosses initial credit" do
      bytes = :binary.copy("abcdef0123456789", 8192)

      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, false} = Peer.request(socket)
          assert Peer.body(socket, id) == bytes
          Peer.response(socket, id, "done")
        end)

      body =
        if unquote(kind) == :binary do
          bytes
        else
          {:ok, stream} =
            HTTP.Stream.from_enumerable(for <<chunk::binary-size(16_384) <- bytes>>, do: chunk)

          stream
        end

      response =
        HTTP.fetch(url,
          method: :post,
          body: body,
          duplex: "half",
          http_version: :h2c,
          http2_profile: :native_v1,
          timeout: 2_000
        )
        |> HTTP.Promise.await()

      assert HTTP.Response.read_all(response) == "done"
      assert_receive {:peer_complete, ^peer}
      send(peer, :close)
    end
  end
end
