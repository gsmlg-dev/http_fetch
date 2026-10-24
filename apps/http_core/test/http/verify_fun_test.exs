defmodule HTTP.Transport.VerifyFunTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.OpenSSLPeer
  alias HTTP.Transport.ExSSL
  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)

  test "ordinary Core direct and TCP upgrade retain callback TLS policy" do
    for {version, wire} <- [{:"tlsv1.2", :tls12}, {:"tlsv1.3", :tls13}],
        route <- [:direct, :upgrade] do
      assert {:ok, peer} =
               OpenSSLPeer.start(
                 certfile: Path.join(@fixtures, "localhost.pem"),
                 keyfile: Path.join(@fixtures, "localhost.key"),
                 min_version: wire,
                 max_version: wire
               )

      options = [
        ssl: [
          versions: [version],
          cacerts: [],
          verify_fun: {fn _, _, state -> {:valid, state + 1} end, 0}
        ]
      ]

      try do
        result =
          case route do
            :direct ->
              ExSSL.connect("localhost", peer.port, options, 5_000)

            :upgrade ->
              assert {:ok, tcp} =
                       :gen_tcp.connect(
                         {127, 0, 0, 1},
                         peer.port,
                         [:binary, active: false],
                         5_000
                       )

              ExSSL.upgrade(tcp, "localhost", options, 5_000)
          end

        assert {:ok, socket} = result

        try do
          assert {:ok, %{"version" => negotiated}} = OpenSSLPeer.event(peer, "handshake", 5_000)
          assert negotiated == if(wire == :tls12, do: "TLSv1.2", else: "TLSv1.3")
          assert :ok = ExSSL.send(socket, <<4::32, "ping">>)
          assert {:ok, <<4::32, "ping">>} = ExSSL.recv(socket, 8, 5_000)
          assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        after
          ExSSL.close(socket)
        end
      after
        OpenSSLPeer.stop(peer)
        assert Port.info(peer.handle) == nil
      end
    end
  end
end
