defmodule HTTP.VerifyFunTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.OpenSSLPeer
  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "ordinary Fetch callback controls actual TLS12 and TLS13 HTTP outcomes" do
    for {version, wire} <- [{:"tlsv1.2", :tls12}, {:"tlsv1.3", :tls13}],
        reject? <- [false, true] do
      assert {:ok, peer} =
               OpenSSLPeer.start(
                 certfile: Path.join(@fixtures, "localhost.pem"),
                 keyfile: Path.join(@fixtures, "localhost.key"),
                 min_version: wire,
                 max_version: wire,
                 mode: :http1
               )

      parent = self()
      ref = make_ref()

      callback = fn _, event, state ->
        send(parent, {ref, event})

        if reject? and event == :valid_peer,
          do: {:fail, "R44_PRIVATE_FETCH_REJECTION"},
          else: {:valid, state + 1}
      end

      trust =
        if reject?,
          do: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          else: [cacerts: []]

      try do
        promise =
          HTTP.fetch("https://127.0.0.1:#{peer.port}/r44",
            tls_backend: :ex_ssl,
            http_version: :http1,
            timeout: 5_000,
            connect_timeout: 5_000,
            ssl:
              trust ++
                [
                  versions: [version],
                  server_name_indication: ~c"localhost",
                  verify_fun: {callback, 0}
                ]
          )

        result = HTTP.Promise.await(promise, 5_000)

        if reject? do
          assert {:error, _} = result
          assert_receive {^ref, :valid_peer}, 1_000
          assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "exchange", 5_000)
          refute inspect(result) =~ "R44_PRIVATE_FETCH_REJECTION"
        else
          assert %HTTP.Response{status: 200} = result
          assert HTTP.Response.read_all(result) == "pong"
          assert_receive {^ref, {:bad_cert, :unknown_ca}}, 1_000
          assert {:ok, %{"version" => negotiated}} = OpenSSLPeer.event(peer, "handshake", 5_000)
          assert negotiated == if(wire == :tls12, do: "TLSv1.2", else: "TLSv1.3")
          assert {:ok, %{"bytes" => 0}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        end
      after
        OpenSSLPeer.stop(peer)
        assert Port.info(peer.handle) == nil
      end
    end
  end
end
