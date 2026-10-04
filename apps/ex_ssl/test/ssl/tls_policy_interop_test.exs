defmodule SSL.TLSPolicyInteropTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer

  @moduletag :integration
  @request "GET /policy HTTP/1.1\r\nHost: exssl.test\r\nConnection: close\r\n\r\n"
  @response "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npolicy"

  test "ordered public policy negotiates a constrained OTP peer and verified HTTP response" do
    {:ok, peer} =
      LocalTLSPeer.start(
        fn socket ->
          assert {:ok, @request} = :ssl.recv(socket, byte_size(@request), 5_000)
          assert :ok = :ssl.send(socket, @response)
        end,
        ssl_options: [
          ciphers: [:ssl.str_to_suite(~c"TLS_AES_128_GCM_SHA256")],
          signature_algs: [:rsa_pss_rsae_sha256],
          supported_groups: [:secp384r1]
        ]
      )

    options =
      LocalTLSPeer.client_options() ++
        [
          ciphers: ["TLS_AES_128_GCM_SHA256"],
          signature_algs: [:rsa_pss_rsae_sha256],
          signature_algs_cert: [:rsa_pkcs1_sha256],
          supported_groups: [:secp384r1]
        ]

    try do
      assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
      monitor = Process.monitor(socket.pid)
      assert :ok = SSL.send(socket, @request)
      assert {:ok, @response} = SSL.recv(socket, byte_size(@response), 5_000)
      assert :ok = SSL.close(socket)
      assert_receive {:DOWN, ^monitor, :process, _, _}, 1_000
    after
      assert :ok = LocalTLSPeer.stop(peer)
    end
  end

  test "incompatible certificate policy fails without sending application bytes" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert {:error, _} = :ssl.recv(socket, 0, 5_000)
      end)

    options =
      LocalTLSPeer.client_options() ++
        [signature_algs: [:rsa_pss_rsae_sha256], signature_algs_cert: [:rsa_pss_rsae_sha256]]

    try do
      assert {:error, _} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
    after
      assert {:handshake_error, _} = LocalTLSPeer.stop(peer)
    end
  end
end
