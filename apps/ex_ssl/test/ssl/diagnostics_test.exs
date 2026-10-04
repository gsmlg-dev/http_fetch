defmodule SSL.DiagnosticsTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer, OpenSSLPeer}

  test "TLS 1.3 diagnostics return authenticated metadata and live addresses" do
    {:ok, peer} = LocalTLSPeer.start(fn socket -> :ssl.recv(socket, 0, 5_000) end)

    try do
      assert {:ok, socket} =
               SSL.connect({127, 0, 0, 1}, peer.port, LocalTLSPeer.client_options(), 5_000)

      assert {:ok, info} = SSL.connection_information(socket)

      assert info == [
               protocol: :"tlsv1.3",
               selected_cipher_suite: info[:selected_cipher_suite],
               session_resumption: false
             ]

      assert info[:selected_cipher_suite] == %{
               key_exchange: :any,
               cipher: info[:selected_cipher_suite].cipher,
               mac: :aead,
               prf: info[:selected_cipher_suite].prf
             }

      assert info[:selected_cipher_suite] in :ssl.cipher_suites(:all, :"tlsv1.3")

      assert {:ok, [session_resumption: false, protocol: :"tlsv1.3"]} =
               SSL.connection_information(socket, [:session_resumption, :protocol])

      assert {:ok, []} = SSL.connection_information(socket, [])
      assert SSL.peercert(socket) == {:ok, LocalTLSPeer.server_certificate()}
      assert {:ok, {{127, 0, 0, 1}, peer.port}} == SSL.peername(socket)
      assert {:ok, {{127, 0, 0, 1}, local_port}} = SSL.sockname(socket)
      assert local_port in 1..65_535

      for keys <- [
            [:client_random],
            [:protocol, :protocol],
            [123],
            [:protocol | :bad_tail],
            :protocol
          ] do
        assert {:error, {:options, _}} = SSL.connection_information(socket, keys)
      end

      stale = %{socket | ref: make_ref()}
      assert {:error, :badarg} = SSL.peercert(stale)
      assert {:error, :badarg} = SSL.connection_information(stale)
      assert :ok = SSL.close(socket)
      assert {:error, :closed} = SSL.peercert(socket)
      assert {:error, :closed} = SSL.peername(socket)
      assert {:error, :closed} = SSL.sockname(socket)
      assert {:error, :closed} = SSL.connection_information(socket)
    after
      LocalTLSPeer.stop(peer)
    end
  end

  test "OTP reference returns the same public diagnostic shapes" do
    {:ok, peer} = LocalTLSPeer.start(fn socket -> :ssl.recv(socket, 0, 5_000) end)

    try do
      assert {:ok, socket} =
               :ssl.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

      assert {:ok, info} =
               :ssl.connection_information(socket, [
                 :protocol,
                 :selected_cipher_suite,
                 :session_resumption
               ])

      assert info[:protocol] == :"tlsv1.3"
      assert info[:selected_cipher_suite] in :ssl.cipher_suites(:all, :"tlsv1.3")
      assert is_boolean(info[:session_resumption])
      assert :ssl.peercert(socket) == {:ok, LocalTLSPeer.server_certificate()}
      assert {:ok, {{127, 0, 0, 1}, peer.port}} == :ssl.peername(socket)
      assert {:ok, {address, port}} = :ssl.sockname(socket)
      assert is_tuple(address) and port in 1..65_535
      assert :ok = :ssl.close(socket)
      assert {:error, :closed} = :ssl.peercert(socket)
    after
      LocalTLSPeer.stop(peer)
    end
  end

  @tag :integration
  test "TLS 1.2 OpenSSL peer reports its selected ECDHE suite and DER" do
    directory =
      Path.join(System.tmp_dir!(), "exssl-diagnostics-#{System.unique_integer([:positive])}")

    fixtures = ClientAuthFixtures.create(directory)

    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: fixtures.server.certificate,
        keyfile: fixtures.server.key,
        min_version: :tls12,
        max_version: :tls12,
        alpn: ["http/1.1"]
      )

    try do
      assert {:ok, socket} =
               SSL.connect({127, 0, 0, 1}, peer.port,
                 verify: :verify_peer,
                 cacerts: [fixtures.ca.der],
                 server_name_indication: ~c"exssl.test",
                 versions: [:"tlsv1.2"],
                 alpn_advertised_protocols: ["http/1.1"]
               )

      assert {:ok,
              [protocol: :"tlsv1.2", selected_cipher_suite: suite, session_resumption: false]} =
               SSL.connection_information(socket)

      assert suite == :ssl.str_to_suite(~c"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
      assert SSL.peercert(socket) == {:ok, fixtures.server.der}
      assert {:ok, {{127, 0, 0, 1}, peer.port}} == SSL.peername(socket)
      assert {:ok, {{127, 0, 0, 1}, _}} = SSL.sockname(socket)
      assert :ok = SSL.close(socket)
    after
      OpenSSLPeer.stop(peer)
      File.rm_rf!(directory)
    end
  end
end
