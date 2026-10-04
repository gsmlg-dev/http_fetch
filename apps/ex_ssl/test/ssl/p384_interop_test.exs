defmodule SSL.P384InteropTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer
  alias SSL.ClientHello.WireProfile

  @moduletag :integration
  @request "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
  @response "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\np384"

  for {label, initial_group} <- [direct: 0x0018, hello_retry_request: 0x001D] do
    test "P384 HTTP exchange with #{label}" do
      {:ok, peer} =
        LocalTLSPeer.start(
          fn socket ->
            assert {:ok, @request} = :ssl.recv(socket, byte_size(@request), 5_000)
            assert :ok = :ssl.send(socket, @response)
          end,
          ssl_options: [supported_groups: [:secp384r1]]
        )

      profile = %WireProfile{
        name: :p384,
        cipher_suites: [0x1301],
        extensions: [
          {:server_name, :from_connection},
          {:supported_versions, [0x0304]},
          {:supported_groups, [unquote(initial_group), 0x0018] |> Enum.uniq()},
          {:signature_algorithms, [0x0804]},
          {:key_share, [unquote(initial_group)]}
        ]
      }

      options = Keyword.put(LocalTLSPeer.client_options(), :ex_ssl, profile: profile)

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

      assert {:error, :econnrefused} =
               :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 1_000)
    end
  end
end
