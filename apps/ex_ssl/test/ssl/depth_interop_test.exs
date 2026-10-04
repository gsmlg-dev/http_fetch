defmodule SSL.DepthInteropTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer

  @moduletag :integration

  test "OTP 28 depth probe counts intermediate CA certificates, not TLS Certificate entries" do
    # This is an executable differential probe against the supported OTP 28
    # baseline.  A direct root-signed leaf has no intermediate CA certificates,
    # while the generated chain below has exactly one.  The server sends neither
    # root in its TLS Certificate message.
    assert :ok = otp_handshake(:rsa, 0)
    assert :error = otp_handshake(:intermediate_chain, 0)
    assert :ok = otp_handshake(:intermediate_chain, 1)
  end

  test "ex_ssl applies depth to the authenticated root to leaf path" do
    assert :ok = ex_ssl_handshake(:rsa, 0)
    assert :error = ex_ssl_handshake(:intermediate_chain, 0)
    assert :ok = ex_ssl_handshake(:intermediate_chain, 1)
  end

  test "ex_ssl matches the OTP 28 depth boundary for the generated chain" do
    for {certificate, depth} <- [rsa: 0, intermediate_chain: 0, intermediate_chain: 1] do
      assert ex_ssl_handshake(certificate, depth) == otp_handshake(certificate, depth)
    end
  end

  defp otp_handshake(certificate, depth) do
    {:ok, peer} = LocalTLSPeer.start(&hold_until_client_closes/1, certificate: certificate)

    result =
      case :ssl.connect(~c"127.0.0.1", peer.port, depth_options(depth), 5_000) do
        {:ok, socket} ->
          :ok = :ssl.close(socket)
          :ok

        {:error, _reason} ->
          :error
      end

    _ = LocalTLSPeer.stop(peer)
    result
  end

  defp ex_ssl_handshake(certificate, depth) do
    {:ok, peer} = LocalTLSPeer.start(&hold_until_client_closes/1, certificate: certificate)

    result =
      case SSL.connect(~c"127.0.0.1", peer.port, depth_options(depth), 5_000) do
        {:ok, socket} ->
          :ok = SSL.close(socket)
          :ok

        {:error, _reason} ->
          :error
      end

    _ = LocalTLSPeer.stop(peer)
    result
  end

  defp depth_options(depth), do: Keyword.put(LocalTLSPeer.client_options(), :depth, depth)

  defp hold_until_client_closes(socket), do: :ssl.recv(socket, 1, 5_000)
end
