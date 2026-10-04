defmodule ExSslE2E.Client do
  @moduledoc false
  alias SSL.ClientHello.WireProfile

  @profile %WireProfile{
    name: :caddy_e2e,
    session_id: :random_32,
    cipher_suites: [:tls_aes_128_gcm_sha256, :tls_aes_256_gcm_sha384],
    extensions: [
      {:server_name, :from_connection},
      {:supported_groups, [:x25519]},
      {:ec_point_formats, [0]},
      {:signature_algorithms, [:ecdsa_secp256r1_sha256]},
      {:alpn, ["http/1.1"]},
      {:supported_versions, [:tlsv1_3]},
      {:key_share, [:x25519]}
    ]
  }

  def request(options) do
    host = Keyword.fetch!(options, :host)
    server_name = Keyword.fetch!(options, :server_name)
    port = Keyword.fetch!(options, :port)
    timeout = Keyword.fetch!(options, :timeout)
    deadline = System.monotonic_time(:millisecond) + timeout

    tls_options = [
      :binary,
      active: false,
      packet: :raw,
      verify: :verify_peer,
      cacertfile: Keyword.fetch!(options, :ca_file),
      server_name_indication: String.to_charlist(server_name),
      versions: [:"tlsv1.3"],
      ex_ssl: [profile: @profile]
    ]

    with {:ok, socket} <- SSL.connect(host, port, tls_options, timeout) do
      try do
        with :ok <-
               SSL.send(socket, [
                 "GET /fingerprint HTTP/1.1\r\nHost: ",
                 server_name,
                 "\r\nConnection: close\r\n\r\n"
               ]) do
          receive_http_response(socket, <<>>, deadline)
        end
      after
        SSL.close(socket)
      end
    end
  end

  defp receive_http_response(_socket, response, _deadline) when byte_size(response) > 1_048_576,
    do: {:error, :response_too_large}

  defp receive_http_response(socket, response, deadline) do
    case complete_http_response(response) do
      :more ->
        with {:ok, bytes} <-
               SSL.recv(socket, 0, max(deadline - System.monotonic_time(:millisecond), 0)) do
          receive_http_response(socket, response <> bytes, deadline)
        end

      result ->
        result
    end
  end

  defp complete_http_response(response) do
    case :binary.match(response, "\r\n\r\n") do
      :nomatch ->
        :more

      {header_end, 4} ->
        headers = binary_part(response, 0, header_end)
        body_offset = header_end + 4
        body = binary_part(response, body_offset, byte_size(response) - body_offset)

        with [_, status] <- Regex.run(~r/^HTTP\/1\.1 (\d{3})/, headers),
             [_, length] <- Regex.run(~r/(?im)^content-length:\s*(\d+)\s*$/, headers),
             {content_length, ""} <- Integer.parse(length) do
          if byte_size(body) >= content_length do
            {:ok,
             %{
               status: String.to_integer(status),
               body: binary_part(body, 0, content_length)
             }}
          else
            :more
          end
        else
          _invalid -> {:error, {:invalid_http_response_headers, headers}}
        end
    end
  end
end
