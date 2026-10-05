defmodule QuicHttp3.TLSOptions do
  @moduledoc false

  # Trust, identities, key loading and algorithm validation use the shared raw
  # QUIC validator. This application owns its separate HTTP/3 ALPN policy.
  def normalize(host, options) when is_list(options) do
    with true <- Keyword.keyword?(options),
         true <- Keyword.keys(options) == Enum.uniq(Keyword.keys(options)),
         true <- Keyword.get(options, :alpn, ["h3"]) == ["h3"],
         {:ok, tls} <- HTTP.QUIC.TLSOptions.normalize(host, Keyword.delete(options, :alpn)) do
      tls = Keyword.put(tls, :alpn, ["h3"])

      if Keyword.has_key?(options, :server_name_indication) do
        {:ok, tls}
      else
        case :inet.parse_address(String.to_charlist(host)) do
          {:ok, _ip} -> {:ok, tls}
          {:error, _} -> {:ok, Keyword.put(tls, :server_name, host)}
        end
      end
    else
      false -> {:error, :invalid_h3_tls_options}
      error -> error
    end
  end

  def normalize(_, _), do: {:error, :invalid_h3_tls_options}
end
