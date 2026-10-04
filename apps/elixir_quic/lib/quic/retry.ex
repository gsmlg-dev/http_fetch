defmodule Quic.Retry do
  @moduledoc """
  Bounded, authenticated server Retry tokens. The endpoint owns the random key
  and supplies monotonic microseconds. Tokens bind the source IP/port, original
  DCID and Retry SCID; restarting the endpoint invalidates outstanding tokens.
  They prove address reachability, not a client identity, and are replayable
  within their short lifetime. No per-client token state is retained.
  """

  @spec issue(binary(), {:inet.ip_address(), :inet.port_number()}, binary(), binary(), integer()) ::
          binary()
  def issue(key, remote, original, retry_cid, now)
      when byte_size(key) == 32 and byte_size(original) in 8..20 and
             byte_size(retry_cid) in 8..20 and is_integer(now) do
    body =
      <<1, now::signed-64, byte_size(original), original::binary, byte_size(retry_cid),
        retry_cid::binary>>

    body <> mac(key, remote, body)
  end

  @spec verify(
          binary(),
          {:inet.ip_address(), :inet.port_number()},
          binary(),
          binary(),
          integer(),
          pos_integer()
        ) ::
          {:ok, binary()} | {:error, :invalid_retry_token}
  def verify(key, remote, cid, token, now, ttl)
      when byte_size(key) == 32 and is_binary(token) and byte_size(token) in 59..83 and
             is_integer(now) and is_integer(ttl) and ttl > 0 do
    body_size = byte_size(token) - 32
    <<body::binary-size(^body_size), tag::binary-size(32)>> = token

    with true <- :crypto.hash_equals(mac(key, remote, body), tag),
         <<1, issued::signed-64, olen, rest::binary>> <- body,
         true <- olen in 8..20,
         <<original::binary-size(^olen), rlen, retry_cid::binary>> <- rest,
         true <- rlen in 8..20 and byte_size(retry_cid) == rlen,
         true <- retry_cid == cid and issued <= now and now - issued <= ttl do
      {:ok, original}
    else
      _ -> {:error, :invalid_retry_token}
    end
  end

  def verify(_, _, _, _, _, _), do: {:error, :invalid_retry_token}

  defp mac(key, {ip, port}, body) do
    address =
      case ip do
        {a, b, c, d} ->
          <<4, a, b, c, d, port::16>>

        {a, b, c, d, e, f, g, h} ->
          <<6, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, port::16>>
      end

    :crypto.mac(:hmac, :sha256, key, ["ex_quic retry v1", address, body])
  end
end
