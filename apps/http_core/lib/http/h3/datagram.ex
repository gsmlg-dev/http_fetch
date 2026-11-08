defmodule HTTP.H3.Datagram do
  @moduledoc "RFC 9297 quarter-stream association. The limit includes the association overhead."
  alias HTTP.H3.Varint
  alias HTTP.H3.WebTransport.Draft17

  def encode(stream_id, payload, max_bytes)
      when is_binary(payload) and is_integer(max_bytes) and max_bytes >= 0 do
    if Draft17.valid_session_id?(stream_id) do
      bytes = Varint.encode!(div(stream_id, 4)) <> payload
      if byte_size(bytes) <= max_bytes, do: {:ok, bytes}, else: {:error, :datagram_too_large}
    else
      {:error, :invalid_session_id}
    end
  end

  def decode(bytes, max_bytes)
      when is_binary(bytes) and is_integer(max_bytes) and max_bytes >= 0 do
    if byte_size(bytes) > max_bytes do
      {:error, :datagram_too_large}
    else
      case Varint.decode(bytes) do
        {:ok, quarter, payload} when quarter < 1_152_921_504_606_846_976 ->
          {:ok, quarter * 4, payload}

        _ ->
          {:error, :invalid_datagram_association}
      end
    end
  end
end
