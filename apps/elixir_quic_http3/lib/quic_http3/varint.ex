defmodule QuicHttp3.Varint do
  @moduledoc "QUIC variable-length integer facade for HTTP/3 codecs."

  alias HTTP.H3.Varint, as: CoreVarint

  @type encoded_size :: CoreVarint.encoded_size()
  @type decode_result :: CoreVarint.decode_result()

  defdelegate max(), to: CoreVarint
  defdelegate encoded_size(value), to: CoreVarint
  defdelegate encode(value), to: CoreVarint
  defdelegate encode(value, bytes), to: CoreVarint
  defdelegate encode!(value), to: CoreVarint
  defdelegate encode!(value, bytes), to: CoreVarint
  defdelegate decode(data), to: CoreVarint
end
