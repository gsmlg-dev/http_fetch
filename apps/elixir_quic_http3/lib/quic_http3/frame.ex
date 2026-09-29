defmodule QuicHttp3.Frame do
  @moduledoc """
  Public HTTP/3 frame codec facade.

  The wire codec remains owned by `http_core` for compatibility with the
  existing H3 helpers. This facade gives the new application layer a stable
  namespace without maintaining a second implementation.
  """

  alias HTTP.H3.Frame, as: CoreFrame

  @type t :: CoreFrame.t()
  @type decode_result :: CoreFrame.decode_result()

  defdelegate data(), to: CoreFrame
  defdelegate headers(), to: CoreFrame
  defdelegate cancel_push(), to: CoreFrame
  defdelegate settings(), to: CoreFrame
  defdelegate push_promise(), to: CoreFrame
  defdelegate goaway(), to: CoreFrame
  defdelegate max_push_id(), to: CoreFrame
  defdelegate wt_stream(), to: CoreFrame
  defdelegate name(type), to: CoreFrame
  defdelegate type(type), to: CoreFrame
  defdelegate encode(frame), to: CoreFrame
  defdelegate encode(frame_type, payload), to: CoreFrame
  defdelegate encode!(frame), to: CoreFrame
  defdelegate encode!(frame_type, payload), to: CoreFrame
  defdelegate decode(data), to: CoreFrame
end
