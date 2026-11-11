defmodule HTTP.ResponseError do
  @moduledoc """
  Raised by the `HTTP.Response` body readers (`read_all/1`, `text/1`,
  `arrayBuffer/1`, `array_buffer/1`, `blob/1` and `clone/1`) when a streamed
  body fails before it completes.

  `reason` is the stream failure, for example `:timeout`, `:aborted`,
  `{:invalid_content_encoding, coding}` or `{:stream_down, exit_reason}`.
  `HTTP.Response.json/1`, `HTTP.Response.read_as_json/1` and
  `HTTP.Response.write_to/2` return `{:error, reason}` instead of raising.
  """
  defexception [:reason]

  @type t :: %__MODULE__{reason: term()}

  @impl true
  def message(%__MODULE__{reason: reason}),
    do: "response body stream failed: #{inspect(reason)}"
end
