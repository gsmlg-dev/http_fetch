defmodule Quic.Error do
  @moduledoc """
  Typed error categories used at QUIC runtime boundaries.
  """

  defexception [:kind, :reason, :detail]

  @type kind :: :parse | :bounds | :unsupported | :crypto | :state | :io | :timeout
  @type t :: %__MODULE__{kind: kind(), reason: atom(), detail: term()}

  @impl true
  def message(%__MODULE__{kind: kind, reason: reason, detail: detail}) do
    "#{kind}: #{reason}#{if detail, do: " (#{inspect(detail)})", else: ""}"
  end

  def new(kind, reason, detail \\ nil),
    do: %__MODULE__{kind: kind, reason: reason, detail: detail}
end
