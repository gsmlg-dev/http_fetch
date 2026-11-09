defmodule SSL.ListenSocket do
  @moduledoc "An opaque TLS server listen socket. Contains no TLS key material when inspected."
  @derive {Inspect, only: [:carrier]}
  @enforce_keys [:carrier, :options]
  defstruct [:carrier, :options]
  @opaque t :: %__MODULE__{carrier: :gen_tcp.socket(), options: SSL.ServerOptions.t()}

  @doc false
  @spec new(:gen_tcp.socket(), SSL.ServerOptions.t()) :: t()
  def new(carrier, options) when is_port(carrier) and is_map(options),
    do: %__MODULE__{carrier: carrier, options: options}

  # Accessors take term() so callers may match `%SSL.ListenSocket{}` before calling them.
  @doc false
  @spec carrier(term()) :: :gen_tcp.socket()
  def carrier(%__MODULE__{carrier: carrier}), do: carrier

  @doc false
  @spec options(term()) :: SSL.ServerOptions.t()
  def options(%__MODULE__{options: options}), do: options
end
