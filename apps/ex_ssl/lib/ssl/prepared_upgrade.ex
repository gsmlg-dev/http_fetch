defmodule SSL.PreparedUpgrade do
  @moduledoc """
  Opaque resolved configuration returned by `SSL.prepare_upgrade/1`.

  The immutable snapshot retains loaded trust, client credentials, wire profile,
  reference identity, SNI and supported upgrade options. It contains no socket,
  connection process, deadline, traffic secrets or ephemeral key material.

  A snapshot may be reused deliberately with `SSL.connect_prepared/3`; each
  connection still generates fresh handshake material. Preparation does not
  establish a connection or prove resource adoption, cancellation or cleanup.
  Callers must not construct, modify or inspect the internal representation.
  """

  @derive {Inspect, only: []}
  @enforce_keys [:options]
  defstruct [:options]

  @opaque t :: %__MODULE__{options: SSL.Options.t()}

  @doc false
  @spec new(SSL.Options.t()) :: t()
  def new(%SSL.Options{endpoint: :upgrade} = options), do: %__MODULE__{options: options}

  @doc false
  @spec fetch_options(term()) :: {:ok, SSL.Options.t()} | {:error, :badarg}
  def fetch_options(%__MODULE__{options: %SSL.Options{endpoint: :upgrade} = options}),
    do: {:ok, options}

  def fetch_options(_), do: {:error, :badarg}
end
