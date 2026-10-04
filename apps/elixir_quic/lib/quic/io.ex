defmodule Quic.IO do
  @moduledoc """
  Socket-free IO adapter contract.

  Adapters perform local IO only. A successful send returns its actual local
  completion timestamp in monotonic microseconds, not a peer acknowledgement. Admission, generations, amplification
  accounting and timer validation live in `Quic.IO.Endpoint`.
  """

  @callback send(term(), binary(), term()) :: {:ok, integer()} | {:error, term()}
  @callback close(term()) :: :ok | {:error, term()}
  @callback monotonic_time() :: integer()
end
