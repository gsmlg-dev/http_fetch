defmodule QuicHttp3.Transport do
  # TODO(upstream): gsmlg-dev/ex_quic#5 -- expose h3 ALPN and QUIC DATAGRAM support.
  @moduledoc """
  Narrow transport contract consumed by the HTTP/3 session layer.

  Implementations provide QUIC operations only. HTTP/3 frame parsing, QPACK,
  control streams, and request streams remain in `QuicHttp3`.
  """

  @type connection :: term()
  @type stream :: term()
  @type options :: keyword()
  @type failure :: {:error, term()} | {:blocked, term()} | {:unknown, reference()}

  @callback connect(binary() | :inet.ip_address(), :inet.port_number(), options()) ::
              {:ok, connection()} | failure()
  @callback ready(connection(), timeout()) :: :ok | :pending | failure()
  @callback open_stream(connection(), :bidi | :uni, options()) ::
              {:ok, stream()} | failure()
  @callback send_stream(stream(), binary(), boolean(), options()) ::
              {:ok, reference()} | :ok | failure()
  @callback read(stream(), pos_integer(), options()) :: {:ok, list()} | failure()
  @callback events(connection(), pos_integer(), options()) :: {:ok, list()} | failure()
  @callback reset_stream(stream(), non_neg_integer(), options()) ::
              {:ok, reference()} | :ok | failure()
  @callback stop_stream(stream(), non_neg_integer(), options()) ::
              {:ok, reference()} | :ok | failure()
  @callback close(connection(), non_neg_integer(), binary(), options()) :: :ok | failure()
  @callback capabilities() :: map()
end
