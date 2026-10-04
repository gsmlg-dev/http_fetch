defmodule QuicHttp3.Transport do
  @moduledoc """
  Narrow transport contract consumed by the HTTP/3 session layer.

  Implementations provide QUIC operations only. HTTP/3 frame parsing, QPACK,
  control streams, and request streams remain in `QuicHttp3`.
  """

  @type connection :: term()
  @type stream :: term()
  @type options :: keyword()
  @type failure :: {:error, term()} | {:blocked, term()} | {:unknown, reference()}

  @callback client(options()) :: {:ok, pid()} | failure()
  @callback connect(binary() | :inet.ip_address(), :inet.port_number(), options()) ::
              {:ok, connection()} | failure()
  @callback ready(connection(), timeout()) :: :ready | :pending | failure()
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
  @callback send_datagram(connection(), binary(), options()) :: {:ok, reference()} | failure()
  @callback read_datagrams(connection(), pos_integer(), options()) ::
              {:ok, [binary()]} | failure()
  @callback stop_endpoint(pid()) :: :ok | {:error, term()}
  @callback capabilities() :: map()
end
