defmodule QuicHttp3.Transport do
  @moduledoc """
  Narrow transport contract consumed by the HTTP/3 session layer.

  Implementations provide QUIC operations only. HTTP/3 frame parsing, QPACK,
  control streams, and request streams remain in `QuicHttp3`.

  Operation options may carry `deadline: {:abs_ms, monotonic_milliseconds}`.
  Session retains the same absolute deadline across blocked or unknown work.
  The internal exclusive `cleanup` descriptor is supported only by a Session
  using the production Quic adapter and an owned endpoint. Cleanup acknowledgements
  do not replace the separately retained `Quic.Cleanup` receipt.
  """

  @type connection :: term()
  @type stream :: term()
  @type options :: keyword()
  @type failure :: {:error, term()} | {:blocked, term()} | {:unknown, reference()}

  @callback client(options()) :: {:ok, term()} | failure()
  @callback connect(binary() | :inet.ip_address(), :inet.port_number(), options()) ::
              {:ok, connection()} | {:unknown, connection(), reference()} | failure()
  @callback ready(connection(), timeout()) :: :ready | :pending | failure()
  @callback info(connection()) :: {:ok, map()} | failure()
  @callback operation_status(connection(), reference(), atom()) :: map() | :unknown | failure()
  @callback cleanup(connection()) :: :ok | {:error, term()}
  @callback abort(connection(), options()) :: :ok | failure()
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
