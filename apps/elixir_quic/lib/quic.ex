defmodule Quic do
  @moduledoc """
  Certificate-based QUIC v1 reliable streams with bounded pull consumption.

  See `docs/consumer-contract.md` for ownership, generation handles, deadlines,
  admission outcomes and limitations. ALPN is metadata; application protocols
  are provided by consumers.
  """
  alias Quic.{Connection, Endpoint}
  alias Quic.Runtime.{ConnectionHandle, StreamHandle}

  @type failure :: {:error, term()} | {:blocked, term()} | {:unknown, reference()}
  @type operation_options :: keyword()

  @spec local(pid()) :: {:inet.ip_address(), :inet.port_number()} | {:error, term()}
  def local(endpoint), do: Endpoint.local(endpoint)
  @spec listen(keyword()) :: GenServer.on_start()
  def listen(opts), do: Endpoint.start_link(public_opts(opts, :server))
  @spec client(keyword()) :: GenServer.on_start()
  def client(opts), do: Endpoint.start_link(public_opts(opts, :client))

  defp public_opts(opts, role) do
    opts
    |> Keyword.put(:role, role)
    |> Keyword.put(:public, true)
    |> Keyword.put_new(:acceptor, self())
    |> Keyword.update(:streams, [delivery: :manual], &Keyword.put(&1, :delivery, :manual))
  end

  @spec connect(pid(), {:inet.ip_address(), :inet.port_number()}, operation_options()) ::
          {:ok, ConnectionHandle.t()} | failure()
  def connect(endpoint, remote, opts \\ []), do: Endpoint.connect(endpoint, remote, opts)

  @spec accept(pid(), non_neg_integer() | operation_options()) ::
          {:ok, ConnectionHandle.t()} | failure()
  def accept(endpoint, timeout_or_opts \\ 5_000), do: Endpoint.accept(endpoint, timeout_or_opts)

  @spec attach(ConnectionHandle.t(), pid(), keyword()) :: :ok | failure()
  def attach(%ConnectionHandle{id: pid, generation: generation}, consumer, opts \\ []),
    do: Connection.attach(pid, generation, consumer, opts)

  @spec ready(ConnectionHandle.t()) :: :ready | :pending | failure()
  def ready(%ConnectionHandle{id: pid, generation: generation}),
    do: Connection.ready(pid, generation)

  @spec open_stream(ConnectionHandle.t(), :bidi | :uni, operation_options()) ::
          {:ok, StreamHandle.t()} | failure()
  def open_stream(%ConnectionHandle{id: pid, generation: generation}, kind, opts \\ []),
    do: Connection.open_public_stream(pid, generation, kind, opts)

  @spec send_stream(StreamHandle.t(), binary(), boolean(), operation_options()) ::
          {:ok, reference()} | failure()
  def send_stream(
        %StreamHandle{connection: %ConnectionHandle{id: pid, generation: generation}, id: id},
        data,
        fin \\ false,
        opts \\ []
      ),
      do: Connection.send_public_stream(pid, generation, id, data, fin, opts)

  @spec read(StreamHandle.t(), pos_integer(), operation_options()) :: {:ok, list()} | failure()
  def read(
        %StreamHandle{connection: %ConnectionHandle{id: pid, generation: generation}, id: id},
        max,
        opts \\ []
      ),
      do: Connection.read(pid, generation, id, max, opts)

  @spec send_datagram(ConnectionHandle.t(), binary(), operation_options()) ::
          {:ok, reference()} | failure()
  def send_datagram(%ConnectionHandle{id: pid, generation: generation}, data, opts \\ []),
    do: Connection.send_public_datagram(pid, generation, data, opts)

  @spec read_datagrams(ConnectionHandle.t(), pos_integer(), operation_options()) ::
          {:ok, [binary()]} | failure()
  def read_datagrams(%ConnectionHandle{id: pid, generation: generation}, max \\ 32, opts \\ []),
    do: Connection.read_datagrams(pid, generation, max, opts)

  @spec events(ConnectionHandle.t(), pos_integer(), operation_options()) ::
          {:ok, list()} | failure()
  def events(%ConnectionHandle{id: pid, generation: generation}, max \\ 32, opts \\ []),
    do: Connection.events(pid, generation, max, opts)

  @spec info(ConnectionHandle.t()) :: {:ok, map()} | failure()
  def info(%ConnectionHandle{id: pid, generation: generation}),
    do: Connection.info(pid, generation)

  @spec operation_status(ConnectionHandle.t() | pid(), reference()) ::
          map() | :unknown | failure()
  def operation_status(%ConnectionHandle{id: pid, generation: generation}, ref),
    do: Connection.operation_status(pid, generation, ref)

  def operation_status(endpoint, ref) when is_pid(endpoint),
    do: Endpoint.operation_status(endpoint, ref)

  @spec reset_stream(StreamHandle.t(), non_neg_integer(), operation_options()) ::
          {:ok, reference()} | failure()
  def reset_stream(
        %StreamHandle{connection: %ConnectionHandle{id: pid, generation: generation}, id: id},
        code,
        opts \\ []
      ),
      do: Connection.reset_public_stream(pid, generation, id, code, opts)

  @spec stop_stream(StreamHandle.t(), non_neg_integer(), operation_options()) ::
          {:ok, reference()} | failure()
  def stop_stream(
        %StreamHandle{connection: %ConnectionHandle{id: pid, generation: generation}, id: id},
        code,
        opts \\ []
      ),
      do: Connection.stop_public_stream(pid, generation, id, code, opts)

  @spec close(ConnectionHandle.t(), non_neg_integer(), binary(), operation_options()) ::
          :ok | failure()
  def close(
        %ConnectionHandle{id: pid, generation: generation},
        code \\ 0,
        reason \\ <<>>,
        opts \\ []
      ),
      do: Connection.close_public(pid, generation, code, reason, opts)

  @spec capabilities() :: %{
          datagram: true,
          delivery: :pull,
          http3: false,
          io: [:external | :standalone, ...],
          max_write_bytes: 16_384,
          resumption: false,
          streams: [:bidi | :uni, ...],
          version: 1
        }
  def capabilities,
    do: %{
      version: 1,
      streams: [:bidi, :uni],
      max_write_bytes: 16_384,
      delivery: :pull,
      io: [:standalone, :external],
      datagram: true,
      http3: false,
      resumption: false
    }
end
