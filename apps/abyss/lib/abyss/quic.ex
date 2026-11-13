defmodule Abyss.QUIC do
  @moduledoc """
  Supervised QUIC service entry point.

  `elixir_quic` remains the protocol engine and owns connection state. This module
  owns one UDP socket, application binding, and a public service lifecycle.
  It exposes opaque connection and stream handles returned by `elixir_quic`;
  their generation checks and all stream semantics are delegated unchanged.
  """

  alias Abyss.QUIC.Service

  @type option ::
          {:handler, module() | {module(), term()}}
          | {:alpn, [binary()]}
          | {:tls, keyword()}
          | {:ip, :inet.ip_address()}
          | {:port, :inet.port_number()}
          | {:max_connections, pos_integer()}
          | {:name, GenServer.name()}
          | {:init_timeout, pos_integer()}
          | {:callback_timeout, pos_integer()}
          | {:shutdown_timeout, pos_integer()}
          | {:poll_interval, pos_integer()}
          | {:event_batch, 1..128}
          | {:writer_timeout, pos_integer()}
          | {:writer_max_queue, pos_integer()}
          | {:writer_max_bytes, pos_integer()}
          | {:quic_options, keyword()}

  def child_spec(opts) do
    %{
      id:
        {__MODULE__,
         if(Keyword.keyword?(opts), do: Keyword.get(opts, :name, make_ref()), else: make_ref())},
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :transient
    }
  end

  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts), do: Service.start_link(opts)

  @spec stop(pid() | GenServer.name(), timeout()) :: :ok
  def stop(listener, timeout \\ 5_000), do: GenServer.stop(listener, :normal, timeout)

  @spec local(pid() | GenServer.name()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def local(listener), do: GenServer.call(listener, :local)

  @doc """
  Asks a connection worker to run one event turn now instead of at its next poll.

  `worker` is the process that runs the handler callbacks: `self()` inside
  `c:Abyss.QUIC.Handler.init/3` or `c:Abyss.QUIC.Handler.handle_event/2`. Other
  processes, such as request workers that queued work for the handler, call this
  after queuing so the handler can act without waiting up to `poll_interval`.

  The turn polls engine events and calls `handle_event/2` with them followed by
  `:tick`, exactly like a timed poll. It leaves the poll timer unchanged, so one
  timer stays outstanding however often wakes arrive. Wakes queued before a turn
  starts are coalesced into that turn. Waking a worker that has not finished
  `init/3`, or one that has exited, does nothing. Always returns `:ok`.
  """
  @spec wake(pid()) :: :ok
  def wake(worker) when is_pid(worker) do
    send(worker, :abyss_quic_wake)
    :ok
  end

  # The remaining calls deliberately use the engine's public API. No endpoint
  # private state or structs are expanded here, keeping `:elixir_quic` optional.
  def ready(connection), do: backend_for_handle(connection, :ready, [connection])
  def info(connection), do: backend_for_handle(connection, :info, [connection])

  @doc """
  Requests one bounded QUIC PING using the engine's public operation API.

  Requires `elixir_quic` 0.21.17 or later. Applications own the keepalive cadence;
  admission does not confirm peer receipt. Operation references, finite deadlines,
  blocked and unknown results follow the engine's normal write contract.
  """
  def ping(connection, opts \\ []), do: backend_for_handle(connection, :ping, [connection, opts])

  @doc """
  Admits one unreliable QUIC DATAGRAM using the engine's public operation API.

  The peer must advertise DATAGRAM receive support. Payloads preserve message
  boundaries, are congestion-controlled and are never retransmitted after loss.
  `info/1` exposes the negotiated payload limit under `:datagram`. Admission is
  not peer delivery; references, deadlines, blocked and unknown outcomes follow
  the same contract as `send_stream/4`.
  """
  def send_datagram(connection, bytes, opts \\ []),
    do: backend_for_handle(connection, :send_datagram, [connection, bytes, opts])

  @doc """
  Pulls up to `max` complete DATAGRAM payloads from the attached consumer.

  Enable receive support with `quic_options: [datagram: [max_frame_size: 1200]]`.
  The handler receives coalesced `:datagram_readable` events, which rearm while
  messages remain unread. Receive queues have finite item and byte limits;
  overflow drops whole new messages. Destructive pulls retain the engine's
  operation references, finite deadlines and unknown-outcome semantics.
  """
  def read_datagrams(connection, max \\ 32, opts \\ []),
    do: backend_for_handle(connection, :read_datagrams, [connection, max, opts])

  def events(connection, max \\ 32, opts \\ []),
    do: backend_for_handle(connection, :events, [connection, max, opts])

  def open_stream(connection, kind, opts \\ []),
    do: backend_for_handle(connection, :open_stream, [connection, kind, opts])

  def send_stream(stream, bytes, fin \\ false, opts \\ []),
    do: backend_for_handle(stream, :send_stream, [stream, bytes, fin, opts])

  def read(stream, max_bytes, opts \\ []),
    do: backend_for_handle(stream, :read, [stream, max_bytes, opts])

  def reset_stream(stream, code, opts \\ []),
    do: backend_for_handle(stream, :reset_stream, [stream, code, opts])

  def stop_stream(stream, code, opts \\ []),
    do: backend_for_handle(stream, :stop_stream, [stream, code, opts])

  def close(connection, code \\ 0, reason \\ <<>>, opts \\ []),
    do: backend_for_handle(connection, :close, [connection, code, reason, opts])

  def operation_status(handle, ref),
    do: backend_for_handle(handle, :operation_status, [handle, ref])

  # elixir_quic is the supported engine. Runtime calls keep the dependency optional
  # for ordinary UDP consumers; no optional-package struct is expanded here.
  defp backend_for_handle(_handle, function, args), do: apply(Quic, function, args)
end
