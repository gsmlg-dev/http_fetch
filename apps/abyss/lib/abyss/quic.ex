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
