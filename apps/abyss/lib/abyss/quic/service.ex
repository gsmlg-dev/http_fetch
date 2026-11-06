defmodule Abyss.QUIC.Service do
  @moduledoc false
  use GenServer
  alias Abyss.Dispatcher.{Admission, Writer, SendCapability}

  def start_link(opts) do
    if Keyword.keyword?(opts) do
      with {:ok, config} <- validate(opts),
           :ok <- validate_credentials(config) do
        GenServer.start_link(__MODULE__, config, Keyword.take(opts, [:name]))
      end
    else
      {:error, :invalid_configuration}
    end
  end

  @impl true
  def init(config) do
    Process.flag(:trap_exit, true)

    state =
      Map.merge(config, %{
        generation: make_ref(),
        workers: %{},
        worker_refs: %{},
        callbacks: %{}
      })

    steps = [
      {:socket, fn s -> :gen_udp.open(s.port, [:binary, active: false, ip: s.ip]) end},
      {:local, fn s -> :inet.sockname(s.socket) end},
      {:admission,
       fn s ->
         Admission.start_link(
           generation: s.generation,
           max_queue: s.writer_max_queue,
           max_bytes: s.writer_max_bytes
         )
       end},
      {:writer,
       fn s ->
         Writer.start_link(
           socket: s.socket,
           transport: Abyss.QUIC.SocketTransport,
           owner: self(),
           generation: s.generation,
           admission: s.admission,
           max_queue: s.writer_max_queue,
           max_bytes: s.writer_max_bytes
         )
       end},
      {:endpoint, &start_endpoint/1}
    ]

    case Enum.reduce_while(steps, {:ok, state}, fn {key, start}, {:ok, s} ->
           case start.(s) do
             {:ok, value} -> {:cont, {:ok, Map.put(s, key, value)}}
             {:error, reason} -> {:halt, {:error, reason, s}}
           end
         end) do
      {:ok, state} ->
        receiver =
          spawn_link(fn -> receive_loop(state.socket, state.endpoint, state.backend) end)

        {:ok, Map.put(state, :receiver, receiver)}

      {:error, reason, state} ->
        cleanup(state)
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:local, _from, state), do: {:reply, {:ok, state.local}, state}

  @impl true
  def handle_info({:quic_accept, endpoint}, %{endpoint: endpoint} = state), do: accept_one(state)
  def handle_info(:accept_next, state), do: accept_one(state)

  def handle_info({:callback_started, worker, token, timeout}, state) do
    if Map.has_key?(state.worker_refs, worker) do
      timer = Process.send_after(self(), {:callback_timeout, worker, token}, timeout)
      {:noreply, %{state | callbacks: Map.put(state.callbacks, worker, {token, timer})}}
    else
      {:noreply, state}
    end
  end

  def handle_info({:callback_finished, worker, token}, state) do
    case state.callbacks[worker] do
      {^token, timer} ->
        _ = Process.cancel_timer(timer)
        {:noreply, %{state | callbacks: Map.delete(state.callbacks, worker)}}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:callback_timeout, worker, token}, state) do
    if match?({^token, _}, state.callbacks[worker]), do: Process.exit(worker, :kill)
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, worker, _reason}, state) do
    # The engine monitors its attached consumer. Never perform a blocking close
    # from this shared service process on consumer death.
    if state.worker_refs[worker] == ref do
      _ = if entry = state.callbacks[worker], do: Process.cancel_timer(elem(entry, 1))

      {:noreply,
       %{
         state
         | workers: Map.delete(state.workers, ref),
           worker_refs: Map.delete(state.worker_refs, worker),
           callbacks: Map.delete(state.callbacks, worker)
       }}
    else
      {:noreply, state}
    end
  end

  def handle_info({:EXIT, pid, reason}, state) do
    if pid in [state.writer, state.admission, state.endpoint, state.receiver],
      do: {:stop, {:host_component_down, reason}, state},
      else: {:noreply, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  @impl true
  def format_status(_reason, [_dictionary, state]),
    do: [data: [{String.to_charlist("State"), Map.drop(state, [:tls, :handler_opts])}]]

  @impl true
  def terminate(_reason, state), do: cleanup(state)

  defp accept_one(state) do
    # A finite endpoint call and one connection per mailbox turn let watchdogs
    # and shutdown remain responsive under a stream of new connections.
    case apply(state.backend, :accept, [state.endpoint, [timeout: state.init_timeout]]) do
      {:ok, connection} ->
        if map_size(state.workers) < state.max_connections do
          {:ok, worker} =
            Abyss.QUIC.Worker.start_link(
              self(),
              connection,
              Map.take(state, [
                :backend,
                :handler,
                :handler_opts,
                :alpn,
                :init_timeout,
                :callback_timeout,
                :shutdown_timeout,
                :poll_interval,
                :event_batch
              ])
            )

          ref = Process.monitor(worker)
          send(self(), :accept_next)

          {:noreply,
           %{
             state
             | workers: Map.put(state.workers, ref, connection),
               worker_refs: Map.put(state.worker_refs, worker, ref)
           }}
        else
          # Engine and host use the same connection ceiling; exceeding it means
          # ownership accounting is no longer reliable, so fail this listener.
          {:stop, :consumer_limit, state}
        end

      {:error, :would_block} ->
        {:noreply, state}

      other ->
        {:stop, {:accept_failed, other}, state}
    end
  end

  defp start_endpoint(state) do
    capability = %SendCapability{
      writer: state.writer,
      admission: state.admission,
      generation: state.generation
    }

    send_fun = fn remote, bytes ->
      case Abyss.Dispatcher.send_receipt(capability, remote, bytes, state.writer_timeout) do
        {:unknown, ref} -> {:error, {:unknown_send, state.generation, ref}}
        result -> result
      end
    end

    opts =
      Keyword.merge(state.quic_options,
        io: {:external, state.local, send_fun},
        tls: Keyword.put(state.tls, :alpn, state.alpn),
        acceptor: self(),
        max_connections: state.max_connections
      )

    apply(state.backend, :listen, [opts])
  end

  defp receive_loop(socket, endpoint, backend) do
    case :gen_udp.recv(socket, 0, :infinity) do
      {:ok, {ip, port, bytes}} ->
        case apply(Module.concat(backend, Endpoint), :receive_datagram, [
               endpoint,
               {ip, port},
               bytes,
               System.monotonic_time(:microsecond)
             ]) do
          :ok -> receive_loop(socket, endpoint, backend)
          {:error, reason} -> exit({:ingress_failed, reason})
        end

      {:error, reason} ->
        exit({:socket_closed, reason})
    end
  end

  defp cleanup(state) do
    # Stop intake before draining; queued/new datagrams cannot admit connections.
    if is_pid(state[:receiver]), do: Process.exit(state.receiver, :kill)
    workers = Map.keys(state.worker_refs)
    Enum.each(workers, &send(&1, :service_draining))
    deadline = System.monotonic_time(:millisecond) + state.shutdown_timeout
    await_workers(Map.values(state.worker_refs), deadline)
    # All hard stops share the same drain deadline. No socket operation is
    # delegated to a connection; this owner alone explicitly closes the socket.
    Enum.each(
      workers ++ Enum.map([:receiver, :endpoint, :writer], &Map.get(state, &1)),
      fn
        pid when is_pid(pid) -> Process.exit(pid, :kill)
        _ -> :ok
      end
    )

    if not Map.has_key?(state, :writer) and is_pid(state[:admission]),
      do: Process.exit(state.admission, :kill)

    if socket = Map.get(state, :socket), do: :gen_udp.close(socket)
    :ok
  end

  defp await_workers([], _deadline), do: :ok

  defp await_workers(refs, deadline) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    receive do
      {:DOWN, ref, :process, _, _} -> await_workers(List.delete(refs, ref), deadline)
    after
      remaining -> :ok
    end
  end

  defp validate(opts) do
    backend = Keyword.get(opts, :_backend, Quic)
    handler = Keyword.get(opts, :handler)

    {module, handler_opts} =
      case handler do
        {m, o} when is_atom(m) -> {m, o}
        m -> {m, []}
      end

    defaults = [
      ip: {127, 0, 0, 1},
      port: 0,
      max_connections: 128,
      init_timeout: 5000,
      callback_timeout: 5000,
      shutdown_timeout: 1000,
      poll_interval: 10,
      event_batch: 32,
      writer_timeout: 1000,
      writer_max_queue: 128,
      writer_max_bytes: 1_048_576,
      tls: [],
      quic_options: []
    ]

    config = Map.new(Keyword.merge(defaults, opts))

    positive = [
      :max_connections,
      :init_timeout,
      :callback_timeout,
      :shutdown_timeout,
      :poll_interval,
      :writer_timeout,
      :writer_max_queue,
      :writer_max_bytes
    ]

    cond do
      not is_atom(backend) or not Code.ensure_loaded?(backend) or
          not function_exported?(backend, :listen, 1) ->
        {:error, :quic_backend_unavailable}

      not is_atom(module) or not Code.ensure_loaded?(module) or
        not function_exported?(module, :init, 3) or
          not function_exported?(module, :handle_event, 2) ->
        {:error, :invalid_handler}

      not valid_alpn?(config[:alpn]) ->
        {:error, :invalid_alpn}

      not Keyword.keyword?(config.tls) ->
        {:error, :invalid_tls}

      not Keyword.has_key?(config.tls, :cert) or not Keyword.has_key?(config.tls, :key) ->
        {:error, :missing_server_credentials}

      not Keyword.keyword?(config.quic_options) ->
        {:error, :invalid_quic_options}

      Enum.any?(config.quic_options, fn {k, _} ->
        k in [:io, :acceptor, :tls, :max_connections, :role, :public]
      end) ->
        {:error, :reserved_quic_option}

      not valid_engine_options?(config.quic_options) ->
        {:error, :invalid_quic_options}

      not valid_ip?(config.ip) ->
        {:error, :invalid_ip}

      config.ip in [{0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}] ->
        {:error, :wildcard_bind_unsupported}

      not is_integer(config.port) or config.port not in 0..65535 ->
        {:error, :invalid_port}

      Enum.any?(positive, &(not is_integer(config[&1]) or config[&1] <= 0)) ->
        {:error, :invalid_limit}

      not is_integer(config.event_batch) or config.event_batch not in 1..128 ->
        {:error, :invalid_limit}

      Keyword.keys(opts) -- (Keyword.keys(defaults) ++ [:_backend, :handler, :alpn, :name]) != [] ->
        {:error, :unknown_option}

      true ->
        {:ok, Map.merge(config, %{backend: backend, handler: module, handler_opts: handler_opts})}
    end
  end

  defp valid_engine_options?(options) do
    Enum.all?(options, fn
      {:retry, value} ->
        is_boolean(value)

      {:retry_ttl, value} ->
        is_integer(value) and value in 1..60_000_000

      {key, value} when key in [:retry_limit, :event_limit, :operation_limit] ->
        is_integer(value) and value in 1..10_000

      {:idle_timeout, :infinity} ->
        true

      {key, value}
      when key in [:handshake_timeout, :idle_timeout, :closing_timeout, :draining_timeout] ->
        is_integer(value) and value > 0

      {:streams, streams} ->
        valid_stream_options?(streams)

      _ ->
        false
    end) and length(Keyword.keys(options)) == length(Enum.uniq(Keyword.keys(options)))
  end

  defp valid_stream_options?(options) do
    credit = [
      :max_data,
      :max_stream_data,
      :max_stream_data_bidi_local,
      :max_stream_data_bidi_remote,
      :max_stream_data_uni,
      :max_streams_bidi,
      :max_streams_uni
    ]

    retained = [:max_buffer, :max_ready_bytes, :max_stream_records, :max_recv_ranges]

    Keyword.keyword?(options) and
      Enum.all?(options, fn {key, value} ->
        is_integer(value) and value < 4_611_686_018_427_387_904 and
          ((key in credit and value >= 0) or (key in retained and value > 0))
      end) and length(Keyword.keys(options)) == length(Enum.uniq(Keyword.keys(options)))
  end

  # Validate credentials through the public record-free TLS API. The preflight
  # state is discarded; elixir_quic still creates and owns every real TLS transcript.
  defp validate_credentials(%{backend: Quic} = config) do
    opts = Keyword.merge(config.tls, alpn: config.alpn, transport_parameters: <<>>)

    case apply(SSL.QUIC, :new, [:server, opts]) do
      {:ok, _state, _actions} -> :ok
      {:error, reason} -> {:error, {:invalid_tls, reason}}
    end
  end

  defp validate_credentials(_test_backend), do: :ok

  defp valid_alpn?(list) when is_list(list) and list != [],
    do:
      Enum.all?(list, &(is_binary(&1) and byte_size(&1) in 1..255)) and
        length(Enum.uniq(list)) == length(list)

  defp valid_alpn?(_), do: false

  defp valid_ip?(ip) when is_tuple(ip) and tuple_size(ip) in [4, 8] do
    max = if tuple_size(ip) == 4, do: 255, else: 65535
    ip |> Tuple.to_list() |> Enum.all?(&(is_integer(&1) and &1 >= 0 and &1 <= max))
  end

  defp valid_ip?(_), do: false
end

defmodule Abyss.QUIC.Worker do
  @moduledoc false
  use GenServer

  def start_link(owner, connection, config),
    do: GenServer.start_link(__MODULE__, {owner, connection, config})

  @impl true
  def init({owner, connection, config}) do
    send(self(), :attach)

    {:ok,
     %{owner: owner, connection: connection, config: config, app_state: nil, initialized: false}}
  end

  @impl true
  def handle_info(:attach, state) do
    watched(state, state.config.init_timeout, fn ->
      with :ok <-
             apply(state.config.backend, :attach, [
               state.connection,
               self(),
               [timeout: state.config.init_timeout]
             ]),
           {:ok, metadata} <- apply(state.config.backend, :info, [state.connection]),
           true <- metadata.alpn in state.config.alpn,
           {:ok, app_state} <-
             state.config.handler.init(state.connection, metadata, state.config.handler_opts) do
        send(self(), :poll)
        {:noreply, %{state | initialized: true, app_state: app_state}}
      else
        reason ->
          # If attachment failed the engine may not yet monitor us. Request a
          # bounded local close from this isolated worker, never from ingress.
          apply(state.config.backend, :close, [
            state.connection,
            0,
            <<>>,
            [timeout: state.config.init_timeout]
          ])

          {:stop, {:binding_failed, reason}, state}
      end
    end)
  end

  def handle_info(:poll, %{initialized: true} = state) do
    watched(state, state.config.callback_timeout, fn ->
      case apply(state.config.backend, :events, [
             state.connection,
             state.config.event_batch,
             [timeout: state.config.callback_timeout]
           ]) do
        {:ok, events} ->
          case Enum.reduce_while(events ++ [:tick], {:ok, state.app_state}, fn event,
                                                                               {:ok, app_state} ->
                 case state.config.handler.handle_event(event, app_state) do
                   {:ok, next} -> {:cont, {:ok, next}}
                   {:stop, reason, next} -> {:halt, {:stop, reason, next}}
                 end
               end) do
            {:ok, next} ->
              Process.send_after(self(), :poll, state.config.poll_interval)
              {:noreply, %{state | app_state: next}}

            {:stop, reason, next} ->
              {:stop, reason, %{state | app_state: next}}
          end

        other ->
          {:stop, {:event_poll_failed, other}, state}
      end
    end)
  end

  def handle_info({:quic_closed, connection, reason}, %{connection: connection} = state) do
    watched(state, state.config.callback_timeout, fn ->
      next =
        if state.initialized do
          case state.config.handler.handle_event({:closed, reason}, state.app_state) do
            {:ok, next} -> next
            {:stop, _, next} -> next
          end
        else
          state.app_state
        end

      {:stop, :normal, %{state | app_state: next}}
    end)
  end

  def handle_info(:service_draining, state) do
    apply(state.config.backend, :close, [
      state.connection,
      0,
      <<>>,
      [timeout: state.config.shutdown_timeout]
    ])

    {:stop, :normal, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  @impl true
  def format_status(_reason, [_dictionary, state]),
    do: [
      data: [{String.to_charlist("State"), Map.take(state, [:connection, :initialized, :owner])}]
    ]

  @impl true
  def terminate(reason, state) do
    watched(state, state.config.callback_timeout, fn ->
      if state.initialized and function_exported?(state.config.handler, :terminate, 2),
        do: state.config.handler.terminate(reason, state.app_state)
    end)
  end

  defp watched(state, timeout, fun) do
    token = make_ref()
    send(state.owner, {:callback_started, self(), token, timeout})
    result = fun.()
    send(state.owner, {:callback_finished, self(), token})
    result
  end
end

defmodule Abyss.QUIC.SocketTransport do
  @moduledoc false
  def send(socket, ip, port, bytes), do: :gen_udp.send(socket, ip, port, bytes)
end
