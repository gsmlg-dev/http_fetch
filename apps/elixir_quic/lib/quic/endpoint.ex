defmodule Quic.Endpoint do
  @moduledoc """
  Bounded standalone UDP endpoint with persistent connection routing.

  A server owns one shared socket; connections only borrow its send capability.
  Reception has one outstanding credit and is rearmed after synchronous routing.
  Active CID routes can forward changed peer addresses to a server connection;
  only the connection may authenticate and validate a new path.
  """
  use GenServer
  alias Quic.{Codec, Connection, Protection, ResumptionStore, Retry, TransportParameters}
  alias Quic.IO.{ExternalWriter, GenUDP}

  @cid_length 8
  def start_link(opts) do
    case Keyword.get(opts, :cleanup) do
      nil ->
        GenServer.start_link(__MODULE__, opts)

      _ ->
        {:abs_ms, deadline} = Quic.Cleanup.deadline(opts)
        remaining = deadline - System.monotonic_time(:millisecond)

        if remaining > 0,
          do: GenServer.start_link(__MODULE__, opts, timeout: remaining),
          else: {:error, :deadline_expired}
    end
  end

  def local(pid), do: safe_call(pid, :local, 5_000)
  def connections(pid), do: safe_call(pid, :connections, 5_000)
  def stats(pid), do: safe_call(pid, :stats, 5_000)

  def accept(pid, timeout_or_opts \\ 5_000) do
    opts = if is_list(timeout_or_opts), do: timeout_or_opts, else: [timeout: timeout_or_opts]
    endpoint_call(pid, :accept, opts)
  end

  def connect(pid, remote, opts \\ []), do: endpoint_call(pid, {:connect, remote}, opts)
  def operation_status(pid, ref), do: safe_call(pid, {:operation_status, ref}, 5_000)

  def receive_datagram(pid, remote, bytes, at),
    do: safe_call(pid, {:datagram, remote, bytes, at}, 5_000)

  @impl true
  def init(opts) do
    role = Keyword.fetch!(opts, :role)
    max = Keyword.get(opts, :max_connections, 128)
    event_limit = Keyword.get(opts, :event_limit, 128)

    retry = Keyword.get(opts, :retry, false)
    retry_limit = Keyword.get(opts, :retry_limit, 100)
    retry_ttl = Keyword.get(opts, :retry_ttl, 5_000_000)

    operation_limit = Keyword.get(opts, :operation_limit, 256)

    if role in [:client, :server] and is_integer(max) and max > 0 and
         valid_item_limit?(event_limit) and valid_item_limit?(operation_limit) and
         valid_retry_options?(retry, role, retry_limit, retry_ttl) do
      with {:ok, resumption} <- resumption_policy(Keyword.get(opts, :resumption)),
           {:ok, early_policy} <-
             Quic.EarlyData.policy(Keyword.get(opts, :early_data), resumption),
           {:ok, store} <- ResumptionStore.new(if(resumption, do: resumption.store, else: [])),
           :ok <- enroll_cleanup(opts),
           {:ok, io} <- open_io(opts, role) do
        data = %{
          resumption: resumption,
          early_policy: early_policy,
          early_authority: %Quic.EarlyData{},
          session_store: store,
          cleanup: Keyword.get(opts, :cleanup),
          cleanup_monitor: Quic.Cleanup.monitor(Keyword.get(opts, :cleanup)),
          role: role,
          retry: retry,
          retry_key: if(retry, do: :crypto.strong_rand_bytes(32)),
          retry_limit: retry_limit,
          retry_ttl: retry_ttl,
          retry_window: GenUDP.monotonic_time(),
          retry_count: 0,
          retry_sent: 0,
          retry_validated: 0,
          socket: io.socket,
          ios: %{
            default:
              Map.merge(io, %{
                generation: if(io.external, do: nil, else: GenUDP.identity(io.socket).generation),
                retiring: false
              })
          },
          migration: nil,
          ingress_local: nil,
          monitor: io.monitor,
          io_module: io.module,
          io_writer: io.writer,
          local: io.local,
          external: io.external,
          opts: opts,
          stream_observer: Keyword.get(opts, :stream_observer),
          max: max,
          routes: %{},
          provisional: %{},
          retired: %{},
          retired_limit: max * 4,
          connections: %{},
          admission_drops: 0,
          last_error: nil,
          accepts: [],
          acceptor: Keyword.get(opts, :acceptor),
          acceptor_monitor: if(is_pid(opts[:acceptor]), do: Process.monitor(opts[:acceptor])),
          operations: %{},
          operation_sequence: 0,
          operation_limit: operation_limit
        }

        if role == :server or not Keyword.has_key?(opts, :remote) do
          {:ok, data}
        else
          admit_initial_remote(data, opts, io)
        end
      end
    else
      {:stop, :invalid_endpoint_options}
    end
  end

  defp admit_initial_remote(data, opts, io) do
    case admit(
           data,
           Keyword.fetch!(opts, :remote),
           :crypto.strong_rand_bytes(@cid_length),
           nil
         ) do
      {:ok, data, _entry} ->
        {:ok, data}

      {:error, reason} ->
        close_io(io)
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:local, _from, %{local: local} = data), do: {:reply, local, data}

  def handle_call({:datagram, remote, bytes, at}, _from, data)
      when is_tuple(remote) and is_binary(bytes) and is_integer(at) do
    {:reply, :ok, route(data, remote, bytes, at)}
  end

  def handle_call(:connections, _from, data) do
    entries =
      Enum.map(data.connections, fn {pid, entry} -> %{pid: pid, generation: entry.generation} end)

    {:reply, entries, data}
  end

  def handle_call({:endpoint_operation, ref, deadline, request}, _from, data) do
    signature = :crypto.hash(:sha256, :erlang.term_to_binary(request))

    cond do
      not is_reference(ref) or not is_integer(deadline) ->
        {:reply, {:error, :invalid_operation}, data}

      Map.has_key?(data.operations, ref) ->
        previous = data.operations[ref]

        result =
          if previous.signature == signature,
            do: previous.result,
            else: {:error, :operation_ref_conflict}

        {:reply, result, data}

      System.monotonic_time(:millisecond) >= deadline ->
        result = {:error, :deadline_expired}
        {:reply, result, record_operation(data, ref, signature, :rejected, result)}

      request == :accept ->
        case data.accepts do
          [handle | rest] ->
            result = {:ok, handle}
            next = record_operation(%{data | accepts: rest}, ref, signature, :completed, result)
            {:reply, result, next}

          [] ->
            result = {:error, :would_block}
            {:reply, result, record_operation(data, ref, signature, :rejected, result)}
        end

      match?({:connect, _}, request) and data.migration != nil ->
        result = {:blocked, :exclusive_migration}
        {:reply, result, record_operation(data, ref, signature, :rejected, result)}

      match?({:connect, _}, request) and data.role == :client ->
        connect_operation(data, ref, signature, request, deadline)

      match?({:connect, _}, request) ->
        result = {:error, :server_endpoint}
        {:reply, result, record_operation(data, ref, signature, :rejected, result)}

      true ->
        result = {:error, :invalid_operation}
        {:reply, result, record_operation(data, ref, signature, :rejected, result)}
    end
  end

  def handle_call({:operation_status, ref}, _from, data) do
    result =
      case Map.get(data.operations, ref) do
        nil -> :unknown
        entry -> Map.take(entry, [:status, :result])
      end

    {:reply, result, data}
  end

  def handle_call(:stats, _from, data),
    do:
      {:reply,
       %{
         routes: map_size(data.routes) + map_size(data.provisional),
         admission_drops: data.admission_drops,
         retry_sent: data.retry_sent,
         retry_validated: data.retry_validated,
         last_error: data.last_error,
         resumption: %{
           enabled: data.resumption != nil,
           early_data: data.early_policy != nil,
           early_capacity: Quic.EarlyData.stats(data.early_authority),
           tickets: map_size(data.session_store.entries),
           bytes: data.session_store.bytes
         }
       }, data}

  @impl true
  def handle_info({:quic_udp, generation, credit, remote, bytes, at}, data) do
    case Quic.Cleanup.authorize(data.cleanup) do
      :ok ->
        io =
          Enum.find_value(data.ios, fn {_, io} ->
            if io.generation == generation and not Map.get(io, :retiring, false), do: io
          end)

        next = if io, do: route(%{data | ingress_local: io.local}, remote, bytes, at), else: data

        case if(io,
               do: consume_credit(%{next | socket: io.socket}, generation, credit),
               else: :ok
             ) do
          :ok -> {:noreply, next}
          :retired -> {:stop, :normal, next}
          {:error, reason} -> {:stop, {:socket_receive, reason}, next}
        end

      {:error, _reason} ->
        {:stop, :normal, data}
    end
  end

  def handle_info({:quic_tls_request, pid, generation, request, deadline}, data) do
    now = System.monotonic_time(:millisecond)

    case data.connections[pid] do
      %{generation: ^generation, session_partition: partition}
      when is_binary(partition) and now < deadline ->
        {result, store} = authority_request(data.session_store, partition, request, now, deadline)
        data = %{data | session_store: store}
        {result, data} = admit_early(data, pid, generation, request, result)
        send(pid, {:quic_tls_result, generation, request.id, result})
        {:noreply, data}

      _ ->
        send(pid, {:quic_tls_result, generation, request.id, :miss})
        {:noreply, data}
    end
  end

  def handle_info({:quic_early_release, pid, generation}, data) do
    if match?(%{generation: ^generation}, data.connections[pid]),
      do:
        {:noreply, %{data | early_authority: Quic.EarlyData.release(data.early_authority, pid)}},
      else: {:noreply, data}
  end

  def handle_info({:quic_session_ticket, pid, generation, session}, data) do
    case data.connections[pid] do
      %{generation: ^generation, session_partition: partition}
      when is_binary(partition) and data.role == :client ->
        case ResumptionStore.store(
               data.session_store,
               partition,
               session,
               System.monotonic_time(:millisecond)
             ) do
          {:ok, store} -> {:noreply, %{data | session_store: store}}
          {:error, _, store} -> {:noreply, %{data | session_store: store}}
        end

      _ ->
        {:noreply, data}
    end
  end

  def handle_info({:quic_bind_path, pid, generation, ref, id, local, deadline}, data) do
    permitted =
      match?(%{generation: ^generation}, data.connections[pid]) and
        data.role == :client and not data.external and map_size(data.connections) == 1 and
        map_size(data.ios) == 1 and data.migration == nil

    if permitted and System.monotonic_time(:millisecond) < deadline do
      {ip, port} = local

      # An endpoint without a cleanup scope binds its migration socket the same
      # way it bound its first socket. A private scope cannot be used: this
      # endpoint is not an enrolled producer in it, so every reservation fails.
      opts = [ip: ip, port: port, cleanup: data.cleanup, deadline: {:abs_ms, deadline}]

      case open_udp(opts, :client) do
        {:ok, socket} ->
          identity = GenUDP.identity(socket)

          io = %{
            socket: socket,
            monitor: Process.monitor(socket),
            generation: identity.generation,
            local: identity.local,
            retiring: false
          }

          send(pid, {:quic_path_bound, generation, ref, id, {:ok, socket, io.local}})
          {:noreply, %{data | ios: Map.put(data.ios, id, io), migration: {pid, generation, ref}}}

        {:error, reason} ->
          send(pid, {:quic_path_bound, generation, ref, id, {:error, {:bind_failed, reason}}})
          {:noreply, data}
      end
    else
      send(pid, {:quic_path_bound, generation, ref, id, {:error, :endpoint_not_exclusive}})
      {:noreply, data}
    end
  end

  def handle_info({:quic_select_local_path, pid, generation, id}, data) do
    case {data.connections[pid], data.ios[id]} do
      {%{generation: ^generation}, io} when is_map(io) ->
        {:noreply,
         %{data | socket: io.socket, monitor: io.monitor, io_writer: io.socket, local: io.local}}

      _ ->
        {:noreply, data}
    end
  end

  def handle_info({:quic_retire_local_path, pid, generation, id}, data) do
    case {data.connections[pid], data.ios[id]} do
      {%{generation: ^generation}, io} when is_map(io) ->
        # IO termination closes its native socket before the monitored DOWN.
        GenUDP.close(io.socket)

        {:noreply, put_in(data.ios[id].retiring, true)}

      _ ->
        send(pid, {:quic_path_retired, generation, id})
        {:noreply, data}
    end
  end

  def handle_info({:quic_ready, pid, generation, _metadata}, data) do
    case data.connections[pid] do
      %{generation: ^generation} = entry when data.role == :server ->
        accepted = handle(entry)

        if is_pid(data.acceptor) and data.accepts == [],
          do: send(data.acceptor, {:quic_accept, self()})

        {:noreply, %{data | accepts: data.accepts ++ [accepted]}}

      _ ->
        {:noreply, data}
    end
  end

  def handle_info({:quic_closed, pid, generation, reason}, data) do
    case data.connections[pid] do
      %{generation: ^generation} -> {:noreply, remove(%{data | last_error: reason}, pid)}
      _ -> {:noreply, data}
    end
  end

  def handle_info({:quic_register_cid, pid, generation, registration}, data) do
    case data.connections[pid] do
      %{generation: ^generation} ->
        count = Enum.count(data.routes, fn {_, target} -> target == pid end)
        cid = registration.cid

        if byte_size(cid) == @cid_length and not Map.has_key?(data.routes, cid) and count < 8 do
          routes = Map.put(data.routes, cid, pid)
          send(pid, {:quic_cid_registered, generation, registration.registration_id})
          {:noreply, %{data | routes: routes}}
        else
          send(pid, {:quic_cid_registration_failed, generation, registration.registration_id})
          {:noreply, data}
        end

      _ ->
        {:noreply, data}
    end
  end

  def handle_info({:quic_retire_cid, pid, generation, cid}, data) do
    if match?(%{generation: ^generation}, data.connections[pid]) and data.routes[cid] == pid do
      retired = add_retired(data.retired, [{:cid, cid}], data.retired_limit)
      {:noreply, %{data | routes: Map.delete(data.routes, cid), retired: retired}}
    else
      {:noreply, data}
    end
  end

  def handle_info({:quic_closing, pid, generation, reason}, data) do
    case data.connections[pid] do
      %{generation: ^generation} ->
        # Keep CID routes while the connection drains.  A late Initial addressed
        # to an old CID must reach the existing process and never trigger admission
        # of a replacement connection.  Terminal cleanup happens on quic_closed.
        {:noreply, %{data | last_error: reason}}

      _ ->
        {:noreply, data}
    end
  end

  def handle_info(
        {:quic_cleanup_retire, observer},
        %{cleanup: %Quic.Cleanup.Lease{handle: %{observer: observer}}} = data
      ),
      do: {:stop, :normal, data}

  def handle_info({:DOWN, monitor, :process, pid, _reason}, data) do
    retiring = Enum.find(data.ios, fn {_, io} -> io.monitor == monitor end)

    if retiring != nil and monitor != data.monitor do
      {id, io} = retiring

      case data.migration do
        {connection, generation, _ref} ->
          message =
            if Map.get(io, :retiring, false),
              do: :quic_path_retired,
              else: :quic_local_path_failed

          send(connection, {message, generation, id})

        _ ->
          :ok
      end

      {:noreply, %{data | ios: Map.delete(data.ios, id), migration: nil}}
    else
      if monitor in [data.monitor, data.acceptor_monitor, data.cleanup_monitor] do
        {:stop, :normal, data}
      else
        case data.connections[pid] do
          %{monitor: ^monitor} -> {:noreply, remove(data, pid)}
          _ -> {:noreply, data}
        end
      end
    end
  end

  def handle_info({:quic_udp_error, _, _}, data), do: {:stop, :normal, data}

  def handle_info({:quic_stream, pid, stream_id, events}, data) do
    if is_pid(data.stream_observer),
      do: send(data.stream_observer, {:quic_stream, pid, stream_id, events})

    {:noreply, data}
  end

  def handle_info({:quic_stream_reset, pid, stream_id, events}, data) do
    if is_pid(data.stream_observer),
      do: send(data.stream_observer, {:quic_stream_reset, pid, stream_id, events})

    {:noreply, data}
  end

  def handle_info(_, data), do: {:noreply, data}

  defp consume_credit(%{socket: socket} = data, generation, credit) do
    case GenUDP.consumed(socket, generation, credit) do
      {:error, :retiring} = failure ->
        case Quic.Cleanup.authorize(data.cleanup) do
          :ok -> failure
          {:error, _reason} -> :retired
        end

      result ->
        result
    end
  catch
    :exit, {reason, {GenServer, :call, [^socket, {:consumed, ^generation, ^credit}, _]}} = failure
    when reason in [:noproc, :normal] ->
      # Retirement can close IO after the routing authorization above. Only
      # lost scope authority makes that exact receive-credit call a normal stop.
      case Quic.Cleanup.authorize(data.cleanup) do
        :ok -> exit(failure)
        {:error, _reason} -> :retired
      end
  end

  defp route(data, remote, bytes, at) do
    case destination(bytes) do
      {:ok, dcid} ->
        if retired?(data, remote, dcid) do
          data
        else
          pid = Map.get(data.routes, dcid) || Map.get(data.provisional, {remote, dcid})

          case data.connections[pid] do
            %{remote: ^remote} = entry -> deliver(data, entry, remote, bytes, at)
            nil -> maybe_admit(data, remote, bytes, at)
            entry when data.role == :server -> deliver(data, entry, remote, bytes, at)
            _ -> data
          end
        end

      _ ->
        data
    end
  end

  defp maybe_admit(%{role: :server} = data, remote, bytes, at) when byte_size(bytes) >= 1200 do
    with {:ok, initial} <- Codec.parse_initial(bytes),
         true <- byte_size(initial.dcid) >= 8 do
      if map_size(data.connections) >= data.max do
        %{data | admission_drops: data.admission_drops + 1}
      else
        admit_initial(data, remote, initial, bytes, at)
      end
    else
      _ -> data
    end
  end

  defp maybe_admit(data, _, _, _), do: data

  defp admit_initial(%{retry: true} = data, remote, %{token: <<>>} = initial, _bytes, at) do
    now = GenUDP.monotonic_time()

    data =
      if now - data.retry_window >= 1_000_000,
        do: %{data | retry_window: now, retry_count: 0},
        else: data

    if data.retry_count >= data.retry_limit do
      %{data | admission_drops: data.admission_drops + 1}
    else
      scid = :crypto.strong_rand_bytes(@cid_length)
      token = Retry.issue(data.retry_key, remote, initial.dcid, scid, at)

      body =
        <<0xF0, 1::32, byte_size(initial.scid), initial.scid::binary, byte_size(scid),
          scid::binary, token::binary>>

      {:ok, tag} = Protection.retry_tag(initial.dcid, body)
      data = %{data | retry_count: data.retry_count + 1}

      case data.io_module.send(data.io_writer, body <> tag, remote) do
        {:ok, _sent_at} -> %{data | retry_sent: data.retry_sent + 1}
        {:error, reason} -> %{data | last_error: {:retry_send, reason}}
      end
    end
  end

  defp admit_initial(%{retry: true} = data, remote, initial, bytes, at) do
    with {:ok, original} <-
           Retry.verify(
             data.retry_key,
             remote,
             initial.dcid,
             initial.token,
             GenUDP.monotonic_time(),
             data.retry_ttl
           ),
         {:ok, next, entry} <- admit(data, remote, original, initial.scid, initial.dcid) do
      deliver(%{next | retry_validated: next.retry_validated + 1}, entry, bytes, at)
    else
      {:error, _} -> %{data | admission_drops: data.admission_drops + 1}
    end
  end

  defp admit_initial(data, remote, initial, bytes, at) do
    case admit(data, remote, initial.dcid, initial.scid) do
      {:ok, next, entry} -> deliver(next, entry, bytes, at)
      {:error, _} -> %{data | admission_drops: data.admission_drops + 1}
    end
  end

  defp admit(data, remote, original_dcid, peer_scid, retry_scid \\ nil, deadline \\ nil) do
    deadline = deadline || Quic.Cleanup.deadline(data.opts)
    scid = :crypto.strong_rand_bytes(@cid_length)
    dcid = peer_scid || original_dcid

    with false <- Map.has_key?(data.routes, scid),
         profile <- Keyword.get(data.opts, :profile),
         tls_opts <- profile_tls_options(Keyword.get(data.opts, :tls, []), profile),
         {:ok, data, tls_opts} <- configure_resumption(data, tls_opts, remote),
         {:ok, tls, idle_timeout} <-
           materialize(
             tls_opts,
             data.role,
             original_dcid,
             scid,
             retry_scid,
             effective_streams(data),
             Keyword.get(data.opts, :datagram, []),
             data.opts
           ),
         {:ok, local_parameters} <- TransportParameters.decode(tls[:transport_parameters]),
         opts <- [
           cleanup: data.cleanup,
           cleanup_deadline: if(data.cleanup, do: deadline),
           role: data.role,
           address_validated: retry_scid != nil,
           owner: self(),
           io: {data.io_module, data.io_writer},
           remote: remote,
           local: data.local,
           exclusive_io: not data.external and data.role == :client,
           public: Keyword.get(data.opts, :public, false),
           event_limit: Keyword.get(data.opts, :event_limit, 128),
           operation_limit: Keyword.get(data.opts, :operation_limit, 256),
           datagram: Keyword.get(data.opts, :datagram, []),
           handshake_timeout: Keyword.get(data.opts, :handshake_timeout, 10_000),
           idle_timeout: idle_timeout,
           closing_timeout: Keyword.get(data.opts, :closing_timeout),
           draining_timeout: Keyword.get(data.opts, :draining_timeout),
           scheduler:
             [
               dcid: dcid,
               scid: scid,
               original_dcid: original_dcid,
               initial_key_dcid: retry_scid || original_dcid,
               retry_scid: retry_scid,
               streams: effective_streams(data),
               ordinary_streams: if(data.early_policy, do: Keyword.get(data.opts, :streams, [])),
               early_receive_parameters: local_parameters.values,
               early_staging_limit:
                 if(data.early_policy && MapSet.size(data.early_authority.staging) < 32,
                   do: 32_768,
                   else: 0
                 ),
               max_datagram_frame_size:
                 Map.get(local_parameters.values, :max_datagram_frame_size, 0),
               active_connection_id_limit:
                 Map.get(local_parameters.values, :active_connection_id_limit, 2),
               reset_stream_at: Map.get(local_parameters.values, :reset_stream_at, false),
               max_packet_size: profile_packet_size(profile)
             ] ++ tls
         ],
         {:ok, birth} <- reserve_connection(data, deadline),
         {:ok, pid} <- start_connection(opts, birth),
         {:ok, generation} <- generation(pid) do
      entry = %{
        pid: pid,
        remote: remote,
        generation: generation,
        monitor: Process.monitor(pid),
        session_partition: get_in(tls_opts, [:resumption, :context]),
        local_parameters: tls[:transport_parameters]
      }

      {authority, _} =
        if data.early_policy,
          do: Quic.EarlyData.reserve_staging(data.early_authority, pid),
          else: {data.early_authority, 0}

      data = %{data | early_authority: authority}

      data = %{
        data
        | connections: Map.put(data.connections, pid, entry),
          routes: Map.put(data.routes, scid, pid)
      }

      data =
        if data.role == :server,
          do: %{
            data
            | provisional: Map.put(data.provisional, {remote, retry_scid || original_dcid}, pid)
          },
          else: data

      handle = handle(entry)

      data =
        if data.role == :server and not Keyword.get(data.opts, :public, false),
          do: %{data | accepts: data.accepts ++ [handle]},
          else: data

      {:ok, data, entry}
    else
      true ->
        {:error, :cid_collision}

      {:error, _} = error ->
        error
    end
  end

  defp handle(%{pid: pid, generation: generation}),
    do: %Quic.Runtime.ConnectionHandle{id: pid, generation: generation}

  defp generation(pid) do
    {:ok, Connection.status(pid).generation}
  catch
    :exit, _ -> {:error, :connection_start_failed}
  end

  defp resumption_policy(nil), do: {:ok, nil}
  defp resumption_policy(false), do: {:ok, nil}

  defp resumption_policy(opts) when is_list(opts) do
    if Keyword.keyword?(opts),
      do: valid_resumption_policy(opts),
      else: {:error, :invalid_resumption_policy}
  end

  defp resumption_policy(_), do: {:error, :invalid_resumption_policy}

  defp valid_resumption_policy(opts) do
    profile = Keyword.get(opts, :application_profile)
    lifetime = Keyword.get(opts, :ticket_lifetime, 600)

    cond do
      Keyword.get(opts, :enabled) != true ->
        {:error, :invalid_resumption_policy}

      not is_binary(profile) or byte_size(profile) not in 1..128 ->
        {:error, :resumption_profile_required}

      not is_integer(lifetime) or lifetime not in 1..600 ->
        {:error, :invalid_ticket_lifetime}

      Keyword.get(opts, :early_data, false) != false ->
        {:error, :early_data_unavailable}

      true ->
        {:ok,
         %{
           profile: profile,
           lifetime: lifetime,
           store: Keyword.take(opts, [:max_entries, :max_bytes])
         }}
    end
  end

  defp admit_early(
         data,
         pid,
         generation,
         %{operation: :commit, early_data: true, session: session},
         {:ok, :resumed}
       ) do
    case data.connections[pid] do
      %{generation: ^generation, local_parameters: parameters}
      when not is_nil(data.early_policy) ->
        case Quic.EarlyData.reserve(
               data.early_authority,
               pid,
               session.transport_parameters,
               parameters
             ) do
          {:ok, authority} -> {{:ok, :early_data}, %{data | early_authority: authority}}
          {:error, _} -> {{:ok, :resumed}, data}
        end

      _ ->
        {{:ok, :resumed}, data}
    end
  end

  defp admit_early(data, _, _, _, result), do: {result, data}

  defp configure_resumption(data, tls, remote) do
    cond do
      Keyword.has_key?(tls, :resumption) ->
        {:error, :runtime_resumption_policy_required}

      data.resumption == nil ->
        {:ok, data, tls}

      true ->
        # Bind immutable endpoint policy, trust, identity, algorithms and profile.
        # Generated transport parameters, keys and connection IDs never enter this digest.
        policy =
          {1, data.role, data.resumption.profile, if(data.role == :client, do: remote),
           Keyword.drop(tls, [:transport_parameters]), Keyword.get(data.opts, :profile),
           data.early_policy}

        partition = :crypto.hash(:sha256, :erlang.term_to_binary(policy))
        now = System.monotonic_time(:millisecond)

        {session, store} =
          if data.role == :client,
            do: ResumptionStore.claim_client(data.session_store, partition, now),
            else: {nil, data.session_store}

        options = [
          enabled: true,
          context: partition,
          now: now,
          session: session,
          ticket_lifetime: data.resumption.lifetime,
          early_data: early_offer?(data, session)
        ]

        {:ok, %{data | session_store: store}, Keyword.put(tls, :resumption, options)}
    end
  end

  defp authority_request(
         store,
         partition,
         %{operation: :lookup, identity: identity, context: partition},
         now,
         deadline
       ) do
    case ResumptionStore.lookup(store, partition, identity, now, deadline) do
      {:ok, session, lease, store} -> {{:ok, session, lease, now}, store}
      {:miss, store} -> {:miss, store}
    end
  end

  defp authority_request(
         store,
         partition,
         %{operation: :commit, session: %{context: partition} = session, lease: lease},
         now,
         _deadline
       ) do
    case ResumptionStore.commit(store, partition, session.identity, lease, now) do
      {:ok, store} -> {{:ok, :resumed}, store}
      {:miss, store} -> {:miss, store}
    end
  end

  defp authority_request(store, partition, %{operation: :store, session: session}, now, _deadline) do
    case ResumptionStore.store(store, partition, session, now) do
      {:ok, store} -> {:ok, store}
      {:error, _, store} -> {:miss, store}
    end
  end

  defp authority_request(store, _, _, _, _), do: {:miss, store}

  defp early_offer?(%{early_policy: nil}, _), do: false
  defp early_offer?(%{role: :server}, _), do: true

  defp early_offer?(_, %SSL.QUIC.Session{transport_parameters: wire}) do
    case TransportParameters.decode(wire) do
      {:ok, parameters} -> Quic.EarlyData.compatible(parameters.values, parameters.values) == :ok
      _ -> false
    end
  end

  defp early_offer?(_, _), do: false

  defp effective_streams(data) do
    opts = Keyword.get(data.opts, :streams, [])

    if data.early_policy,
      do: opts |> Quic.EarlyData.cap_streams() |> Keyword.put(:delivery, :manual),
      else: opts
  end

  defp materialize(tls, role, original, scid, retry_scid, stream_opts, datagram_opts, opts) do
    entries = [%{id: 0x0F, value: scid}]
    entries = if role == :server, do: [%{id: 0, value: original} | entries], else: entries
    entries = if retry_scid, do: [%{id: 0x10, value: retry_scid} | entries], else: entries
    {:ok, cid_limit} = Codec.encode_varint(8)
    entries = entries ++ [%{id: 0x0E, value: cid_limit}]

    reset_entries =
      if Keyword.get(opts, :reliable_reset, false), do: [%{id: 0x1D, value: <<>>}], else: []

    with {:ok, stream_entries} <- stream_transport_entries(stream_opts),
         {:ok, datagram_entries} <- datagram_transport_entries(datagram_opts),
         {:ok, idle_wire} <- idle_timeout_wire(Keyword.get(opts, :idle_timeout, 30_000)),
         {:ok, generated} <-
           TransportParameters.encode(
             entries ++
               stream_entries ++ datagram_entries ++ reset_entries ++ [%{id: 1, value: idle_wire}],
             role: role
           ),
         raw <- Keyword.get(tls, :transport_parameters, generated),
         {:ok, decoded} <- TransportParameters.decode(raw),
         {:ok, idle_timeout} <- local_idle_timeout(opts, decoded.values),
         :ok <-
           TransportParameters.validate(decoded,
             role: role,
             initial_source_connection_id: scid,
             retry_source_connection_id: retry_scid,
             original_destination_connection_id: if(role == :server, do: original)
           ) do
      {:ok, tls |> apply_profile(raw) |> Keyword.put(:transport_parameters, raw), idle_timeout}
    end
  end

  defp idle_timeout_wire(:infinity), do: Codec.encode_varint(0)

  defp idle_timeout_wire(timeout) when is_integer(timeout) and timeout > 0,
    do: Codec.encode_varint(timeout)

  defp idle_timeout_wire(_), do: {:error, :invalid_idle_timeout}

  defp local_idle_timeout(opts, values) do
    advertised = Map.get(values, :max_idle_timeout, 0)
    local = if advertised == 0, do: :infinity, else: advertised

    if Keyword.has_key?(opts, :idle_timeout) and opts[:idle_timeout] != local,
      do: {:error, :idle_timeout_transport_parameter_mismatch},
      else: {:ok, local}
  end

  defp datagram_transport_entries(opts) when is_list(opts) do
    max_frame = Keyword.get(opts, :max_frame_size, 0)
    max_items = Keyword.get(opts, :max_items, 64)
    max_bytes = Keyword.get(opts, :max_buffer_bytes, 65_536)

    if is_integer(max_frame) and max_frame in 0..65_527 and is_integer(max_items) and
         max_items in 1..1024 and is_integer(max_bytes) and max_bytes in 0..1_048_576 do
      if max_frame == 0 do
        {:ok, []}
      else
        {:ok, wire} = Quic.Codec.encode_varint(max_frame)
        {:ok, [%{id: 0x20, value: wire}]}
      end
    else
      {:error, :invalid_datagram_options}
    end
  end

  defp datagram_transport_entries(_), do: {:error, :invalid_datagram_options}

  defp stream_transport_entries(opts) do
    streams = Quic.Streams.new(:server, opts)

    values = [
      {0x04, streams.max_data},
      {0x05, streams.max_stream_data_bidi_local},
      {0x06, streams.max_stream_data_bidi_remote},
      {0x07, streams.max_stream_data_uni},
      {0x08, streams.max_streams_bidi},
      {0x09, streams.max_streams_uni}
    ]

    Enum.reduce_while(values, {:ok, []}, fn {id, value}, {:ok, acc} ->
      case Quic.Codec.encode_varint(value) do
        {:ok, encoded} -> {:cont, {:ok, acc ++ [%{id: id, value: encoded}]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp apply_profile(tls, generated) do
    case Keyword.get(tls, :profile) do
      profile when is_struct(profile, SSL.ClientHello.WireProfile) ->
        Keyword.put(tls, :profile, replace_profile_transport_parameters(profile, generated))

      _ ->
        tls
    end
  end

  defp profile_tls_options(tls, %{tls: _} = profile),
    do: Keyword.put(tls, :profile, profile.tls)

  defp profile_tls_options(tls, _), do: tls

  defp replace_profile_transport_parameters(profile, generated) do
    extensions =
      Enum.map(profile.extensions, fn
        {:raw, 57, _} -> {:raw, 57, generated}
        other -> other
      end)

    %{profile | extensions: extensions}
  end

  defp profile_packet_size(%{max_packet_size: size}) when is_integer(size), do: size
  defp profile_packet_size(_), do: 1_350

  defp deliver(data, entry, bytes, at) do
    deliver(data, entry, entry.remote, bytes, at)
  end

  defp deliver(data, entry, remote, bytes, at) do
    case Connection.deliver(entry.pid, entry.generation, bytes, at, %{
           local: data.ingress_local || data.local,
           remote: remote
         }) do
      :ok -> data
      {:error, reason} -> %{data | last_error: reason}
    end
  catch
    :exit, _ -> remove(data, entry.pid)
  end

  defp retire_extra_io(%{socket: socket}, socket), do: :ok

  defp retire_extra_io(io, _selected) do
    close_io(%{external: false, socket: io.socket})
  end

  defp remove(data, pid) do
    data = %{data | early_authority: Quic.EarlyData.release(data.early_authority, pid)}

    data =
      case data.migration do
        {^pid, _generation, _ref} ->
          Enum.each(data.ios, fn {_id, io} -> retire_extra_io(io, data.socket) end)

          %{data | migration: nil}

        _ ->
          data
      end

    case data.connections[pid] do
      %{monitor: monitor} -> Process.demonitor(monitor, [:flush])
      _ -> :ok
    end

    retired =
      data.routes
      |> Enum.filter(fn {_, target} -> target == pid end)
      |> Enum.map(fn {cid, _} -> {:cid, cid} end)
      |> Kernel.++(
        data.provisional
        |> Enum.filter(fn {_, target} -> target == pid end)
        |> Enum.map(fn {{remote, cid}, _} -> {:remote, remote, cid} end)
      )

    %{
      data
      | connections: Map.delete(data.connections, pid),
        accepts: Enum.reject(data.accepts, &(&1.id == pid)),
        routes: Map.reject(data.routes, fn {_, target} -> target == pid end),
        provisional: Map.reject(data.provisional, fn {_, target} -> target == pid end),
        retired: add_retired(data.retired, retired, data.retired_limit)
    }
  end

  defp retired?(data, remote, cid),
    do:
      Map.has_key?(data.retired, {:cid, cid}) or
        Map.has_key?(data.retired, {:remote, remote, cid})

  # Retired identifiers carry a monotonic stamp so that, once over the limit, the
  # oldest are evicted first and a just-retired CID keeps blocking replays.
  @doc false
  def add_retired(retired, keys, limit) do
    retired = Enum.reduce(keys, retired, &Map.put(&2, &1, :erlang.unique_integer([:monotonic])))
    excess = map_size(retired) - limit

    if excess <= 0 do
      retired
    else
      retired
      |> Enum.sort_by(fn {_key, stamp} -> stamp end)
      |> Enum.take(excess)
      |> Enum.reduce(retired, fn {key, _stamp}, acc -> Map.delete(acc, key) end)
    end
  end

  defp destination(<<first, _version::32, length, rest::binary>>)
       when Bitwise.band(first, 0x80) != 0 and length <= 20 and byte_size(rest) >= length,
       do: {:ok, binary_part(rest, 0, length)}

  defp destination(<<first, cid::binary-size(@cid_length), _::binary>>)
       when Bitwise.band(first, 0x80) == 0,
       do: {:ok, cid}

  defp destination(_), do: {:error, :malformed_header}

  defp endpoint_call(pid, request, opts) do
    ref = Keyword.get(opts, :ref, make_ref())
    timeout = Keyword.get(opts, :timeout, 5_000)
    bound = Keyword.get(opts, :deadline, timeout)
    deadline = absolute_deadline(bound)
    timeout = call_timeout(timeout, bound)

    try do
      GenServer.call(pid, {:endpoint_operation, ref, deadline, request}, timeout)
    catch
      :exit, {:timeout, _} -> {:unknown, ref}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {_reason, _call} -> {:unknown, ref}
    end
  end

  defp call_timeout(timeout, {:abs_ms, deadline}),
    do: max(0, min(timeout, deadline - System.monotonic_time(:millisecond)))

  # Legacy duration options retain their existing call wait semantics.
  defp call_timeout(timeout, _duration), do: timeout

  defp absolute_deadline({:abs_ms, deadline}) when is_integer(deadline), do: deadline
  defp absolute_deadline(duration), do: System.monotonic_time(:millisecond) + duration

  defp safe_call(pid, request, timeout) do
    try do
      GenServer.call(pid, request, timeout)
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {reason, _call} -> {:error, {:closed, reason}}
    end
  end

  defp record_operation(data, ref, signature, status, result) do
    operations =
      Map.put(data.operations, ref, %{
        signature: signature,
        status: status,
        result: result,
        sequence: data.operation_sequence
      })

    operations =
      if map_size(operations) > data.operation_limit do
        {oldest, _} = Enum.min_by(operations, fn {_, entry} -> entry.sequence end)
        Map.delete(operations, oldest)
      else
        operations
      end

    %{data | operations: operations, operation_sequence: data.operation_sequence + 1}
  end

  @impl true
  def terminate(_, data) do
    Enum.each(data.connections, fn {pid, _} -> Process.exit(pid, :shutdown) end)

    Enum.each(data.ios, fn {_id, io} ->
      if is_pid(io.socket), do: close_io(%{external: false, socket: io.socket})
    end)

    if data.external, do: close_io(data)
    :ok
  end

  defp open_io(opts, role) do
    case Keyword.get(opts, :io) do
      {:external, local, send_fun}
      when role == :server and is_tuple(local) and is_function(send_fun, 2) ->
        with {:ok, writer} <- ExternalWriter.start_link(owner: self(), send_fun: send_fun) do
          {:ok,
           %{
             socket: nil,
             monitor: nil,
             module: ExternalWriter,
             writer: writer,
             local: local,
             external: true
           }}
        end

      {:external, _local, _send_fun} ->
        {:error, :invalid_external_endpoint}

      nil ->
        with {:ok, socket} <-
               open_udp(opts, role) do
          {:ok,
           %{
             socket: socket,
             monitor: Process.monitor(socket),
             module: GenUDP,
             writer: socket,
             local: GenUDP.local(socket),
             external: false
           }}
        end
    end
  end

  defp enroll_cleanup(opts) do
    case Keyword.get(opts, :cleanup_birth) do
      nil -> :ok
      birth -> Quic.Cleanup.enroll(birth, self())
    end
  end

  defp reserve_connection(%{cleanup: nil}, _deadline), do: {:ok, nil}

  defp reserve_connection(data, deadline),
    do: Quic.Cleanup.reserve(data.cleanup, :connection, deadline)

  defp start_connection(opts, nil), do: Connection.start(opts)

  defp start_connection(opts, birth) do
    case Connection.start(Keyword.put(opts, :cleanup_birth, birth)) do
      {:ok, _} = result ->
        result

      {:error, _} = error ->
        Quic.Cleanup.no_birth(birth)
        error
    end
  end

  defp open_udp(opts, role) do
    io_opts = Keyword.take(opts, [:ip, :port]) ++ [owner: self(), role: role]

    case Keyword.get(opts, :cleanup) do
      nil ->
        GenUDP.open(io_opts)

      lease ->
        with {:ok, birth} <- Quic.Cleanup.reserve(lease, :io, Quic.Cleanup.deadline(opts)) do
          case GenUDP.open(
                 io_opts ++
                   [cleanup: lease, cleanup_birth: birth, deadline: Quic.Cleanup.deadline(opts)]
               ) do
            {:ok, _} = result ->
              result

            {:error, _} = error ->
              Quic.Cleanup.no_birth(birth)
              error
          end
        end
    end
  end

  defp close_io(%{external: true, io_writer: writer}) when is_pid(writer),
    do: ExternalWriter.close(writer)

  defp close_io(%{external: false, socket: socket}) when is_pid(socket) do
    # The independent observer may have already retired IO. A close reply is
    # only a request result; the cleanup receipt separately joins the actor/Port.
    GenUDP.close(socket)
  catch
    :exit, reason -> {:error, {:close_unconfirmed, reason}}
  end

  defp close_io(%{external: true, writer: writer}) when is_pid(writer),
    do: ExternalWriter.close(writer)

  defp close_io(_), do: :ok

  defp valid_item_limit?(value), do: is_integer(value) and value in 1..10_000

  defp connect_operation(data, ref, signature, request, deadline) do
    {:connect, remote} = request

    case if(map_size(data.connections) < data.max,
           do:
             admit(
               data,
               remote,
               :crypto.strong_rand_bytes(@cid_length),
               nil,
               nil,
               {:abs_ms, deadline}
             ),
           else: {:error, :connection_limit}
         ) do
      {:ok, next, entry} ->
        result = {:ok, handle(entry)}
        {:reply, result, record_operation(next, ref, signature, :admitted, result)}

      {:error, reason} ->
        result = {:error, reason}
        {:reply, result, record_operation(data, ref, signature, :rejected, result)}
    end
  end

  defp valid_retry_options?(retry, role, limit, ttl) do
    is_boolean(retry) and (not retry or role == :server) and
      valid_item_limit?(limit) and is_integer(ttl) and ttl in 1..60_000_000
  end
end
