defmodule Quic.Endpoint do
  @moduledoc """
  Bounded standalone UDP endpoint with persistent connection routing.

  A server owns one shared socket; connections only borrow its send capability.
  Reception has one outstanding credit and is rearmed after synchronous routing.
  Current paths remain bound to the original peer address; migration is not yet
  exposed. This internal endpoint is not an independent interoperability claim.
  """
  use GenServer
  alias Quic.{Codec, Connection, TransportParameters, Retry, Protection}
  alias Quic.IO.GenUDP
  alias Quic.IO.ExternalWriter

  @cid_length 8
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)
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
      with {:ok, io} <- open_io(opts, role) do
        data = %{
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
      end
    else
      {:stop, :invalid_endpoint_options}
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

      match?({:connect, _}, request) and data.role == :client ->
        connect_operation(data, ref, signature, request)

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
         last_error: data.last_error
       }, data}

  @impl true
  def handle_info({:quic_udp, generation, credit, remote, bytes, at}, data) do
    next = route(data, remote, bytes, at)

    case GenUDP.consumed(data.socket, generation, credit) do
      :ok -> {:noreply, next}
      {:error, reason} -> {:stop, {:socket_receive, reason}, next}
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

  def handle_info({:DOWN, monitor, :process, pid, _reason}, data) do
    if monitor in [data.monitor, data.acceptor_monitor] do
      {:stop, :normal, data}
    else
      case data.connections[pid] do
        %{monitor: ^monitor} -> {:noreply, remove(data, pid)}
        _ -> {:noreply, data}
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

  defp route(data, remote, bytes, at) do
    case destination(bytes) do
      {:ok, dcid} ->
        if retired?(data, remote, dcid) do
          data
        else
          pid = Map.get(data.routes, dcid) || Map.get(data.provisional, {remote, dcid})

          case data.connections[pid] do
            %{remote: ^remote} = entry -> deliver(data, entry, bytes, at)
            nil -> maybe_admit(data, remote, bytes, at)
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

  defp admit(data, remote, original_dcid, peer_scid, retry_scid \\ nil) do
    scid = :crypto.strong_rand_bytes(@cid_length)
    dcid = peer_scid || original_dcid

    with false <- Map.has_key?(data.routes, scid),
         profile <- Keyword.get(data.opts, :profile),
         tls_opts <- profile_tls_options(Keyword.get(data.opts, :tls, []), profile),
         {:ok, tls} <-
           materialize(
             tls_opts,
             data.role,
             original_dcid,
             scid,
             retry_scid,
             Keyword.get(data.opts, :streams, []),
             Keyword.get(data.opts, :datagram, [])
           ),
         {:ok, local_parameters} <- TransportParameters.decode(tls[:transport_parameters]),
         opts <- [
           role: data.role,
           address_validated: retry_scid != nil,
           owner: self(),
           io: {data.io_module, data.io_writer},
           remote: remote,
           local: data.local,
           public: Keyword.get(data.opts, :public, false),
           event_limit: Keyword.get(data.opts, :event_limit, 128),
           operation_limit: Keyword.get(data.opts, :operation_limit, 256),
           datagram: Keyword.get(data.opts, :datagram, []),
           handshake_timeout: Keyword.get(data.opts, :handshake_timeout, 10_000),
           idle_timeout: Keyword.get(data.opts, :idle_timeout, 30_000),
           closing_timeout: Keyword.get(data.opts, :closing_timeout),
           draining_timeout: Keyword.get(data.opts, :draining_timeout),
           scheduler:
             [
               dcid: dcid,
               scid: scid,
               original_dcid: original_dcid,
               initial_key_dcid: retry_scid || original_dcid,
               retry_scid: retry_scid,
               streams: Keyword.get(data.opts, :streams, []),
               max_datagram_frame_size:
                 Map.get(local_parameters.values, :max_datagram_frame_size, 0),
               max_packet_size: profile_packet_size(profile)
             ] ++ tls
         ],
         {:ok, pid} <- Connection.start(opts),
         {:ok, generation} <- generation(pid) do
      entry = %{pid: pid, remote: remote, generation: generation, monitor: Process.monitor(pid)}

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

  defp materialize(tls, role, original, scid, retry_scid, stream_opts, datagram_opts) do
    entries = [%{id: 0x0F, value: scid}]
    entries = if role == :server, do: [%{id: 0, value: original} | entries], else: entries
    entries = if retry_scid, do: [%{id: 0x10, value: retry_scid} | entries], else: entries

    with {:ok, stream_entries} <- stream_transport_entries(stream_opts),
         {:ok, datagram_entries} <- datagram_transport_entries(datagram_opts),
         {:ok, generated} <-
           TransportParameters.encode(entries ++ stream_entries ++ datagram_entries, role: role),
         tls <- apply_profile(tls, generated),
         raw <- Keyword.get(tls, :transport_parameters, generated),
         {:ok, decoded} <- TransportParameters.decode(raw),
         :ok <-
           TransportParameters.validate(decoded,
             role: role,
             initial_source_connection_id: scid,
             retry_source_connection_id: retry_scid,
             original_destination_connection_id: if(role == :server, do: original)
           ) do
      {:ok, Keyword.put(tls, :transport_parameters, raw)}
    end
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
    case Connection.deliver(entry.pid, entry.generation, bytes, at) do
      :ok -> data
      {:error, reason} -> %{data | last_error: reason}
    end
  catch
    :exit, _ -> remove(data, entry.pid)
  end

  defp remove(data, pid) do
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

  defp add_retired(retired, keys, limit) do
    retired = Enum.reduce(keys, retired, &Map.put(&2, &1, true))

    if map_size(retired) <= limit do
      retired
    else
      retired
      |> Map.keys()
      |> Enum.take(map_size(retired) - limit)
      |> Enum.reduce(retired, &Map.delete(&2, &1))
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
    deadline = System.monotonic_time(:millisecond) + Keyword.get(opts, :deadline, timeout)

    try do
      GenServer.call(pid, {:endpoint_operation, ref, deadline, request}, timeout)
    catch
      :exit, {:timeout, _} -> {:unknown, ref}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {_reason, _call} -> {:unknown, ref}
    end
  end

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
    close_io(data)
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
               GenUDP.open(Keyword.take(opts, [:ip, :port]) ++ [owner: self(), role: role]) do
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

  defp close_io(%{external: true, io_writer: writer}) when is_pid(writer),
    do: ExternalWriter.close(writer)

  defp close_io(%{external: false, socket: socket}) when is_pid(socket),
    do: GenUDP.close(socket)

  defp close_io(%{external: true, writer: writer}) when is_pid(writer),
    do: ExternalWriter.close(writer)

  defp close_io(_), do: :ok

  defp valid_item_limit?(value), do: is_integer(value) and value in 1..10_000

  defp connect_operation(data, ref, signature, request) do
    {:connect, remote} = request

    case if(map_size(data.connections) < data.max,
           do: admit(data, remote, :crypto.strong_rand_bytes(@cid_length), nil),
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
