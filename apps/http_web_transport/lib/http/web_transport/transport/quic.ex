defmodule HTTP.WebTransport.Transport.QUIC do
  @moduledoc """
  Draft-17 WebTransport backend over one exclusive `HTTP.HTTP3.ConnectionOwner`.

  The owner is the sole QUIC event consumer. It is started inert with a
  session-owned `Quic.Cleanup` scope, sends exactly one `webtransport-h3`
  extended CONNECT after validating the peer's draft-17 SETTINGS plus negotiated
  reliable reset (draft-11) and QUIC DATAGRAM, and never falls back to another
  protocol or connection. Stream and datagram deliveries carry owner credit
  receipts that the session returns with `acknowledge/2` once data leaves its
  bounded buffers. Operations run under absolute deadlines; a call whose
  outcome is unknown returns `{:error, {:indeterminate_operation, ref}}` and is
  never replayed. `close/2` returns `:ok` only after the native cleanup scope
  confirms that every QUIC resource of the connection is down.

  This adapter does not assert interoperability: `HTTP.WebTransport.Profile.supported?/0`
  stays false until independent draft-17 acceptance passes.
  """
  @behaviour HTTP.WebTransport.Transport

  alias HTTP.HTTP3.{ConnectionOwner, ConnectionSupervisor}
  alias HTTP.WebTransport.{CloseInfo, Options, Stats}

  @protocol "webtransport-h3"
  @default_operation_timeout 5_000
  @default_close_linger 500
  @cleanup_timeout 5_000

  defmodule Ref do
    @moduledoc false
    defstruct [:owner, :ref, :generation, :monitor, :lease, :timeout, :linger]
  end

  @impl true
  def connect(%URI{} = uri, %Options{} = options) do
    deadline = now() + options.connect_timeout

    with :ok <- validate_target(uri),
         {:ok, fields} <- connect_fields(uri, options),
         {:ok, handle, lease} <- Quic.Cleanup.new(owner: self()) do
      cleanup = %{handle: handle, lease: lease}

      case establish(uri, options, fields, cleanup, deadline) do
        {:ok, _ref, _info} = ok ->
          ok

        {:error, reason, owner} ->
          _ = shutdown(owner, lease)
          {:error, reason}
      end
    end
  end

  def connect(_uri, _options), do: {:error, :invalid_webtransport_options}

  defp establish(uri, options, fields, cleanup, deadline) do
    activation = make_ref()
    generation = make_ref()
    timeout = Keyword.get(options.quic, :operation_timeout, @default_operation_timeout)

    owner_opts =
      [
        host: uri.host,
        port: uri.port || 443,
        tls: options.ssl,
        exclusive?: true,
        max_streams: 1,
        webtransport: true,
        inert: true,
        creator: self(),
        activation: activation,
        cleanup: cleanup,
        opening_deadline_at: deadline,
        connect_timeout: options.connect_timeout,
        operation_timeout: timeout,
        reliable_reset: true,
        session_options: [
          webtransport: [
            max_bytes: min(options.max_buffered_bytes, 262_144),
            max_items: min(options.max_buffered_items, 128),
            max_streams: min(options.max_streams, 128)
          ]
        ]
      ] ++ Keyword.take(options.quic, [:profile, :idle_timeout, :datagram, :streams])

    case ConnectionSupervisor.start_connection(owner_opts) do
      {:ok, owner} ->
        monitor = Process.monitor(owner)

        session_ref = %Ref{
          owner: owner,
          generation: generation,
          monitor: monitor,
          lease: cleanup.lease,
          timeout: timeout,
          linger: Keyword.get(options.quic, :close_linger, @default_close_linger)
        }

        case open_session(session_ref, activation, fields, deadline) do
          {:ok, ref, headers} ->
            accepted(%{session_ref | ref: ref}, headers, options, deadline)

          {:error, reason} ->
            {:error, reason, owner}
        end

      {:error, reason} ->
        {:error, reason, nil}
    end
  end

  defp open_session(%Ref{owner: owner} = session_ref, activation, fields, deadline) do
    with :ok <- call(fn -> ConnectionOwner.activate(owner, activation) end),
         :ok <- owner_ready(session_ref, deadline),
         {:ok, ref} <-
           call(fn ->
             ConnectionOwner.open(owner, fields, :stream, self(), session_ref.generation,
               purpose: :extended_connect,
               protocol: @protocol,
               timeout: remaining(deadline),
               deadline_at: deadline,
               deadline: {:abs_ms, deadline}
             )
           end),
         {:ok, headers} <- await_response(session_ref, ref, deadline) do
      {:ok, ref, headers}
    end
  end

  defp owner_ready(session_ref, deadline) do
    case call(fn -> ConnectionOwner.await_ready(session_ref.owner, remaining(deadline)) end) do
      :ok -> :ok
      {:error, {:owner_down, reason}} -> {:error, {:http3_not_established, reason}}
      {:error, reason} -> {:error, {:http3_not_established, reason}}
    end
  end

  defp await_response(%Ref{owner: owner, generation: generation, monitor: monitor}, ref, deadline) do
    receive do
      {:http3, ^generation, ^ref, {:headers, status, headers}} when status in 200..299 ->
        {:ok, [{":status", Integer.to_string(status)} | headers]}

      {:http3, ^generation, ^ref, {:headers, status, _headers}} ->
        {:error, {:webtransport_rejected, status}}

      {:http3, ^generation, ^ref, {:informational, _status, _headers}} ->
        await_response(
          %Ref{owner: owner, generation: generation, monitor: monitor},
          ref,
          deadline
        )

      {:http3, ^generation, ^ref, {:error, reason}} ->
        {:error, reason}

      {:http3, ^generation, ^ref, :done} ->
        {:error, :webtransport_connect_closed}

      {:DOWN, ^monitor, :process, ^owner, reason} ->
        {:error, {:owner_down, reason}}
    after
      remaining(deadline) ->
        {:error, :connect_timeout}
    end
  end

  defp accepted(session_ref, headers, options, deadline) do
    with {:ok, info} <- owner_call(session_ref, :info, remaining(deadline)),
         {:ok, protocol} <- selected_protocol(headers, options.protocols) do
      {:ok, session_ref,
       %{
         protocol: protocol,
         reliability: "supports-unreliable",
         response_headers: tl(headers),
         max_datagram_size: info.max_datagram_payload,
         session_id: info.session_id
       }}
    else
      {:error, reason} -> {:error, reason, session_ref.owner}
    end
  end

  @impl true
  def close(%Ref{} = session_ref, %CloseInfo{} = info) do
    if Process.alive?(session_ref.owner) do
      code = if info.close_code in 0..0xFFFFFFFF, do: info.close_code, else: 0
      _ = owner_call(session_ref, {:close, code, info.reason}, session_ref.timeout)
      linger(session_ref, now() + session_ref.linger)
    end

    Process.demonitor(session_ref.monitor, [:flush])
    shutdown(session_ref.owner, session_ref.lease)
  end

  def close(_session_ref, _info), do: :ok

  @impl true
  def get_stats(_session_ref), do: {:ok, %Stats{}}

  @impl true
  def open_bidirectional_stream(session_ref, _options), do: open(session_ref, :bidi)

  @impl true
  def open_unidirectional_stream(session_ref, _options), do: open(session_ref, :uni)

  @impl true
  def send_datagram(session_ref, bytes, _options),
    do: owner_call(session_ref, {:datagram, bytes}, session_ref.timeout)

  @impl true
  def recv_stream(_stream_ref, _timeout), do: {:error, :push_delivery_only}

  @impl true
  def send_stream({__MODULE__, session_ref, key}, bytes, _options),
    do:
      owner_call(
        session_ref,
        {:send, key, IO.iodata_to_binary(bytes), false},
        session_ref.timeout
      )

  def send_stream(_stream_ref, _bytes, _options), do: {:error, :invalid_stream}

  @impl true
  def close_send_stream({__MODULE__, session_ref, key}),
    do: owner_call(session_ref, {:send, key, <<>>, true}, session_ref.timeout)

  def close_send_stream(_stream_ref), do: {:error, :invalid_stream}

  @impl true
  def abort_send_stream({__MODULE__, session_ref, key}, code),
    do: owner_call(session_ref, {:reset, key, code}, session_ref.timeout)

  def abort_send_stream(_stream_ref, _code), do: {:error, :invalid_stream}

  @impl true
  def cancel_receive_stream({__MODULE__, session_ref, key}, code),
    do: owner_call(session_ref, {:stop, key, code}, session_ref.timeout)

  def cancel_receive_stream(_stream_ref, _code), do: {:error, :invalid_stream}

  @doc "Returns owner delivery credit for a receipt carried by a session event."
  def acknowledge(%Ref{owner: owner, ref: ref}, receipt) when is_reference(receipt),
    do: ConnectionOwner.webtransport_ack(owner, ref, receipt)

  def acknowledge(_session_ref, _receipt), do: :ok

  @doc """
  Translates an owner message into session events, or `:ignore`.

  Data events carry a receipt; empty deliveries and datagrams are acknowledged
  here because their retained size is already bounded by the session.
  """
  def handle_message(
        %Ref{generation: generation, ref: ref} = session_ref,
        {:http3, generation, ref, event}
      ),
      do: {:ok, owner_event(session_ref, event)}

  def handle_message(
        %Ref{owner: owner, monitor: monitor} = session_ref,
        {:DOWN, monitor, :process, owner, reason}
      ),
      do: {:ok, [{:webtransport_failed, session_ref, {:owner_down, reason}}]}

  def handle_message(_session_ref, _message), do: :ignore

  defp owner_event(session_ref, {:wt, {:stream, key, kind, bytes, fin, receipt}}) do
    stream_ref = {__MODULE__, session_ref, key}
    if bytes == <<>>, do: acknowledge(session_ref, receipt)

    incoming(session_ref, stream_ref, key, kind) ++
      if(bytes == <<>>, do: [], else: [{:webtransport_stream_data, stream_ref, bytes, receipt}]) ++
      if fin, do: [{:webtransport_stream_fin, stream_ref}], else: []
  end

  defp owner_event(session_ref, {:wt, {:reset, key, code}}) do
    stream_ref = {__MODULE__, session_ref, key}

    incoming(session_ref, stream_ref, key, if(rem(key, 4) in [2, 3], do: :uni, else: :bidi)) ++
      [{:webtransport_stream_error, stream_ref, {:reset, code}}]
  end

  defp owner_event(session_ref, {:wt, {:stopped, key, code}}),
    do: [{:webtransport_send_stopped, {__MODULE__, session_ref, key}, code}]

  defp owner_event(session_ref, {:wt, {:datagram, payload, receipt}}) do
    acknowledge(session_ref, receipt)
    [{:webtransport_datagram, session_ref, payload}]
  end

  defp owner_event(session_ref, {:wt, {:close, code, reason}}),
    do: [{:webtransport_closed, session_ref, %CloseInfo{close_code: code, reason: reason}}]

  defp owner_event(session_ref, {:wt, :drain}), do: [{:webtransport_draining, session_ref}]

  defp owner_event(session_ref, :done),
    do: [{:webtransport_closed, session_ref, %CloseInfo{close_code: 0, reason: ""}}]

  defp owner_event(session_ref, {:error, reason}),
    do: [{:webtransport_failed, session_ref, reason}]

  defp owner_event(_session_ref, _event), do: []

  # Peer-initiated QUIC stream IDs have the low bit set; locally opened streams
  # are already known to the session.
  defp incoming(session_ref, stream_ref, key, kind) when rem(key, 2) == 1 do
    message =
      if kind == :bidi,
        do: :webtransport_incoming_bidi_stream,
        else: :webtransport_incoming_uni_stream

    [{message, session_ref, stream_ref}]
  end

  defp incoming(_session_ref, _stream_ref, _key, _kind), do: []

  defp open(session_ref, kind) do
    with {:ok, key} <- owner_call(session_ref, {:open, kind}, session_ref.timeout),
         do: {:ok, {__MODULE__, session_ref, key}}
  end

  defp owner_call(%Ref{owner: owner, ref: ref}, op, timeout) do
    operation = make_ref()

    try do
      ConnectionOwner.webtransport(owner, ref, op, timeout)
    catch
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {:normal, _} -> {:error, :closed}
      :exit, _ -> {:error, {:indeterminate_operation, operation}}
    end
  end

  defp owner_call(_session_ref, _op, _timeout), do: {:error, :invalid_session}

  # Gives the CLOSE_WEBTRANSPORT_SESSION capsule a bounded chance to reach the
  # peer before the exclusive connection is retired.
  defp linger(%Ref{generation: generation, ref: ref, owner: owner, monitor: monitor}, until) do
    receive do
      {:http3, ^generation, ^ref, :done} -> :ok
      {:http3, ^generation, ^ref, {:error, _}} -> :ok
      {:DOWN, ^monitor, :process, ^owner, _} -> :ok
    after
      max(until - now(), 0) -> :ok
    end
  end

  defp shutdown(owner, lease) do
    if is_pid(owner) do
      try do
        GenServer.stop(owner, :normal, @cleanup_timeout)
      catch
        :exit, _ -> Process.exit(owner, :kill)
      end
    end

    case Quic.Cleanup.retire(lease, {:abs_ms, now() + @cleanup_timeout}) do
      {:ok, %{cleanup: :confirmed}} -> :ok
      other -> {:error, {:cleanup_unconfirmed, other}}
    end
  end

  defp validate_target(%URI{scheme: "https", host: host, fragment: nil})
       when is_binary(host) and host != "",
       do: :ok

  defp validate_target(_uri), do: {:error, :invalid_webtransport_url}

  defp connect_fields(uri, options) do
    authority =
      if uri.port in [nil, 443], do: uri.host, else: "#{uri.host}:#{uri.port}"

    path = (uri.path || "/") <> if(uri.query, do: "?" <> uri.query, else: "")
    path = if String.starts_with?(path, "/"), do: path, else: "/" <> path

    headers =
      Enum.map(options.headers, fn {name, value} -> {String.downcase(name), value} end) ++
        available_protocols(options.protocols)

    {:ok,
     [
       {":method", "CONNECT"},
       {":scheme", "https"},
       {":authority", authority},
       {":path", path}
     ] ++ headers}
  end

  # Draft-17 application protocol negotiation uses Structured Field strings.
  defp available_protocols([]), do: []

  defp available_protocols(protocols),
    do: [{"wt-available-protocols", Enum.map_join(protocols, ", ", &sf_string/1)}]

  defp sf_string(value),
    do: "\"" <> String.replace(String.replace(value, "\\", "\\\\"), "\"", "\\\"") <> "\""

  defp selected_protocol(headers, offered) do
    case List.keyfind(headers, "wt-protocol", 0) do
      nil ->
        {:ok, ""}

      {_, value} ->
        selected = parse_sf_string(String.trim(value))

        if selected in offered,
          do: {:ok, selected},
          else: {:error, {:unexpected_selected_protocol, value}}
    end
  end

  defp parse_sf_string("\"" <> rest) do
    if String.ends_with?(rest, "\"") do
      rest
      |> String.slice(0..-2//1)
      |> String.replace("\\\"", "\"")
      |> String.replace("\\\\", "\\")
    else
      nil
    end
  end

  defp parse_sf_string(_value), do: nil

  defp call(fun) do
    fun.()
  catch
    :exit, {reason, _} -> {:error, {:owner_down, reason}}
  end

  defp remaining(deadline), do: max(deadline - now(), 1)

  defp now, do: System.monotonic_time(:millisecond)
end
