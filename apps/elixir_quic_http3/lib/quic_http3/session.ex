defmodule QuicHttp3.Session do
  @moduledoc """
  Caller-driven HTTP/3 session with resumable QUIC admission.

  Mutating failures return the advanced session. Call `resume/1` to reconcile an
  unknown operation, or retry a definitely blocked operation after credit changes.
  Unknown operations are never replayed, including after result-cache eviction.
  Definitely credit-blocked stream writes are split into smaller ordered
  fragments under the original deadline; `max_frame` remains an upper bound.
  Native query calls and DNS retain their transport timeout bounds; the session
  deadline is an admission/reconciliation budget, not a shorter wall-clock bound.

  QPACK: `:qpack_max_table_capacity` (default 4096) and `:qpack_blocked_streams`
  (default 16) are advertised in SETTINGS. A nonzero capacity opens local QPACK
  encoder and decoder streams, applies peer encoder instructions to a bounded
  dynamic table, holds blocked sections without reading further from their
  streams, and sends Section Acknowledgment, Stream Cancellation and Insert
  Count Increment through ordinary stream-write admission. `0`/`0` keeps the
  static/literal profile without QPACK streams. The local encoder is always
  static/literal.

  WebTransport: `webtransport: true` (or router limits as a keyword list)
  advertises the draft-17 client SETTINGS and admits exactly one
  `webtransport-h3` extended CONNECT after the peer's draft-17 SETTINGS and the
  connection's negotiated reliable reset and QUIC DATAGRAM support are
  confirmed. Peer WT streams and datagrams are associated through
  `QuicHttp3.WebTransportRouter`; deliveries are `{:wt, connect_ref, event}`
  poll events whose credit is released by `webtransport_acknowledge/2`.

  Early data (beta): before the handshake completes, `request/4` with
  `early_data: remembered_settings` admits a GET, HEAD or OPTIONS request
  without a body as replayable QUIC 0-RTT stream operations, provided the
  connection offered 0-RTT. `remembered_settings` are the peer SETTINGS the
  caller remembered for the resumption partition; the request must fit their
  `SETTINGS_MAX_FIELD_SECTION_SIZE`. Control and QPACK streams are opened only
  after the handshake. When `open/1` finds 0-RTT rejected, every early request
  is re-sent once on a fresh stream under the same request reference. When
  0-RTT was accepted, a peer SETTINGS frame that omits or reduces a remembered
  non-default value this client understands is an `H3_SETTINGS_ERROR`
  connection error (RFC 9114 Section 7.2.4.2). At most eight requests are
  admitted early per connection.
  """

  alias HTTP.H3.{Capsule, Datagram}
  alias HTTP.H3.WebTransport.Draft17
  alias QuicHttp3.{Connect, Control, Frame, Qpack, Response, Stream, Varint}
  alias QuicHttp3.Transport.Quic, as: QuicTransport
  alias QuicHttp3.Transport.Quic.Stream, as: TransportStream
  alias QuicHttp3.WebTransportRouter, as: Router

  defstruct transport: QuicTransport,
            connection: nil,
            control: nil,
            control_stream: nil,
            peer_streams: %{},
            requests: %{},
            next_request: 1,
            next_stream_id: 0,
            max_fields: 128,
            max_encoded_headers: 65_536,
            max_header_bytes: 65_536,
            max_retained_bytes: 262_144,
            qpack_streams: %{},
            qpack_max_table_capacity: 4_096,
            qpack_blocked_streams: 16,
            qpack: nil,
            qpack_encoder_stream: nil,
            qpack_decoder_stream: nil,
            qpack_known: 0,
            qpack_blocked: [],
            qpack_out: <<>>,
            continuations: %{},
            max_frame: 16_384,
            timeout: 5_000,
            deadline: nil,
            cleanup: nil,
            pending: nil,
            work: nil,
            runnable: [],
            retired: MapSet.new(),
            aborted_operation: nil,
            wt: nil,
            early: nil,
            open?: false

  defmodule Continuation do
    @moduledoc false
    @enforce_keys [:id, :connection, :work, :pending, :request_ref]
    defstruct [:id, :connection, :work, :pending, :request_ref]
  end

  @type t :: %__MODULE__{}
  @type failure :: {:error, t(), term()} | {:blocked, t(), term()} | {:unknown, t(), reference()}

  def new(opts \\ [])

  def new(opts) when is_list(opts) do
    transport = Keyword.get(opts, :transport, QuicTransport)
    max_frame = Keyword.get(opts, :max_frame, 16_384)
    timeout = Keyword.get(opts, :timeout, 5_000)
    deadline = Keyword.get(opts, :deadline)
    cleanup = Keyword.get(opts, :cleanup)

    if is_atom(transport) and is_integer(max_frame) and max_frame in 1..16_384 and
         is_integer(timeout) and timeout > 0 and valid_deadline?(deadline) do
      limits =
        Keyword.take(opts, [
          :max_fields,
          :max_encoded_headers,
          :max_header_bytes,
          :max_retained_bytes,
          :qpack_max_table_capacity,
          :qpack_blocked_streams
        ])

      session =
        struct!(
          __MODULE__,
          [
            transport: transport,
            max_frame: max_frame,
            timeout: timeout,
            deadline: deadline,
            cleanup: cleanup
          ] ++ limits
        )

      with :ok <- validate_cleanup(cleanup, transport),
           {:ok, wt} <- webtransport_state(Keyword.get(opts, :webtransport)) do
        if valid_limits?(session),
          do: {:ok, %{session | wt: wt}},
          else: {:error, :invalid_session_options}
      end
    else
      {:error, :invalid_session_options}
    end
  end

  def new(_), do: {:error, :invalid_session_options}

  defp webtransport_state(value) when value in [nil, false], do: {:ok, nil}
  defp webtransport_state(true), do: webtransport_state([])

  defp webtransport_state(opts) when is_list(opts) do
    case Router.new(Keyword.take(opts, [:max_bytes, :max_items, :max_streams])) do
      {:ok, router} ->
        {:ok,
         %{
           router: router,
           connect: nil,
           streams: %{},
           capsule: Capsule.new(),
           datagram_max: 0
         }}

      {:error, _} ->
        {:error, :invalid_session_options}
    end
  end

  defp webtransport_state(_), do: {:error, :invalid_session_options}

  defp valid_deadline?(nil), do: true
  defp valid_deadline?({:abs_ms, deadline}), do: is_integer(deadline)
  defp valid_deadline?(_), do: false

  defp validate_cleanup(nil, _), do: :ok

  defp validate_cleanup(cleanup, transport) do
    with {:ok, _descriptor} <- Quic.Cleanup.descriptor(cleanup) do
      if transport == QuicTransport,
        do: :ok,
        else: {:error, :cleanup_requires_quic_transport}
    end
  end

  def connect(session, remote, port, opts) do
    if session.connection == nil do
      begin(session, :connect, [{:connect, remote, port, opts}], opts)
    else
      {:error, session, :already_connected}
    end
  end

  def ready(%__MODULE__{connection: nil}), do: {:error, :not_connected}

  def ready(session) do
    if session.deadline != nil and now() >= elem(session.deadline, 1),
      do: {:error, :deadline_expired},
      else: session.transport.ready(session.connection, session.timeout)
  end

  def open(%__MODULE__{connection: nil} = session), do: {:error, session, :not_connected}
  def open(%__MODULE__{open?: true} = session), do: {:error, session, :already_open}

  def open(session) do
    if session.pending do
      {:error, session, :operation_pending}
    else
      case ready(session) do
        :ready ->
          capacity = session.qpack_max_table_capacity

          wt_settings = if session.wt, do: Draft17.client_settings(), else: []

          {:ok, control} =
            Control.new(
              :client,
              [
                {1, capacity},
                {6, session.max_header_bytes},
                {7, session.qpack_blocked_streams}
              ] ++ wt_settings
            )

          {qpack, steps} =
            if capacity > 0,
              do:
                {Qpack.new(max_capacity: capacity),
                 [:open_control, {:open_qpack, :qpack_encoder}, {:open_qpack, :qpack_decoder}]},
              else: {nil, [:open_control]}

          {session, resend} = early_disposition(%{session | control: control, qpack: qpack})
          begin(session, :open, steps ++ resend, [])

        :pending ->
          {:blocked, session, :not_ready}

        {:error, reason} ->
          {:error, session, reason}
      end
    end
  end

  def request(%__MODULE__{open?: false} = session, fields, body, opts) do
    case Keyword.get(opts, :early_data) do
      remembered when is_list(remembered) ->
        early_request(session, fields, body, opts, remembered)

      _ ->
        {:error, session, :not_open}
    end
  end

  def request(session, fields, body, opts)
      when is_list(fields) and (is_binary(body) or body == :stream) do
    with :ok <- request_admission(session),
         false <- List.keymember?(fields, ":protocol", 0),
         :ok <- outgoing_fields(session, fields),
         {:ok, headers} <- Qpack.encode_header_block(fields, opts),
         :ok <- encoded_headers(session, headers),
         {:ok, header_frame} <- Frame.encode(:headers, headers) do
      ref = make_ref()

      method =
        Enum.find_value(fields, "GET", fn {name, value} -> if name == ":method", do: value end)

      begin(session, {:request, ref}, [{:open_request, ref, header_frame, body, method}], opts)
    else
      true -> {:error, session, :protocol_requires_extended_connect}
      {:error, reason} -> {:error, session, reason}
    end
  end

  @early_methods ~w(GET HEAD OPTIONS)
  @max_early_requests 8
  # Settings whose remembered non-default values bind an accepted 0-RTT
  # connection: QPACK capacity, field section size, QPACK blocked streams,
  # extended CONNECT and HTTP Datagrams.
  @remembered_settings [{1, 0}, {6, nil}, {7, 0}, {8, 0}, {0x33, 0}]

  defp early_request(session, fields, body, opts, remembered) do
    method =
      Enum.find_value(fields, "GET", fn {name, value} -> if name == ":method", do: value end)

    early =
      session.early || %{status: :pending, remembered: [], requests: %{}, accepted: MapSet.new()}

    cond do
      session.connection == nil ->
        {:error, session, :not_connected}

      method not in @early_methods or body != <<>> ->
        {:error, session, :early_data_unsafe_request}

      early.status != :pending ->
        {:error, session, :early_data_unavailable}

      map_size(early.requests) >= @max_early_requests ->
        {:error, session, :early_data_capacity}

      not valid_remembered?(remembered) ->
        {:error, session, :invalid_remembered_settings}

      session.transport.ready(session.connection, session.timeout) != :pending ->
        {:error, session, :early_data_unavailable}

      true ->
        admit_early(%{session | early: %{early | remembered: remembered}}, fields, method, opts)
    end
  end

  defp admit_early(session, fields, method, opts) do
    with :ok <- request_admission(session),
         false <- List.keymember?(fields, ":protocol", 0),
         :ok <- outgoing_fields(session, fields),
         {:ok, headers} <- Qpack.encode_header_block(fields, []),
         :ok <- encoded_headers(session, headers),
         {:ok, header_frame} <- Frame.encode(:headers, headers) do
      ref = make_ref()

      begin(
        session,
        {:request, ref},
        [{:open_request, ref, header_frame, <<>>, method}],
        Keyword.put(opts, :early_work, true)
      )
    else
      true -> {:error, session, :protocol_requires_extended_connect}
      {:error, reason} -> {:error, session, reason}
    end
  end

  defp valid_remembered?(settings) do
    length(settings) <= 32 and
      Enum.all?(
        settings,
        &match?(
          {id, value} when is_integer(id) and id >= 0 and is_integer(value) and value >= 0,
          &1
        )
      )
  end

  @doc "Whether the connection currently offers QUIC 0-RTT for early requests."
  def early_offered?(%__MODULE__{connection: nil}), do: false
  def early_offered?(%__MODULE__{pending: pending}) when not is_nil(pending), do: false

  def early_offered?(session) do
    (session.early == nil or session.early.status == :pending) and
      match?(
        {:ok, %{resumption: %{early_data: :pending}}},
        session.transport.info(session.connection)
      )
  catch
    _, _ -> false
  end

  @doc "Whether `ref` was carried in QUIC 0-RTT data that the server accepted."
  def early_data?(%__MODULE__{early: %{accepted: accepted}}, ref),
    do: MapSet.member?(accepted, ref)

  def early_data?(_session, _ref), do: false

  @doc "Whether the established connection resumed a TLS session."
  def resumed?(%__MODULE__{connection: nil}), do: false

  def resumed?(session) do
    match?({:ok, %{resumption: %{resumed: true}}}, session.transport.info(session.connection))
  catch
    _, _ -> false
  end

  # Resolves 0-RTT disposition at readiness: accepted requests keep their
  # streams; otherwise each early request is re-sent once after the handshake.
  defp early_disposition(%{early: nil} = session), do: {session, []}

  defp early_disposition(%{early: %{requests: requests}} = session) when map_size(requests) == 0,
    do: {%{session | early: %{session.early | status: :not_offered}}, []}

  defp early_disposition(%{early: early} = session) do
    status =
      case session.transport.info(session.connection) do
        {:ok, %{resumption: %{early_data: :accepted}}} -> :accepted
        _ -> :rejected
      end

    if status == :accepted do
      accepted = MapSet.new(Map.keys(early.requests))
      {%{session | early: %{early | status: :accepted, requests: %{}, accepted: accepted}}, []}
    else
      refs = Map.keys(early.requests)
      stale = for ref <- refs, request = session.requests[ref], do: request.stream

      steps =
        for {ref, {frame, method, _order}} <-
              Enum.sort_by(early.requests, fn {_ref, {_, _, order}} -> order end),
            do: {:open_request, ref, frame, <<>>, method}

      next = %{
        session
        | early: %{early | status: :rejected, requests: %{}},
          requests: Map.drop(session.requests, refs),
          runnable: Enum.reject(session.runnable, &(&1 in stale)),
          qpack_blocked: session.qpack_blocked -- refs
      }

      {next, steps}
    end
  end

  defp check_remembered_settings(%{early: %{status: :accepted, remembered: old}}, events) do
    case List.keyfind(events, :settings, 0) do
      {:settings, fresh} ->
        if Enum.any?(@remembered_settings, &reduced_setting?(&1, old, fresh)),
          do: protocol_error(0x109, :remembered_settings_reduced),
          else: :ok

      nil ->
        :ok
    end
  end

  defp check_remembered_settings(_session, _events), do: :ok

  # A remembered non-default value must be repeated and must not shrink.
  defp reduced_setting?({id, default}, old, fresh) do
    case {List.keyfind(old, id, 0), List.keyfind(fresh, id, 0)} do
      {{^id, ^default}, _} -> false
      {nil, _} -> false
      {{^id, _value}, nil} -> true
      {{^id, value}, {^id, current}} -> current < value
    end
  end

  @doc "Opens an explicitly negotiated extended CONNECT without closing its sending direction."
  def extended_connect(session, protocol, fields, opts \\ []) do
    with true <- session.open?,
         :ok <- connect_deadline(session, opts),
         :ok <- request_admission(session),
         :ready <- Connect.ready(session.control),
         {:ok, session} <- extension_requirements(session, protocol),
         {:ok, fields} <- Connect.fields(protocol, fields),
         :ok <- outgoing_fields(session, fields),
         {:ok, block} <- Qpack.encode_header_block(fields, opts),
         :ok <- encoded_headers(session, block),
         {:ok, frame} <- Frame.encode(:headers, block) do
      ref = make_ref()

      begin(
        session,
        {:request, ref},
        [{:open_request, ref, frame, :stream, {:extended_connect, protocol}}],
        opts
      )
    else
      false -> {:error, session, :not_open}
      :pending -> {:blocked, session, :peer_settings_pending}
      {:error, reason} -> {:error, session, reason}
    end
  end

  defp connect_deadline(session, opts) do
    deadline = Keyword.get(opts, :deadline, session.deadline)

    cond do
      not valid_deadline?(deadline) -> {:error, :invalid_operation_options}
      deadline != nil and now() >= elem(deadline, 1) -> {:error, :deadline_expired}
      true -> :ok
    end
  end

  # Draft-17 admission: no profile bytes are sent unless the peer advertised the
  # draft-17 SETTINGS and this connection negotiated reliable reset draft-11
  # plus QUIC DATAGRAM. One session per connection; no fallback is attempted.
  defp extension_requirements(%{wt: nil}, "webtransport-h3"),
    do: {:error, :webtransport_not_enabled}

  defp extension_requirements(%{wt: %{connect: connect}}, "webtransport-h3")
       when connect != nil,
       do: {:error, :webtransport_session_capacity}

  defp extension_requirements(session, "webtransport-h3") do
    with :ok <- Draft17.validate_server_settings(session.control.peer_settings),
         {:ok, info} <- session.transport.info(session.connection),
         {:ok, max} <- webtransport_transport(info) do
      {:ok, put_in(session.wt.datagram_max, max)}
    end
  end

  defp extension_requirements(session, _), do: {:ok, session}

  defp webtransport_transport(%{
         reliable_reset: %{draft: 11, local: true, peer: true, negotiated: true},
         datagram: %{send_max_bytes: max}
       })
       when is_integer(max) and max > 0,
       do: {:ok, max}

  defp webtransport_transport(%{reliable_reset: %{draft: 11, negotiated: true}}),
    do: {:error, :quic_datagram_not_negotiated}

  defp webtransport_transport(_), do: {:error, :reliable_reset_not_negotiated}

  @doc "Returns the accepted WT session identity and maximum DATAGRAM payload."
  def webtransport_info(%{wt: %{connect: ref, router: %{session_id: id}} = wt})
      when ref != nil do
    overhead = byte_size(Varint.encode!(div(id, 4)))

    {:ok,
     %{
       connect: ref,
       session_id: id,
       phase: wt.router.phase,
       max_datagram_payload: max(wt.datagram_max - overhead, 0)
     }}
  end

  def webtransport_info(_), do: {:error, :no_webtransport_session}

  @doc "Opens a session-associated WT stream; returns its QUIC stream ID as key."
  def webtransport_open(session, kind, opts \\ []) when kind in [:bidi, :uni] do
    with :ok <- wt_accepted(session),
         :ok <- request_admission(session) do
      begin(session, {:wt_open, nil}, [{:open_wt, kind}], opts)
    else
      {:error, reason} -> {:error, session, reason}
    end
  end

  @doc "Writes raw WT stream bytes; FIN closes the send side."
  def webtransport_send(session, key, bytes, fin, opts \\ [])
      when is_binary(bytes) and is_boolean(fin) do
    with :ok <- wt_accepted(session),
         {:ok, %{send: :open, stream: stream}} <- wt_entry(session, key) do
      begin(session, :wt_send, wt_send_steps(stream, bytes, fin, session.max_frame), opts)
    else
      {:ok, _} -> {:error, session, :send_closed}
      {:error, reason} -> {:error, session, reason}
    end
  end

  defp wt_send_steps(stream, <<>>, true, _max), do: [{:send, stream, <<>>, true}]
  defp wt_send_steps(_stream, <<>>, false, _max), do: []
  defp wt_send_steps(stream, bytes, fin, max), do: chunks(stream, bytes, fin, max)

  @doc "Resets the send side with RESET_STREAM_AT, reliably delivering the WT prefix."
  def webtransport_reset(session, key, code, opts \\ []) do
    with {:ok, %{send: :open} = entry} <- wt_entry(session, key),
         {:ok, wire} <- Draft17.application_error(code) do
      begin(session, :wt_reset, [{:reset_at, entry.stream, wire, entry.prefix}], opts)
    else
      {:ok, _} -> {:error, session, :send_closed}
      {:error, reason} -> {:error, session, reason}
    end
  end

  @doc "Aborts the receive side with STOP_SENDING carrying a mapped application code."
  def webtransport_stop(session, key, code, opts \\ []) do
    with {:ok, %{recv: :open} = entry} <- wt_entry(session, key),
         {:ok, wire} <- Draft17.application_error(code) do
      begin(session, :wt_stop, [{:stop_code, entry.stream, wire}], opts)
    else
      {:ok, _} -> {:error, session, :receive_closed}
      {:error, reason} -> {:error, session, reason}
    end
  end

  @doc "Sends one HTTP DATAGRAM associated with the accepted WT session."
  def webtransport_datagram(session, payload, opts \\ []) when is_binary(payload) do
    with :ok <- wt_accepted(session),
         {:ok, bytes} <-
           Datagram.encode(session.wt.router.session_id, payload, session.wt.datagram_max) do
      begin(session, :wt_datagram, [{:datagram, bytes}], opts)
    else
      {:error, reason} -> {:error, session, reason}
    end
  end

  @doc "Sends CLOSE_WEBTRANSPORT_SESSION and FIN on the CONNECT stream."
  def webtransport_close(session, code, reason, opts \\ []) do
    with %{connect: ref} when ref != nil <- session.wt || {:error, :no_webtransport_session},
         {:ok, capsule} <- Draft17.close_capsule(code, reason) do
      {:ok, router, _actions} = Router.close(session.wt.router, session.wt.router.session_id)
      send_data(put_in(session.wt.router, router), ref, capsule, true, opts)
    else
      %{} -> {:error, session, :no_webtransport_session}
      {:error, reason} -> {:error, session, reason}
    end
  end

  @doc "Releases delivery credit retained for a WT event receipt."
  def webtransport_acknowledge(%{wt: %{router: router}} = session, receipt) do
    with {:ok, router} <- Router.acknowledge(router, receipt),
         do: {:ok, put_in(session.wt.router, router)}
  end

  def webtransport_acknowledge(_session, _receipt), do: {:error, :unknown_receipt}

  defp wt_accepted(%{wt: %{router: %{phase: :accepted}}}), do: :ok
  defp wt_accepted(_), do: {:error, :webtransport_not_accepted}

  defp wt_entry(%{wt: %{streams: streams}}, key) do
    case Map.fetch(streams, key) do
      {:ok, entry} -> {:ok, entry}
      :error -> {:error, :unknown_stream}
    end
  end

  defp wt_entry(_, _), do: {:error, :no_webtransport_session}

  def send_data(session, ref, bytes, fin, opts)
      when is_binary(bytes) and byte_size(bytes) <= 16_384 and is_boolean(fin) do
    case Map.fetch(session.requests, ref) do
      {:ok, %{purpose: {:extended_connect, _}, decoder: %{status: status}}}
      when status == nil or status < 200 or status > 299 ->
        {:error, session, :tunnel_not_accepted}

      {:ok, %{upload: :open, stream: stream}} ->
        begin(session, :send_data, data_steps(stream, bytes, fin, session.max_frame), opts)

      {:ok, _request} ->
        {:error, session, :upload_closed}

      :error ->
        {:error, session, :unknown_request}
    end
  end

  def send_data(session, _ref, _bytes, _fin, _opts), do: {:error, session, :invalid_upload_chunk}

  @doc "Sends ordered request trailing HEADERS with FIN through resumable admission."
  def send_trailers(session, ref, fields, opts) do
    case Map.fetch(session.requests, ref) do
      {:ok, %{purpose: {:extended_connect, _}}} ->
        {:error, session, :tunnel_trailers_forbidden}

      {:ok, %{upload: :open, stream: stream}} ->
        with {:ok, trailers} <- HTTP.Trailers.validate(fields),
             fields =
               Enum.map(trailers.headers, fn {name, value} -> {String.downcase(name), value} end),
             :ok <- outgoing_fields(session, fields),
             {:ok, block} <- Qpack.encode_header_block(fields, opts),
             :ok <- encoded_headers(session, block),
             {:ok, frame} <- Frame.encode(:headers, block) do
          begin(session, :send_trailers, chunks(stream, frame, true, session.max_frame), opts)
        else
          {:error, reason} -> {:error, session, reason}
        end

      {:ok, _request} ->
        {:error, session, :upload_closed}

      :error ->
        {:error, session, :unknown_request}
    end
  end

  def suspend_blocked(%{pending: %{status: :blocked}} = session) do
    if map_size(session.continuations) < 128 do
      id = make_ref()
      ref = work_request_ref(session)

      token = %Continuation{
        id: id,
        connection: session.connection,
        work: session.work,
        pending: session.pending,
        request_ref: ref
      }

      {:ok,
       %{
         session
         | work: nil,
           pending: nil,
           continuations: Map.put(session.continuations, id, ref)
       }, token}
    else
      {:error, session, :continuation_limit}
    end
  end

  def suspend_blocked(session), do: {:error, session, :operation_not_definitely_blocked}

  def resume(%{pending: pending} = session, _continuation) when not is_nil(pending),
    do: {:error, session, :operation_pending}

  def resume(session, %Continuation{} = continuation) do
    if Map.has_key?(session.continuations, continuation.id) and
         continuation.connection == session.connection and continuation.pending.status == :blocked do
      next = %{session | continuations: Map.delete(session.continuations, continuation.id)}

      if continuation_live?(next, continuation) do
        resume(%{next | work: continuation.work, pending: continuation.pending})
      else
        {:error, next, :stale_continuation}
      end
    else
      {:error, session, :stale_continuation}
    end
  end

  def reset_send(session, ref) do
    case Map.fetch(session.requests, ref) do
      :error ->
        {:error, session, :unknown_request}

      {:ok, %{upload: upload}} when upload != :open ->
        {:ok, session}

      {:ok, _request} ->
        cond do
          session.pending == nil ->
            reset_send_work(session, ref)

          session.pending.status == :blocked and work_request_ref(session) == ref ->
            reset_send_work(%{session | pending: nil, work: nil}, ref)

          true ->
            {:error, session, :operation_pending}
        end
    end
  end

  defp reset_send_work(session, ref) do
    begin(
      drop_continuations(session, ref),
      :reset_send,
      [{:reset, ref}, {:upload_reset, ref}],
      []
    )
  end

  @doc """
  Admits explicit client migration to the concrete `local` `{ip, port}` (beta).

  Returns `{:ok, session, ref}` once the transport admitted migration; the
  outcome later arrives from `poll/3` as `{:migration, ref, {:ok, actual_local}
  | {:error, reason}}`. The migration deadline is the operation deadline. A
  transport without migration returns `:migration_unsupported`.
  """
  def migrate(%__MODULE__{connection: nil} = session, _local, _opts),
    do: {:error, session, :not_connected}

  def migrate(session, local, opts) do
    if function_exported?(session.transport, :migrate, 2),
      do: begin(session, :migrate, [{:migrate, local}], opts),
      else: {:error, session, :migration_unsupported}
  end

  def poll(session, max, opts \\ [])

  def poll(session, max, opts) when is_integer(max) and max in 1..128 do
    begin(session, :poll, [{:events, max}, :drain], opts)
  end

  def poll(session, _, _), do: {:error, session, :invalid_event_limit}

  def cancel(session, ref) do
    if Map.has_key?(session.requests, ref) do
      begin(session, :cancel, [{:reset, ref}, {:stop, ref}, {:remove_request, ref}], [])
    else
      {:error, session, :unknown_request}
    end
  end

  def close(%__MODULE__{connection: nil} = session), do: {:error, session, :not_connected}
  def close(session), do: begin(session, :close, [:close, :cleanup], [])

  @doc """
  Terminate transport resources without replaying pending application work.

  This does not prove an indeterminate request was unsent. The returned session
  retains its abandoned operation identity in `aborted_operation`.
  """
  def abort(%__MODULE__{connection: nil} = session), do: {:ok, session}

  def abort(session) do
    opts = if session.work, do: [deadline: {:abs_ms, session.work.deadline}], else: []

    expired? =
      (session.work != nil and now() >= session.work.deadline) or
        (session.deadline != nil and now() >= elem(session.deadline, 1))

    _retirement =
      if session.cleanup && expired? do
        # Resource retirement remains possible after the application budget ends.
        Quic.Cleanup.retire(session.cleanup.lease, {:abs_ms, now()})
      end

    abandoned =
      if session.pending,
        do: Map.take(session.pending, [:ref, :kind, :status]),
        else: session.aborted_operation

    begin(
      %{session | pending: nil, work: nil, aborted_operation: abandoned},
      :abort,
      [:abort],
      opts
    )
  end

  def resume(%__MODULE__{pending: nil} = session), do: {:error, session, :no_pending_operation}

  def resume(%__MODULE__{pending: %{status: :indeterminate, ref: ref}} = session),
    do: {:error, session, {:indeterminate_operation, ref}}

  def resume(%__MODULE__{pending: pending} = session) do
    cond do
      now() >= pending.deadline ->
        reason =
          if pending.status == :unknown,
            do: {:indeterminate_operation, pending.ref},
            else: :deadline_expired

        {:error, %{session | pending: %{pending | status: :indeterminate}}, reason}

      pending.status == :blocked ->
        drive(%{session | pending: nil})

      true ->
        case session.transport.operation_status(session.connection, pending.ref, pending.kind) do
          %{status: status, result: result} when status in [:admitted, :completed, :rejected] ->
            complete(session, pending.action, result)

          :unknown ->
            {:unknown, session, pending.ref}

          {:error, reason} ->
            {:error, session, {:unresolved_operation, pending.ref, reason}}
        end
    end
  end

  defp begin(%{pending: pending} = session, _kind, _steps, _opts) when not is_nil(pending),
    do: {:error, session, :operation_pending}

  defp begin(session, kind, steps, opts) do
    timeout = Keyword.get(opts, :timeout, session.timeout)
    batches = Keyword.get(opts, :max_read_batches, 128)
    paused = Keyword.get(opts, :paused, MapSet.new())

    if is_integer(timeout) and timeout > 0 and is_integer(batches) and batches in 1..128 and
         is_struct(paused, MapSet) and valid_operation_deadline?(opts) do
      work = %{
        kind: kind,
        steps: steps,
        deadline: operation_deadline(session, opts, timeout),
        call_timeout: timeout,
        absolute?:
          session.transport == QuicTransport or session.deadline != nil or
            match?({:abs_ms, _}, opts[:deadline]),
        acc: [],
        reads: batches,
        paused: paused,
        bytes: 16_384,
        early: Keyword.get(opts, :early_work, false)
      }

      drive(%{session | work: work})
    else
      {:error, session, :invalid_operation_options}
    end
  end

  defp valid_operation_deadline?(opts) do
    case Keyword.get(opts, :deadline) do
      {:abs_ms, deadline} -> is_integer(deadline)
      _ -> true
    end
  end

  defp operation_deadline(session, opts, timeout) do
    requested =
      case Keyword.get(opts, :deadline) do
        {:abs_ms, deadline} -> deadline
        _ -> now() + timeout
      end

    if session.deadline, do: min(requested, elem(session.deadline, 1)), else: requested
  end

  defp drive(%{qpack_out: out, qpack_decoder_stream: stream} = session)
       when out != <<>> and stream != nil do
    steps = chunks(stream, out, false, session.max_frame)

    drive(%{
      session
      | qpack_out: <<>>,
        work: %{session.work | steps: steps ++ session.work.steps}
    })
  end

  defp drive(%{work: %{steps: []}} = session), do: finish(session)

  defp drive(%{work: %{steps: [action | rest]}} = session) do
    case action do
      {:event, event} ->
        drive_event(session, event, rest)

      :drain ->
        drain(session, rest)

      {:remove_request, ref} ->
        case retire_request(session, ref) do
          {:ok, next} -> drive(put_in(next.work.steps, rest))
          {:error, reason} -> {:error, session, reason}
        end

      {:upload_reset, ref} ->
        drive(
          session
          |> put_in([Access.key(:requests), ref, :upload], :reset)
          |> put_in([Access.key(:work), :steps], rest)
        )

      {:body, _ref, <<>>} ->
        drive(put_in(session.work.steps, rest))

      {:body, ref, bytes} ->
        size = min(byte_size(bytes), 16_384)
        <<chunk::binary-size(^size), remaining::binary>> = bytes
        stream = session.requests[ref].stream

        steps =
          data_steps(stream, chunk, remaining == <<>>, session.max_frame) ++
            [{:body, ref, remaining} | rest]

        drive(put_in(session.work.steps, steps))

      :cleanup ->
        case session.transport.cleanup(session.connection) do
          :ok -> drive(put_in(session.work.steps, rest))
          {:error, reason} -> {:error, session, reason}
        end

      _ ->
        invoke(session, action)
    end
  end

  defp drive_event(session, event, rest) do
    case consume_event(session, event) do
      {:ok, next} -> drive(put_in(next.work.steps, rest))
      {:ok, next, steps} -> drive(put_in(next.work.steps, steps ++ rest))
      {:error, reason} -> {:error, session, reason}
    end
  end

  defp drain(%{work: %{reads: 0}} = session, _rest), do: finish(session)
  defp drain(%{work: %{bytes: 0}} = session, _rest), do: finish(session)

  defp drain(session, rest) do
    case Enum.find(session.runnable, &read_allowed?(session, &1)) do
      nil -> drive(put_in(session.work.steps, rest))
      stream -> drive(put_in(session.work.steps, [{:read, stream}, :drain | rest]))
    end
  end

  defp read_allowed?(session, stream) do
    case request_for_stream(session.requests, stream) do
      {ref, request} ->
        not MapSet.member?(session.work.paused, ref) and not Response.blocked?(request.decoder)

      nil ->
        not wt_stream?(session, stream) or wt_credit?(session.wt.router)
    end
  end

  # A read admits at most 16 KiB, so reading only with that much room left keeps
  # reliable stream bytes inside the router budget instead of rejecting them.
  defp wt_credit?(router),
    do:
      router.retained_bytes + 16_384 <= router.max_bytes and
        map_size(router.outstanding) < router.max_items

  defp invoke(session, action) do
    remaining = session.work.deadline - now()

    if remaining <= 0 do
      {:error, session, :deadline_expired}
    else
      ref = make_ref()

      pending = %{
        action: action,
        kind: operation_kind(action),
        ref: ref,
        deadline: session.work.deadline,
        status: :unknown
      }

      deadline = if session.work.absolute?, do: {:abs_ms, pending.deadline}, else: remaining
      opts = [ref: ref, timeout: min(remaining, session.work.call_timeout), deadline: deadline]
      opts = if session.work.early, do: [{:early_data, :replayable} | opts], else: opts

      case retain_intent(session, pending) do
        {:ok, permit, target} ->
          pending = Map.merge(pending, %{cleanup_permit: permit, target_generation: target})
          next = %{session | pending: pending}
          complete(next, action, admitted_operation(session, next, action, opts))

        {:error, reason} ->
          {:error, session, reason}
      end
    end
  end

  defp admitted_operation(session, next, {:open_request, _, _, _, _} = action, opts) do
    with :ok <- request_admission(session), do: operation(next, action, opts)
  end

  defp admitted_operation(_session, next, action, opts), do: operation(next, action, opts)

  defp retain_intent(%{cleanup: nil}, _pending), do: {:ok, nil, nil}

  defp retain_intent(session, pending) do
    with {:ok, target} <-
           QuicTransport.cleanup_target(session.connection, session.cleanup),
         {:ok, permit} <-
           Quic.Cleanup.operation(
             session.cleanup.lease,
             target,
             pending.ref,
             pending.kind,
             {:abs_ms, pending.deadline}
           ) do
      {:ok, permit, target}
    end
  end

  defp operation(session, {:connect, remote, port, opts}, operation_opts) do
    opts = if session.cleanup, do: Keyword.put(opts, :cleanup, session.cleanup), else: opts
    session.transport.connect(remote, port, Keyword.merge(opts, operation_opts))
  end

  defp operation(session, :open_control, opts),
    do: session.transport.open_stream(session.connection, :uni, opts)

  defp operation(session, {:open_qpack, _type}, opts),
    do: session.transport.open_stream(session.connection, :uni, opts)

  defp operation(session, {:open_request, _, _, _, _}, opts),
    do: session.transport.open_stream(session.connection, :bidi, opts)

  defp operation(session, {:send, stream, bytes, fin}, opts),
    do: session.transport.send_stream(stream, bytes, fin, opts)

  defp operation(session, {:events, max}, opts),
    do: session.transport.events(session.connection, max, opts)

  defp operation(session, {:read, stream}, opts),
    do: session.transport.read(stream, min(session.max_frame, session.work.bytes), opts)

  defp operation(session, {:reset_code, stream, code}, opts),
    do: session.transport.reset_stream(stream, code, opts)

  defp operation(session, {:reset_at, stream, code, size}, opts),
    do: session.transport.reset_stream_at(stream, code, size, opts)

  # The draft-17 prefix is declared reliable so a peer STOP_SENDING is answered
  # with RESET_STREAM_AT that still delivers the stream's session association.
  defp operation(session, {:open_wt, kind}, opts) do
    {:ok, prefix} = Draft17.prefix(kind, session.wt.router.session_id)
    opts = Keyword.put(opts, :reliable_prefix, byte_size(prefix))
    session.transport.open_stream(session.connection, kind, opts)
  end

  defp operation(session, {:datagram, bytes}, opts),
    do: session.transport.send_datagram(session.connection, bytes, opts)

  defp operation(session, {:datagrams, max}, opts),
    do: session.transport.read_datagrams(session.connection, max, opts)

  defp operation(session, {:stop_code, stream, code}, opts),
    do: session.transport.stop_stream(stream, code, opts)

  defp operation(session, {:reset, ref}, opts),
    do: session.transport.reset_stream(session.requests[ref].stream, 0x10C, opts)

  defp operation(session, {:stop, ref}, opts),
    do: session.transport.stop_stream(session.requests[ref].stream, 0x10C, opts)

  defp operation(session, :abort, opts), do: session.transport.abort(session.connection, opts)

  defp operation(session, :close, opts),
    do: session.transport.close(session.connection, 0x100, <<>>, opts)

  defp operation(session, {:migrate, local}, opts),
    do: session.transport.migrate(session.connection, [{:local, local} | opts])

  defp operation_kind({:connect, _, _, _}), do: :connect
  defp operation_kind(:open_control), do: :open_stream
  defp operation_kind({:open_qpack, _}), do: :open_stream
  defp operation_kind({:open_request, _, _, _, _}), do: :open_stream
  defp operation_kind({:send, _, _, _}), do: :send_stream
  defp operation_kind({:events, _}), do: :events
  defp operation_kind({:read, _}), do: :read
  defp operation_kind({:reset, _}), do: :reset_stream
  defp operation_kind({:reset_code, _, _}), do: :reset_stream
  defp operation_kind({:reset_at, _, _, _}), do: :reset_stream_at
  defp operation_kind({:open_wt, _}), do: :open_stream
  defp operation_kind({:datagram, _}), do: :send_datagram
  defp operation_kind({:datagrams, _}), do: :read_datagrams
  defp operation_kind({:stop_code, _, _}), do: :stop_stream
  defp operation_kind({:stop, _}), do: :stop_stream
  defp operation_kind(:close), do: :close
  defp operation_kind(:abort), do: :abort
  defp operation_kind({:migrate, _}), do: :migrate

  defp complete(session, action, result) do
    permit = session.pending && Map.get(session.pending, :cleanup_permit)

    if permit do
      if is_tuple(result) and elem(result, 0) == :unknown,
        do: Quic.Cleanup.indeterminate(permit),
        else: Quic.Cleanup.resolved(permit)
    end

    pending = if session.pending, do: Map.delete(session.pending, :cleanup_permit)
    complete_result(%{session | pending: pending}, action, result)
  end

  defp complete_result(session, _action, {:unknown, connection, ref}),
    do:
      {:unknown, %{session | connection: connection, pending: %{session.pending | ref: ref}}, ref}

  defp complete_result(session, _action, {:unknown, ref}),
    do: {:unknown, %{session | pending: %{session.pending | ref: ref}}, ref}

  defp complete_result(session, {:send, stream, bytes, fin}, {:blocked, %{type: :data_blocked}})
       when byte_size(bytes) > 1 do
    # Definite rejection has no send effects. Keep FIN on the final suffix and
    # retain the same deadline; unknown admission never reaches this clause.
    size = div(byte_size(bytes), 2)
    <<prefix::binary-size(^size), suffix::binary>> = bytes
    [_ | rest] = session.work.steps
    steps = [{:send, stream, prefix, false}, {:send, stream, suffix, fin} | rest]
    drive(%{session | pending: nil, work: %{session.work | steps: steps}})
  end

  defp complete_result(session, _action, {:blocked, reason}),
    do: {:blocked, %{session | pending: %{session.pending | status: :blocked}}, reason}

  defp complete_result(session, :close, {:error, :closed}), do: complete(session, :close, :ok)

  defp complete_result(session, _action, {:error, {:attach_failed, connection, error}}),
    do: {:error, %{session | connection: connection, pending: nil}, {:attach_failed, error}}

  defp complete_result(session, _action, {:error, reason}),
    do: {:error, %{session | pending: nil}, reason}

  defp complete_result(session, action, success) when success == :ok or elem(success, 0) == :ok do
    [_ | rest] = session.work.steps
    session = %{session | pending: nil, work: %{session.work | steps: rest}}

    case accepted(session, action, success) do
      {:ok, next} -> drive(next)
      {:error, reason} -> {:error, session, reason}
      {:error, next, reason} -> {:error, next, reason}
    end
  end

  defp accepted(session, {:connect, _, _, _}, {:ok, connection}),
    do: {:ok, %{session | connection: connection}}

  defp accepted(session, :open_control, {:ok, stream}) do
    steps = chunks(stream, Control.local_payload(session.control), false, session.max_frame)

    {:ok,
     %{
       session
       | control_stream: stream,
         work: %{session.work | steps: steps ++ session.work.steps}
     }}
  end

  defp accepted(session, {:open_qpack, type}, {:ok, stream}) do
    session =
      if type == :qpack_encoder,
        do: %{session | qpack_encoder_stream: stream},
        else: %{session | qpack_decoder_stream: stream}

    send = {:send, stream, Varint.encode!(Stream.type_id(type)), false}
    {:ok, put_in(session.work.steps, [send | session.work.steps])}
  end

  defp accepted(session, {:open_request, ref, headers, body, method}, {:ok, stream}) do
    decoder =
      Response.new(
        method: if(is_tuple(method), do: :connect, else: method),
        purpose: if(is_tuple(method), do: :extended_connect, else: :request),
        max_fields: session.max_fields,
        max_encoded_headers: session.max_encoded_headers,
        max_header_bytes: session.max_header_bytes
      )

    id = stream_id(stream, session.next_stream_id)

    request = %{
      stream: stream,
      stream_id: id,
      ref: ref,
      decoder: decoder,
      upload: :open,
      purpose: method,
      remote_fin?: false
    }

    next = %{
      session
      | requests: Map.put(session.requests, ref, request),
        next_request: session.next_request + 1,
        next_stream_id: id + 4
    }

    next =
      if method == {:extended_connect, "webtransport-h3"},
        do: register_webtransport(next, ref, id),
        else: next

    next = if session.work.early, do: retain_early(next, ref, headers, method), else: next
    goaway_id = if session.control, do: session.control.goaway_id

    if goaway_id != nil and id >= goaway_id do
      steps = [{:reset_code, stream, 0x10B}, {:stop_code, stream, 0x10B}, {:remove_request, ref}]
      {:ok, %{next | work: %{next.work | kind: {:rejected, ref, :goaway}, steps: steps}}}
    else
      tail = if body in [:stream, <<>>], do: [], else: [{:body, ref, body}]
      steps = chunks(stream, headers, body == <<>>, session.max_frame) ++ tail
      {:ok, put_in(next.work.steps, steps ++ next.work.steps)}
    end
  end

  defp accepted(session, {:send, stream, _bytes, true}, _success) do
    case request_for_stream(session.requests, stream) do
      {ref, %{remote_fin?: true}} -> retire_request(session, ref)
      {ref, _request} -> {:ok, put_in(session.requests[ref].upload, :closed)}
      nil -> wt_update(session, stream, send: :closed)
    end
  end

  defp accepted(session, {:open_wt, kind}, {:ok, stream}) do
    key = stream_key(stream)
    {:ok, prefix} = Draft17.prefix(kind, session.wt.router.session_id)
    recv = if kind == :bidi, do: :open, else: :closed

    router =
      if kind == :bidi,
        do: elem(Router.local_stream(session.wt.router, key, :bidi), 1),
        else: session.wt.router

    entry = %{stream: stream, kind: kind, local?: true, send: :open, recv: recv, prefix: 0}

    next_id =
      if kind == :bidi and is_integer(key),
        do: max(session.next_stream_id, key + 4),
        else: session.next_stream_id

    wt = %{
      session.wt
      | router: router,
        streams: Map.put(session.wt.streams, key, %{entry | prefix: byte_size(prefix)})
    }

    steps = [{:send, stream, prefix, false} | session.work.steps]

    {:ok,
     %{
       session
       | wt: wt,
         next_stream_id: next_id,
         work: %{session.work | kind: {:wt_open, key}, steps: steps}
     }}
  end

  defp accepted(session, {:reset_at, stream, _code, _size}, _success),
    do: wt_update(session, stream, send: :reset)

  defp accepted(session, {:stop_code, stream, _code}, _success),
    do: wt_update(session, stream, recv: :closed)

  defp accepted(session, {:datagrams, _}, {:ok, datagrams}) when is_list(datagrams) do
    {router, deliveries} =
      Enum.reduce(datagrams, {session.wt.router, []}, fn bytes, {router, acc} ->
        case Router.datagram(router, bytes) do
          {:ok, router, delivered} -> {router, acc ++ delivered}
          {:error, _} -> {router, acc}
        end
      end)

    session = put_in(session.wt.router, router)
    {:ok, record_events(session, wt_events(session, deliveries))}
  end

  defp accepted(_session, {:events, _}, {:ok, events}) when not is_list(events),
    do: {:error, :invalid_event_batch}

  defp accepted(_session, {:events, _}, {:ok, events}) when length(events) > 128,
    do: {:error, :invalid_event_batch}

  defp accepted(session, {:events, _}, {:ok, events}) do
    {:ok, put_in(session.work.steps, Enum.map(events, &{:event, &1}) ++ session.work.steps)}
  end

  defp accepted(session, {:read, stream}, {:ok, items}) do
    with :ok <- valid_read_batch(stream, items),
         {:ok, next, events} <- consume_items(session, stream, items) do
      terminal? =
        Enum.any?(items, &(elem(&1, 0) in [:fin, :reset])) or MapSet.member?(next.retired, stream)

      runnable = List.delete(next.runnable, stream)
      runnable = if items != [] and not terminal?, do: runnable ++ [stream], else: runnable

      result =
        record_events(
          %{
            next
            | runnable: runnable,
              work: %{
                next.work
                | reads: next.work.reads - 1,
                  bytes: max(0, next.work.bytes - read_bytes(items))
              }
          },
          events
        )

      case retained_budget(result) do
        :ok -> {:ok, result}
        {:error, reason} -> {:error, result, reason}
      end
    end
  end

  defp accepted(session, {:migrate, _local}, {:ok, ref}),
    do: {:ok, put_in(session.work.kind, {:migration, ref})}

  defp accepted(session, _action, _success), do: {:ok, session}

  defp retain_early(session, ref, headers, method) do
    early = session.early
    entry = {headers, method, map_size(early.requests)}
    %{session | early: %{early | requests: Map.put(early.requests, ref, entry)}}
  end

  defp data_steps(stream, <<>>, true, _max), do: [{:send, stream, <<>>, true}]
  defp data_steps(_stream, <<>>, false, _max), do: []

  defp data_steps(stream, bytes, fin, max),
    do: chunks(stream, Frame.encode!(:data, bytes), fin, max)

  defp chunks(_stream, <<>>, _fin, _max), do: []

  defp chunks(stream, bytes, fin, max) do
    size = min(byte_size(bytes), max)
    <<chunk::binary-size(^size), rest::binary>> = bytes
    [{:send, stream, chunk, fin and rest == <<>>} | chunks(stream, rest, fin, max)]
  end

  defp finish(%{work: %{kind: kind, acc: acc}} = session) do
    next = %{session | work: nil, pending: nil}

    case kind do
      :poll ->
        {:ok, next, Enum.reverse(acc)}

      {:request, ref} ->
        {:ok, next, ref}

      {:wt_open, key} ->
        {:ok, next, key}

      {:migration, ref} ->
        {:ok, next, ref}

      {:rejected, ref, reason} ->
        {:error, next, {:request_rejected, ref, reason}}

      :open ->
        {:ok, %{next | open?: true}}

      :close ->
        :ok

      :abort ->
        {:ok,
         %{
           next
           | connection: nil,
             control: nil,
             control_stream: nil,
             requests: %{},
             peer_streams: %{},
             runnable: [],
             retired: MapSet.new(),
             continuations: %{},
             qpack_streams: %{},
             qpack: nil,
             qpack_encoder_stream: nil,
             qpack_decoder_stream: nil,
             qpack_known: 0,
             qpack_blocked: [],
             qpack_out: <<>>,
             open?: false
         }}

      _ ->
        {:ok, next}
    end
  end

  defp record_events(session, events),
    do: put_in(session.work.acc, Enum.reverse(events) ++ session.work.acc)

  defp consume_event(session, {:stream_open, stream, :uni}) do
    cond do
      MapSet.member?(session.retired, stream) ->
        {:ok, session}

      map_size(session.peer_streams) >= 128 ->
        protocol_error(0x107, :peer_stream_limit)

      true ->
        {:ok,
         %{
           session
           | peer_streams: Map.put_new(session.peer_streams, stream, %{type: nil, buffer: <<>>})
         }}
    end
  end

  defp consume_event(session, {:stream_open, stream, :bidi}) do
    cond do
      request_for_stream(session.requests, stream) || MapSet.member?(session.retired, stream) ->
        {:ok, session}

      session.wt != nil and map_size(session.wt.streams) < 1_024 ->
        entry = %{stream: stream, kind: :bidi, local?: false, send: :open, recv: :open, prefix: 0}

        {:ok,
         put_in(session.wt.streams, Map.put_new(session.wt.streams, stream_key(stream), entry))}

      session.wt != nil ->
        protocol_error(0x107, :webtransport_stream_limit)

      true ->
        {:error, :peer_bidirectional_stream}
    end
  end

  defp consume_event(session, {:readable, stream}) do
    cond do
      MapSet.member?(session.retired, stream) ->
        {:ok, session}

      request_for_stream(session.requests, stream) || Map.has_key?(session.peer_streams, stream) ||
          wt_stream?(session, stream) ->
        {:ok, %{session | runnable: Enum.uniq(session.runnable ++ [stream])}}

      true ->
        {:error, :unknown_stream_event}
    end
  end

  defp consume_event(session, {:stopped, stream, code}) do
    case request_for_stream(session.requests, stream) do
      {ref, _request} ->
        {:ok, record_events(session, [{:stopped, ref, code}])}

      nil ->
        cond do
          MapSet.member?(session.retired, stream) ->
            {:ok, session}

          wt_stream?(session, stream) ->
            wt_stopped(session, stream, code)

          true ->
            {:error, :unknown_stream_event}
        end
    end
  end

  defp consume_event(_session, {:closed, reason}), do: {:error, {:connection_closed, reason}}
  defp consume_event(_session, {:error, reason}), do: {:error, reason}

  defp consume_event(%{wt: %{}} = session, :datagram_readable),
    do: {:ok, session, [{:datagrams, 32}]}

  defp consume_event(session, event) when event in [:ready, :writable, :datagram_readable],
    do: {:ok, record_events(session, [event])}

  defp consume_event(session, {:ready, _} = event), do: {:ok, record_events(session, [event])}

  defp consume_event(session, {:migration, ref, outcome} = event)
       when is_reference(ref) and tuple_size(outcome) == 2 and elem(outcome, 0) in [:ok, :error],
       do: {:ok, record_events(session, [event])}

  # 0-RTT disposition is resolved from connection info when the session opens.
  defp consume_event(session, {:early_data, _ref, status}) when status in [:accepted, :rejected],
    do: {:ok, session}

  defp consume_event(_session, _event), do: {:error, :invalid_transport_event}

  defp consume_items(session, stream, items) do
    case request_for_stream(session.requests, stream) do
      {ref, request} ->
        settle_response(session, ref, request, response_items(session, request, items, []))

      nil ->
        cond do
          wt_stream?(session, stream) -> consume_wt_items(session, stream, items)
          wt_uni?(session, stream, items) -> promote_wt_uni(session, stream, items)
          true -> consume_peer_items(session, stream, items)
        end
    end
  end

  defp settle_response(session, ref, request, result) do
    {session, result} = connect_result(session, ref, result)

    case result do
      {:ok, request, events, terminal?} ->
        {acks, events} = Enum.split_with(events, &match?({:qpack_ack, _}, &1))

        next =
          session
          |> put_in([Access.key(:requests), ref], request)
          |> acknowledge_sections(request.stream_id, acks)

        with {:ok, next} <- track_blocked(next, ref, request) do
          if terminal?,
            do: finish_response(next, ref, request, events),
            else: {:ok, next, events}
        end

      {:error, {:http3_error, :stream, code, reason}} ->
        steps = [{:reset_code, request.stream, code}, {:stop_code, request.stream, code}]

        with {:ok, next} <- retire_request(session, ref) do
          {:ok, put_in(next.work.steps, steps ++ next.work.steps),
           [{:stream_error, ref, code, reason}]}
        end

      error ->
        error
    end
  end

  defp acknowledge_sections(session, _stream_id, []), do: session

  defp acknowledge_sections(session, stream_id, acks) do
    known = Enum.reduce(acks, session.qpack_known, fn {:qpack_ack, ric}, acc -> max(acc, ric) end)

    out =
      Enum.reduce(acks, session.qpack_out, fn _, acc -> acc <> Qpack.section_ack(stream_id) end)

    %{session | qpack_known: known, qpack_out: out}
  end

  defp track_blocked(session, ref, request) do
    cond do
      not Response.blocked?(request.decoder) ->
        {:ok, %{session | qpack_blocked: List.delete(session.qpack_blocked, ref)}}

      ref in session.qpack_blocked ->
        {:ok, session}

      length(session.qpack_blocked) >= session.qpack_blocked_streams ->
        protocol_error(0x200, :qpack_blocked_streams_limit)

      true ->
        {:ok, %{session | qpack_blocked: session.qpack_blocked ++ [ref]}}
    end
  end

  # Resume blocked sections in blocking order, then report remaining inserts.
  defp unblock_sections(session) do
    ready =
      Enum.filter(session.qpack_blocked, fn ref ->
        Response.required_insert_count(session.requests[ref].decoder) <=
          session.qpack.insert_count
      end)

    with {:ok, session, events} <- resume_sections(session, ready, []) do
      {:ok, increment_insert_count(session), events}
    end
  end

  defp resume_sections(session, [], events), do: {:ok, session, events}

  defp resume_sections(session, [ref | rest], events) do
    request = session.requests[ref]

    result =
      case Response.resume(request.decoder, session.qpack) do
        {:ok, decoder, emitted} ->
          mapped = Enum.map(emitted, &response_event(ref, &1))
          {:ok, %{request | decoder: decoder}, mapped, decoder.phase == :done}

        error ->
          error
      end

    with {:ok, next, more} <- settle_response(session, ref, request, result) do
      next = requeue_unblocked(next, ref)
      resume_sections(next, rest, events ++ more)
    end
  end

  defp requeue_unblocked(session, ref) do
    case session.requests[ref] do
      %{decoder: decoder, stream: stream} ->
        if Response.blocked?(decoder) or decoder.phase == :done or decoder.held_fin?,
          do: session,
          else: %{session | runnable: Enum.uniq(session.runnable ++ [stream])}

      nil ->
        session
    end
  end

  defp increment_insert_count(%{qpack: %{insert_count: count}, qpack_known: known} = session)
       when count > known do
    %{
      session
      | qpack_known: count,
        qpack_out: session.qpack_out <> Qpack.insert_count_increment(count - known)
    }
  end

  defp increment_insert_count(session), do: session

  defp finish_response(
         session,
         ref,
         %{
           purpose: {:extended_connect, _},
           upload: :open,
           decoder: %{status: status, phase: :done}
         } = request,
         events
       )
       when status in 200..299 do
    {:ok, put_in(session.requests[ref], %{request | remote_fin?: true}), events}
  end

  defp finish_response(session, ref, request, events) do
    with {:ok, next} <- retire_request(session, ref) do
      steps = if request.upload == :open, do: [{:reset_code, request.stream, 0x10C}], else: []
      {:ok, put_in(next.work.steps, steps ++ next.work.steps), events}
    end
  end

  defp response_items(_session, request, [], events),
    do: {:ok, request, Enum.reverse(events), false}

  defp response_items(session, request, [{:data, _id, bytes} | rest], events),
    do: response_items(session, request, [{:data, bytes} | rest], events)

  defp response_items(session, request, [{:data, bytes} | rest], events) when is_binary(bytes) do
    with {:ok, decoder, emitted} <- Response.feed(request.decoder, bytes, session.qpack) do
      mapped = Enum.map(emitted, &response_event(request.ref, &1))
      response_items(session, %{request | decoder: decoder}, rest, Enum.reverse(mapped, events))
    end
  end

  defp response_items(session, request, [{:fin, _id} | rest], events),
    do: response_items(session, request, [{:fin} | rest], events)

  defp response_items(_session, request, [{:fin}], events) do
    with {:ok, decoder, emitted} <- Response.finish(request.decoder) do
      mapped = Enum.map(emitted, &response_event(request.ref, &1))

      {:ok, %{request | decoder: decoder}, Enum.reverse(Enum.reverse(mapped, events)),
       decoder.phase == :done}
    end
  end

  defp response_items(_session, request, [{:reset, _id, code, final_size}], events),
    do:
      {:ok, request, Enum.reverse([{:stream_reset, request.ref, code, final_size} | events]),
       true}

  defp response_items(_session, _request, _items, _events),
    do: protocol_error(0x101, :invalid_stream_event)

  defp response_event(ref, {:headers, status, fields}),
    do: {:headers, ref, [{":status", Integer.to_string(status)} | fields]}

  defp response_event(ref, {:informational, status, fields}),
    do: {:informational, ref, status, fields}

  defp response_event(ref, {:data, bytes}), do: {:data, ref, bytes}
  defp response_event(ref, {:trailers, fields}), do: {:trailers, ref, fields}
  defp response_event(ref, :done), do: {:done, ref}
  defp response_event(_ref, {:qpack_ack, _required} = ack), do: ack

  defp valid_read_batch(_stream, items) when not is_list(items), do: {:error, :invalid_read_batch}

  defp valid_read_batch(_stream, items) when length(items) > 16_384,
    do: {:error, :invalid_read_batch}

  defp valid_read_batch(stream, items) do
    if read_bytes(items) > 16_384,
      do: {:error, :invalid_read_batch},
      else: valid_read_identity(stream, items)
  end

  defp valid_read_identity(%TransportStream{handle: %{id: id}}, items) do
    if Enum.all?(items, &valid_read_item?(&1, id)),
      do: :ok,
      else: {:error, :invalid_stream_identity}
  end

  defp valid_read_identity(_stream, _items), do: :ok

  defp valid_read_item?({:data, id, bytes}, id) when is_binary(bytes), do: true
  defp valid_read_item?({:fin, id}, id), do: true

  defp valid_read_item?({:reset, id, code, final_size}, id)
       when is_integer(code) and is_integer(final_size),
       do: true

  defp valid_read_item?(_item, _id), do: false

  defp read_bytes(items) do
    Enum.reduce(items, 0, fn
      {:data, _id, bytes}, acc when is_binary(bytes) -> acc + byte_size(bytes)
      {:data, bytes}, acc when is_binary(bytes) -> acc + byte_size(bytes)
      _, acc -> acc
    end)
  end

  defp now, do: System.monotonic_time(:millisecond)

  defp valid_limits?(session) do
    session.max_fields in 1..128 and session.max_encoded_headers in 1..65_536 and
      session.max_header_bytes in 1..65_536 and session.max_retained_bytes in 1..1_048_576 and
      session.qpack_max_table_capacity in 0..65_536 and session.qpack_blocked_streams in 0..128
  end

  defp request_admission(%{pending: pending}) when not is_nil(pending),
    do: {:error, :operation_pending}

  defp request_admission(%{control: %{goaway_id: id}, next_stream_id: next})
       when is_integer(id) and next >= id,
       do: {:error, :goaway}

  defp request_admission(session) do
    if MapSet.size(session.retired) >= 1024, do: {:error, :terminal_stream_limit}, else: :ok
  end

  defp outgoing_fields(session, fields) do
    cond do
      length(fields) > session.max_fields ->
        {:error, :request_field_limit}

      not Enum.all?(fields, fn
        {name, value} when is_binary(name) and is_binary(value) -> true
        _ -> false
      end) ->
        {:error, :invalid_fields}

      true ->
        size =
          Enum.reduce(fields, 0, fn {name, value}, acc ->
            acc + byte_size(name) + byte_size(value) + 32
          end)

        peer = List.keyfind(peer_settings(session), 6, 0)

        cond do
          size > session.max_header_bytes -> {:error, :request_header_bytes_limit}
          peer != nil and size > elem(peer, 1) -> {:error, :peer_field_section_limit}
          true -> :ok
        end
    end
  end

  # Before the peer SETTINGS arrive, an early request is bound by the remembered values.
  defp peer_settings(%{control: %{peer_settings: settings}}) when is_list(settings), do: settings
  defp peer_settings(%{early: %{remembered: settings}}), do: settings
  defp peer_settings(_session), do: []

  defp encoded_headers(session, bytes) do
    if byte_size(bytes) > session.max_encoded_headers,
      do: {:error, :request_encoded_headers_limit},
      else: :ok
  end

  defp stream_id(%TransportStream{handle: %{id: id}}, _fallback), do: id
  defp stream_id(_stream, fallback), do: fallback

  defp retire_request(session, ref) do
    request = session.requests[ref]

    with {:ok, next} <- retire_stream(session, request.stream) do
      next = cancel_sections(next, ref, request)
      {:ok, %{drop_continuations(next, ref) | requests: Map.delete(next.requests, ref)}}
    end
  end

  # RFC 9204 Section 4.4.2: abandoning an incomplete response stream releases
  # the peer encoder's references through Stream Cancellation.
  defp cancel_sections(%{qpack: nil} = session, _ref, _request), do: session

  defp cancel_sections(session, ref, %{decoder: %{phase: phase}} = request) do
    session = %{session | qpack_blocked: List.delete(session.qpack_blocked, ref)}
    goaway = session.control && session.control.goaway_id

    # Streams rejected by GOAWAY were never processed by the peer.
    if phase == :done or (goaway != nil and request.stream_id >= goaway),
      do: session,
      else: %{session | qpack_out: session.qpack_out <> Qpack.stream_cancel(request.stream_id)}
  end

  defp retire_stream(session, stream) do
    if MapSet.size(session.retired) < 1024 or MapSet.member?(session.retired, stream) do
      {:ok,
       %{
         session
         | retired: MapSet.put(session.retired, stream),
           runnable: List.delete(session.runnable, stream),
           peer_streams: Map.delete(session.peer_streams, stream)
       }}
    else
      {:error, :terminal_stream_limit}
    end
  end

  defp drop_continuations(session, ref) do
    %{
      session
      | continuations:
          Map.reject(session.continuations, fn {_id, request_ref} -> request_ref == ref end)
    }
  end

  defp work_request_ref(%{work: %{kind: {:request, ref}}}), do: ref

  defp work_request_ref(%{pending: %{action: {:send, stream, _, _}}} = session) do
    case request_for_stream(session.requests, stream) do
      {ref, _} -> ref
      nil -> nil
    end
  end

  defp work_request_ref(_), do: nil
  defp continuation_live?(_session, %{request_ref: nil}), do: true
  defp continuation_live?(_session, %{pending: %{action: {:open_request, _, _, _, _}}}), do: true

  defp continuation_live?(session, %{request_ref: ref}),
    do: match?(%{upload: :open}, session.requests[ref])

  defp retained_budget(session) do
    requests =
      Enum.reduce(session.requests, 0, fn {_, request}, acc ->
        acc + Response.retained_bytes(request.decoder)
      end)

    peers =
      Enum.reduce(session.peer_streams, 0, fn {_, peer}, acc -> acc + byte_size(peer.buffer) end)

    control =
      if session.control,
        do: byte_size(session.control.buffer) + byte_size(session.control.peer_type_buffer),
        else: 0

    if requests + peers + control <= session.max_retained_bytes,
      do: :ok,
      else: protocol_error(0x107, :session_retained_bytes_limit)
  end

  defp consume_peer_items(session, _stream, []), do: {:ok, session, []}

  defp consume_peer_items(session, stream, [{:data, _id, bytes} | rest]),
    do: consume_peer_items(session, stream, [{:data, bytes} | rest])

  defp consume_peer_items(session, stream, [{:data, bytes} | rest]) when is_binary(bytes) do
    with {:ok, next, events} <- consume_peer_bytes(session, stream, bytes),
         {:ok, next, more} <- consume_peer_items(next, stream, rest) do
      {:ok, next, events ++ more}
    end
  end

  defp consume_peer_items(session, stream, [{:fin, _id} | rest]),
    do: consume_peer_items(session, stream, [{:fin} | rest])

  defp consume_peer_items(session, stream, [terminal])
       when terminal == {:fin} or elem(terminal, 0) == :reset do
    case session.peer_streams[stream].type do
      type when type in [:control, :qpack_encoder, :qpack_decoder] ->
        protocol_error(0x104, :closed_critical_stream)

      _ ->
        with {:ok, next} <- retire_stream(session, stream), do: {:ok, next, []}
    end
  end

  defp consume_peer_items(_session, _stream, _items),
    do: protocol_error(0x101, :invalid_stream_event)

  defp consume_peer_bytes(session, stream, bytes) do
    peer = session.peer_streams[stream]

    if peer.type == nil do
      data = peer.buffer <> bytes

      case Stream.decode_type(data) do
        :more ->
          {:ok, put_in(session.peer_streams[stream].buffer, :binary.copy(data)), []}

        {:ok, type, rest} ->
          identify_peer_payload(session, stream, type, data, rest)
      end
    else
      receive_peer_payload(session, stream, peer.type, bytes)
    end
  end

  defp identify_peer_payload(session, stream, type, data, rest) do
    with {:ok, next} <- identify_peer_stream(session, stream, type) do
      payload = if type == :control, do: data, else: rest
      receive_peer_payload(next, stream, type, payload)
    end
  end

  defp identify_peer_stream(session, stream, type)
       when type in [:qpack_encoder, :qpack_decoder] do
    if Map.has_key?(session.qpack_streams, type) do
      protocol_error(
        0x103,
        if(type == :qpack_encoder, do: :duplicate_qpack_encoder, else: :duplicate_qpack_decoder)
      )
    else
      {:ok,
       %{
         put_in(session.peer_streams[stream], %{type: type, buffer: <<>>})
         | qpack_streams: Map.put(session.qpack_streams, type, stream)
       }}
    end
  end

  defp identify_peer_stream(_session, _stream, :push),
    do: protocol_error(0x108, :push_not_enabled)

  defp identify_peer_stream(session, stream, type),
    do: {:ok, put_in(session.peer_streams[stream], %{type: type, buffer: <<>>})}

  defp receive_peer_payload(session, stream, :control, bytes) do
    case Control.receive_peer(session.control, stream, bytes) do
      {:ok, control, events} ->
        with :ok <- check_remembered_settings(session, events),
             do: {:ok, %{session | control: control}, events}

      {:error, {:http3_error, _, _, _}} = error ->
        error

      {:error, reason} ->
        protocol_error(control_code(reason), reason)
    end
  end

  defp receive_peer_payload(%{qpack: nil} = session, _stream, :qpack_encoder, bytes) do
    if Enum.all?(:binary.bin_to_list(bytes), &(&1 == 0x20)),
      do: {:ok, session, []},
      else: protocol_error(0x201, :invalid_static_encoder_instruction)
  end

  defp receive_peer_payload(%{qpack: nil} = session, _stream, :qpack_decoder, <<>>),
    do: {:ok, session, []}

  defp receive_peer_payload(%{qpack: nil}, _stream, :qpack_decoder, _bytes),
    do: protocol_error(0x202, :invalid_static_decoder_instruction)

  defp receive_peer_payload(session, stream, :qpack_encoder, bytes) do
    data = session.peer_streams[stream].buffer <> bytes

    case Qpack.apply_encoder_instructions(session.qpack, data) do
      {:ok, table, rest} ->
        session = put_in(session.peer_streams[stream].buffer, :binary.copy(rest))
        unblock_sections(%{session | qpack: table})

      {:error, reason} ->
        protocol_error(0x201, reason)
    end
  end

  # The local encoder never references the dynamic table, so the peer decoder
  # can only cancel streams; acknowledgments and increments are errors.
  defp receive_peer_payload(session, stream, :qpack_decoder, bytes) do
    data = session.peer_streams[stream].buffer <> bytes

    with {:ok, instructions, rest} <- Qpack.decode_decoder_instructions(data),
         true <- Enum.all?(instructions, &match?({:stream_cancel, _}, &1)),
         true <- byte_size(rest) <= 16 do
      {:ok, put_in(session.peer_streams[stream].buffer, :binary.copy(rest)), []}
    else
      false -> protocol_error(0x202, :unexpected_decoder_instruction)
      {:error, reason} -> protocol_error(0x202, reason)
    end
  end

  defp receive_peer_payload(session, _stream, {:unknown, _type}, _bytes), do: {:ok, session, []}

  defp control_code(reason)
       when reason in [:duplicate_peer_control_stream, :invalid_peer_control_stream],
       do: 0x103

  defp control_code(reason) when reason in [:invalid_goaway, :increasing_goaway], do: 0x108
  defp control_code(:settings_must_be_first), do: 0x10A
  defp control_code(:duplicate_settings), do: 0x109
  defp control_code({:duplicate_setting, _id}), do: 0x109
  defp control_code({:reserved_setting, _id}), do: 0x109
  defp control_code({:invalid_setting_value, _id, _value}), do: 0x109
  defp control_code(:control_frame_too_large), do: 0x107

  defp control_code(reason)
       when reason in [:truncated_setting_identifier, :truncated_setting_value],
       do: 0x106

  defp control_code(_reason), do: 0x105
  defp protocol_error(code, reason), do: {:error, {:http3_error, :connection, code, reason}}

  # -- WebTransport association ------------------------------------------

  defp register_webtransport(session, ref, id) do
    case Router.register(session.wt.router, id) do
      {:ok, router} -> %{session | wt: %{session.wt | router: router, connect: ref}}
      {:error, _} -> session
    end
  end

  defp stream_key(%TransportStream{handle: %{id: id}}), do: id
  defp stream_key(stream), do: stream

  defp wt_stream?(%{wt: %{streams: streams}}, stream),
    do: Map.has_key?(streams, stream_key(stream))

  defp wt_stream?(_session, _stream), do: false

  defp wt_uni?(%{wt: %{}} = session, stream, items) do
    case session.peer_streams[stream] do
      %{type: nil, buffer: buffer} ->
        match?({:ok, {:unknown, 0x54}, _}, Stream.decode_type(buffer <> item_bytes(items)))

      _ ->
        false
    end
  end

  defp wt_uni?(_session, _stream, _items), do: false

  defp promote_wt_uni(session, stream, items) do
    %{buffer: buffer} = session.peer_streams[stream]
    entry = %{stream: stream, kind: :uni, local?: false, send: :closed, recv: :open, prefix: 0}

    session = %{
      session
      | peer_streams: Map.delete(session.peer_streams, stream),
        wt: %{session.wt | streams: Map.put(session.wt.streams, stream_key(stream), entry)}
    }

    consume_wt_items(session, stream, [{:data, buffer} | items])
  end

  defp item_bytes(items) do
    for item <- items, into: <<>> do
      case item do
        {:data, _id, bytes} -> bytes
        {:data, bytes} -> bytes
        _ -> <<>>
      end
    end
  end

  defp consume_wt_items(session, stream, items) do
    key = stream_key(stream)
    entry = session.wt.streams[key]
    bytes = item_bytes(items)

    terminal =
      Enum.find_value(items, fn
        {:fin, _} -> :fin
        {:fin} -> :fin
        {:reset, _id, code, _size} -> {:reset, code}
        _ -> nil
      end)

    cond do
      entry.recv != :open ->
        {:ok, session, []}

      match?({:reset, _}, terminal) ->
        wt_reset_items(session, stream, bytes, elem(terminal, 1))

      bytes == <<>> and terminal == nil ->
        {:ok, session, []}

      true ->
        wt_data_items(session, key, entry.kind, bytes, terminal == :fin)
    end
  end

  # Reliable-reset data precedes the reset; deliver it before terminating.
  defp wt_reset_items(session, stream, bytes, code) do
    key = stream_key(stream)

    with {:ok, session, events} <- consume_wt_items(session, stream, [{:data, bytes}]) do
      if match?(%{recv: :open}, session.wt.streams[key]) do
        {:ok, router, deliveries} = Router.reset(session.wt.router, key, code)
        session = put_in(session.wt.router, router)
        finish_wt_receive(session, key, events ++ wt_events(session, deliveries), [])
      else
        {:ok, session, events}
      end
    end
  end

  defp wt_data_items(session, key, kind, bytes, fin) do
    case Router.stream_data(session.wt.router, key, kind, bytes, fin) do
      {:ok, router, deliveries} ->
        session = put_in(session.wt.router, router)
        {delivered, actions} = Enum.split_with(deliveries, &match?({_, _}, &1))
        events = wt_events(session, delivered)

        if actions == [] and not fin,
          do: {:ok, session, events},
          else: finish_wt_receive(session, key, events, actions)

      {:error, _reason} ->
        # Malformed association is a stream error; the connection survives.
        finish_wt_receive(session, key, [], [{:reset, key, 0x101}])
    end
  end

  # Receive side terminal; rejected streams are also stopped and reset.
  defp finish_wt_receive(session, key, events, actions) do
    session = put_in(session.wt.streams[key].recv, :closed)

    steps =
      Enum.flat_map(actions, fn {:reset, ^key, code} ->
        entry = session.wt.streams[key]
        stop = [{:stop_code, entry.stream, code}]
        if entry.send == :open, do: [{:reset_code, entry.stream, code} | stop], else: stop
      end)

    session =
      if actions == [],
        do: session,
        else: put_in(session.wt.router, Router.forget(session.wt.router, key))

    with {:ok, next} <- maybe_retire_wt(session, key) do
      {:ok, put_in(next.work.steps, steps ++ next.work.steps), events}
    end
  end

  # The QUIC engine answers STOP_SENDING itself and discards the send side, so
  # the stream's send direction is terminal here; no second reset is issued.
  defp wt_stopped(session, stream, code) do
    key = stream_key(stream)
    event = {:wt, session.wt.connect, {:stopped, key, decode_wt_code(code)}}
    wt_update(record_events(session, [event]), stream, send: :reset)
  end

  defp wt_update(%{wt: %{}} = session, stream, changes) do
    key = stream_key(stream)

    case session.wt.streams[key] do
      nil ->
        {:ok, session}

      entry ->
        session = put_in(session.wt.streams[key], Map.merge(entry, Map.new(changes)))

        session =
          if Keyword.get(changes, :recv) == :closed,
            do: put_in(session.wt.router, Router.forget(session.wt.router, key)),
            else: session

        maybe_retire_wt(session, key)
    end
  end

  defp wt_update(session, _stream, _changes), do: {:ok, session}

  defp maybe_retire_wt(session, key) do
    case session.wt.streams[key] do
      %{send: send, recv: :closed, stream: stream} when send != :open ->
        with {:ok, next} <- retire_stream(session, stream) do
          {:ok, put_in(next.wt.streams, Map.delete(next.wt.streams, key))}
        end

      _ ->
        {:ok, session}
    end
  end

  defp wt_events(session, deliveries) do
    connect = session.wt.connect

    Enum.map(deliveries, fn
      {receipt, {:stream, _id, key, kind, bytes, fin}} ->
        {:wt, connect, {:stream, key, kind, bytes, fin, receipt}}

      {receipt, {:datagram, _id, payload}} ->
        {:wt, connect, {:datagram, payload, receipt}}

      {nil, {:reset, _id, key, code}} ->
        {:wt, connect, {:reset, key, decode_wt_code(code)}}
    end)
  end

  defp decode_wt_code(code) do
    case Draft17.decode_application_error(code) do
      {:ok, application} -> application
      {:error, _} -> {:http3_error, code}
    end
  end

  # CONNECT stream of the WT session: 2xx accepts the router; DATA carries
  # capsules; any other final status, FIN or reset closes the router.
  defp connect_result(%{wt: %{connect: ref}} = session, ref, {:ok, request, events, terminal?}) do
    case Enum.reduce_while(events, {:ok, session, []}, &connect_event(ref, &1, &2)) do
      {:ok, session, mapped} ->
        session = if terminal?, do: close_router(session), else: session
        {session, {:ok, request, Enum.reverse(mapped), terminal?}}

      {:error, session, reason} ->
        {close_router(session), {:error, {:http3_error, :stream, 0x10E, reason}}}
    end
  end

  defp connect_result(%{wt: %{connect: ref}} = session, ref, result),
    do: {close_router(session), result}

  defp connect_result(session, _ref, result), do: {session, result}

  defp connect_event(ref, {:headers, ref, [{":status", status} | _]} = event, {:ok, session, acc}) do
    if String.to_integer(status) in 200..299 do
      case Router.accept(session.wt.router, session.wt.router.session_id) do
        {:ok, router, pending} ->
          session = put_in(session.wt.router, router)
          {:cont, {:ok, session, Enum.reverse(wt_events(session, pending)) ++ [event | acc]}}

        {:error, reason} ->
          {:halt, {:error, session, reason}}
      end
    else
      {:cont, {:ok, close_router(session), [event | acc]}}
    end
  end

  defp connect_event(ref, {:data, ref, bytes}, {:ok, session, acc}) do
    with {:ok, capsule, capsules} <- Capsule.feed(session.wt.capsule, bytes),
         {:ok, mapped} <- decode_capsules(ref, capsules) do
      {:cont, {:ok, put_in(session.wt.capsule, capsule), Enum.reverse(mapped, acc)}}
    else
      {:error, reason} -> {:halt, {:error, session, reason}}
    end
  end

  defp connect_event(_ref, event, {:ok, session, acc}), do: {:cont, {:ok, session, [event | acc]}}

  defp decode_capsules(ref, capsules) do
    Enum.reduce_while(capsules, {:ok, []}, fn capsule, {:ok, acc} ->
      case Draft17.decode_capsule(capsule) do
        {:ok, {:close, code, reason}} ->
          {:cont, {:ok, acc ++ [{:wt, ref, {:close, code, reason}}]}}

        {:ok, :drain} ->
          {:cont, {:ok, acc ++ [{:wt, ref, :drain}]}}

        :ignore ->
          {:cont, {:ok, acc}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
  end

  defp close_router(session) do
    case Router.close(session.wt.router, session.wt.router.session_id) do
      {:ok, router, _actions} -> put_in(session.wt.router, router)
      {:error, _} -> session
    end
  end

  defp request_for_stream(requests, stream) do
    Enum.find_value(requests, fn
      {ref, %{stream: ^stream} = request} -> {ref, request}
      _ -> nil
    end)
  end
end
