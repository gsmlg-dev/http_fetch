defmodule NoOTP.Consumer do
  @moduledoc false
  alias QuicHttp3.Session

  def run do
    release = System.fetch_env!("NO_OTP_RELEASE") |> Path.expand()
    initial_paths = Enum.map(:code.get_path(), &(to_string(&1) |> Path.expand()))

    release_paths =
      Enum.filter(:code.get_path(), fn path ->
        String.starts_with?(Path.expand(to_string(path)), release <> "/")
      end)

    true = :code.set_path(release_paths)
    # `release eval` boots without starting the consumer's application tree.
    {:ok, _applications} = Application.ensure_all_started(:no_otp_consumer)
    config = System.fetch_env!("NO_OTP_CONFIG") |> File.read!() |> JSON.decode!()

    transport_targets = [HTTP.Transport.TCP, HTTP.Transport.ExSSL]

    parameter_invariants = %{
      HTTP.SocketClient => [
        {{:handle_new_connection, 7}, 1, transport_targets ++ [HTTP.Transport.Unix]},
        {{:connect_http1_or_new, 7}, 0, transport_targets ++ [HTTP.Transport.Unix]},
        {{:refresh_http1_socket, 4}, 0, transport_targets ++ [HTTP.Transport.Unix]},
        {{:initialize_legacy_owner, 4}, 1, transport_targets ++ [HTTP.Transport.Unix]},
        {{:maybe_http2_owner, 5}, 2, transport_targets ++ [HTTP.Transport.Unix]},
        {{:run_http2_owner, 4}, 1, transport_targets ++ [HTTP.Transport.Unix]},
        {{:initialize_http2_owner, 8}, 0, transport_targets ++ [HTTP.Transport.Unix]},
        {{:maybe_activate_http2_owner, 5}, 1, transport_targets ++ [HTTP.Transport.Unix]},
        {{:transfer_http2_socket, 3}, 0, transport_targets ++ [HTTP.Transport.Unix]}
      ],
      HTTP.EventSource.Connection => [
        {{:connect_stream, 2}, 1, [HTTP.HTTP3.Stream, HTTP.Runtime.Stream]}
      ],
      HTTP.Proxy => [
        {{:establish_tunnel, 7}, 6, transport_targets},
        {{:read_head, 7}, 6, transport_targets},
        {{:next_proxy_head, 8}, 7, transport_targets}
      ],
      HTTP.WebSocket.Connection => [
        {{:recv_handshake, 4}, 0, transport_targets ++ [HTTP.Transport.Unix]}
      ]
    }

    # These supported entry points request incoming-edge diagnostics only.
    # No external callback is classified until its complete provenance is proved.
    public_callable_roots = [
      {HTTP.Promise, :then, 2},
      {HTTP.Promise, :then, 3},
      {SSL, :connect, 2},
      {SSL, :connect, 3},
      {SSL, :connect, 4},
      {:telemetry, :span, 3}
    ]

    # A private tagged-event theorem only: this does not classify external code
    # or establish the later queue, deferred-header or receive-message invariant.
    private_shape_invariants = [
      {HTTP.HTTP3.ConnectionOwner,
       [{{:deliver, 3}, 2, [{:tuple, :informational, 3}, {:tuple, :trailers, 2}]}],
       [{{:deliver, 3}, 2, {:notify, 3}, 2, :discover}]}
    ]

    # Flat field diagnostics are conditional facts only. The graph stays
    # unconfirmed until protocol replies, streaming returns and reducer inputs
    # have separately checked origins; these requests remove no findings.
    private_field_invariants = %{
      HTTP.SocketClient => [
        {{:activate_socket, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:activate_socket, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:arm_read_idle, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:arm_read_idle, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:await_failed_write, 3}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:await_failed_write, 3}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:await_http1_upload_completion, 2}, 0, :transport,
         transport_targets ++ [HTTP.Transport.Unix]},
        {{:await_http1_upload_completion, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:cleanup, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:cleanup, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:close_http1_socket, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:close_http1_socket, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:disarm_read_idle, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:disarm_read_idle, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:fail, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:fail, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:fail_transport, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:fail_transport, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:finish, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:finish, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:finish_completed, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:finish_completed, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:flush_protocol_write, 3}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:flush_protocol_write, 3}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:flush_protocol_writes, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:flush_protocol_writes, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:handle_closed, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:handle_closed, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:handle_data, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:handle_data, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:handle_event, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:handle_event, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:handle_events, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:handle_events, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:handle_http1_headers, 3}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:handle_http1_headers, 3}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:owner_loop, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:owner_loop, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:rearm, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:rearm, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:redirect, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:redirect, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:settle_http1_upload, 1}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:settle_http1_upload, 1}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:start_prepared_request, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:start_prepared_request, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]},
        {{:stop_http1_upload, 2}, 0, :transport, transport_targets ++ [HTTP.Transport.Unix]},
        {{:stop_http1_upload, 2}, 0, :protocol_module, [HTTP.HTTP1, HTTP.HTTP2]}
      ]
    }

    report = %{
      nonce: config["nonce"],
      artifacts:
        NoOTP.ReleaseAudit.artifacts(
          parameter_invariants: parameter_invariants,
          public_callable_roots: public_callable_roots,
          private_shape_invariants: private_shape_invariants,
          private_field_invariants: private_field_invariants
        ),
      before: NoOTP.ReleaseAudit.runtime(),
      initial_code_paths: initial_paths,
      scenarios: [],
      runtime: %{
        elixir: System.version(),
        otp: to_string(:erlang.system_info(:otp_release)),
        erts: to_string(:erlang.system_info(:version))
      }
    }

    report =
      try do
        unless NoOTP.ReleaseAudit.clean?(report.artifacts, report.before),
          do:
            raise("release closure/import/dispatch/runtime isolation is forbidden or unconfirmed")

        {:ok, :ex_ssl} = HTTP.TLSBackend.resolve()
        {:error, _legacy_backend_rejected} = HTTP.TLSBackend.resolve(:ssl)
        # Public client calls below omit backend overrides to verify their defaults.
        scenarios = Enum.map(config["scenarios"], &scenario(&1, config["nonce"]))
        Map.put(report, :scenarios, scenarios)
      rescue
        error -> Map.put(report, :error, Exception.message(error))
      end

    report = Map.put(report, :after, NoOTP.ReleaseAudit.runtime())
    File.write!(System.fetch_env!("NO_OTP_REPORT"), JSON.encode!(report))

    unless not Map.has_key?(report, :error) and
             Enum.all?(report.scenarios, &(&1.result == "PASS")) and
             NoOTP.ReleaseAudit.clean?(report.artifacts, report.after),
           do:
             raise(
               "no-OTP production release failed; retained release-report.json contains evidence"
             )
  end

  defp scenario(case_spec, nonce) do
    base = %{
      id: case_spec["id"],
      nonce: nonce,
      client: case_spec["client"],
      action: case_spec["action"],
      executed: 1,
      peer_identity: case_spec["peer_identity"],
      requested_tls: case_spec["tls"],
      required_alpn: case_spec["alpn"],
      peer_identity_source: "owned_external_peer_ready"
    }

    deadline = now() + case_spec["timeout_ms"]

    try do
      evidence =
        case case_spec["client"] do
          client when client in ["h1", "h2"] -> fetch(case_spec, deadline, nil)
          client when client in ["managed_h1", "managed_h2"] -> managed(case_spec, deadline)
          "wss" -> websocket(case_spec, deadline)
          "sse" -> event_source(case_spec, deadline)
          "h3" -> h3(case_spec, deadline)
        end

      isolation = NoOTP.ReleaseAudit.runtime()

      isolated =
        Enum.all?(
          [:ssl_available, :ssl_loaded, :ssl_application_loaded, :ssl_started],
          &(Map.fetch!(isolation, &1) == false)
        )

      Map.merge(
        base,
        Map.merge(evidence, %{result: "PASS", fallback_isolated: isolated, requests_submitted: 1})
      )
    rescue
      error ->
        Map.merge(base, %{result: "FAIL", cleanup: "unconfirmed", error: Exception.message(error)})
    end
  end

  defp ssl(case_spec) do
    version = if case_spec["tls"] == "TLSv1.2", do: :"tlsv1.2", else: :"tlsv1.3"

    host =
      if case_spec["action"] == "invalid_identity", do: ~c"wrong.invalid", else: ~c"localhost"

    options = [
      verify: :verify_peer,
      cacertfile: case_spec["ca_file"],
      versions: [version],
      server_name_indication: host
    ]

    if protocol(case_spec) == :http1,
      do: Keyword.put(options, :alpn_advertised_protocols, ["http/1.1"]),
      else: options
  end

  defp protocol(%{"client" => client}) when client in ["h1", "managed_h1"], do: :http1
  defp protocol(_), do: :http2

  defp fetch(case_spec, deadline, scope) do
    controller = HTTP.AbortController.new()

    timeout =
      if case_spec["action"] == "timeout",
        do: max(div(remaining(deadline), 2), 1),
        else: remaining(deadline)

    options = [
      http_version: protocol(case_spec),
      ssl: ssl(case_spec),
      redirect: :manual,
      timeout: timeout,
      connect_timeout: timeout,
      signal: controller
    ]

    options =
      if protocol(case_spec) == :http1,
        do: Keyword.put(options, :http1_reuse, false),
        else: Keyword.put(options, :http2_reuse, false)

    options =
      if scope do
        # Managed policy owns TLS and reuse; requests must use the public raw-stream contract.
        [
          transport_scope: scope,
          redirect: :manual,
          decode_body: false,
          stream_response: true,
          timeout: timeout,
          connect_timeout: timeout,
          signal: controller
        ]
      else
        options
      end

    promise = HTTP.fetch(case_spec["url"], options)
    completion = HTTP.Promise.completion(promise)

    try do
      case case_spec["action"] do
        "cancellation" ->
          peer_gate(case_spec, deadline)
          HTTP.AbortController.abort(controller)
          expect_error(HTTP.Promise.await(promise, remaining(deadline)), :aborted)

        "invalid_identity" ->
          expect_error(HTTP.Promise.await(promise, remaining(deadline)), :identity)

        "timeout" ->
          expect_error(HTTP.Promise.await(promise, remaining(deadline)), :timeout)

        "shutdown" ->
          %HTTP.Response{status: 200} =
            response = HTTP.Promise.await(promise, remaining(deadline))

          true = HTTP.Response.stream_body?(response)
          HTTP.AbortController.abort(controller)

        "success" ->
          %HTTP.Response{status: 200} =
            response = HTTP.Promise.await(promise, remaining(deadline))

          true = response.http_version == protocol(case_spec)
          true = HTTP.Response.read_all(response) == case_spec["expected"]
      end

      :ok = HTTP.RequestCompletion.await(completion, remaining(deadline))
      %{cleanup: "confirmed", cleanup_kind: "request_completion"}
    after
      # Cancellation is idempotent; failure still requests cleanup. A timeout or
      # unconfirmed await above cannot be relabelled by this best-effort request.
      HTTP.AbortController.abort(controller)
    end
  end

  defp managed(case_spec, deadline) do
    uri = URI.parse(case_spec["url"])
    origin = URI.to_string(%{uri | path: nil, query: nil, fragment: nil})

    {:ok, scope} =
      HTTP.ManagedTransport.open(
        origin: origin,
        connect_address: {127, 0, 0, 1},
        http_version: protocol(case_spec),
        ssl: ssl(case_spec),
        max_connections: 1,
        max_requests: 1
      )

    try do
      fetch(case_spec, deadline, scope)
      {:ok, snapshot} = HTTP.ManagedTransport.snapshot(scope, remaining(deadline))
      # Missing numeric/provider evidence is a real managed-readiness blocker.
      counts = Map.fetch!(snapshot, :provider_resources)

      true =
        Enum.all?(
          [:processes, :tcp_sockets, :generations, :observers, :data_resources],
          &(is_integer(Map.fetch!(counts, &1)) and Map.fetch!(counts, &1) >= 0)
        )

      {:ok, receipt} = HTTP.ManagedTransport.retire(scope, mode: :abort)
      :ok = HTTP.ManagedTransport.await_retired(receipt, remaining(deadline))
      :ok = HTTP.ManagedTransport.await_retired(receipt, remaining(deadline))
      %{cleanup: "confirmed", cleanup_kind: "managed_receipt", provider_resources: counts}
    after
      HTTP.ManagedTransport.retire(scope, mode: :abort)
    end
  end

  defp websocket(case_spec, deadline) do
    socket =
      HTTP.WebSocket.new(case_spec["url"], [],
        http_version: :http2,
        http2_reuse: false,
        ssl: ssl(case_spec),
        opening_timeout: max(div(remaining(deadline), 2), 1),
        close_timeout: remaining(deadline)
      )

    completion = HTTP.WebSocket.completion(socket)
    %HTTP.WebSocket{pid: pid} = socket
    monitor = Process.monitor(pid)

    try do
      case case_spec["action"] do
        action when action in ["invalid_identity", "timeout"] ->
          error = event(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Error, deadline)
          expect_error(error, if(action == "timeout", do: :timeout, else: :identity))

        "cancellation" ->
          event(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Open, deadline)
          HTTP.WebSocket.close(socket)

        _ ->
          event(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Open, deadline)
          :ok = HTTP.WebSocket.send(socket, case_spec["expected"])
          message = event(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Message, deadline)
          true = message.data == case_spec["expected"]
          :ok = HTTP.WebSocket.close(socket, 1000)
          closed = event(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Close, deadline)
          true = closed.code == 1000 and closed.was_clean
      end

      down(pid, monitor, deadline)
      :ok = HTTP.ClientCompletion.await(completion, remaining(deadline))
      :ok = HTTP.ClientCompletion.await(completion, remaining(deadline))
      %{cleanup: "confirmed", cleanup_kind: "client_completion"}
    after
      HTTP.WebSocket.close(socket)
      Process.demonitor(monitor, [:flush])
    end
  end

  defp event_source(case_spec, deadline) do
    source =
      HTTP.EventSource.new(case_spec["url"],
        http_version: :http2,
        http2_reuse: false,
        ssl: ssl(case_spec),
        connect_timeout: max(div(remaining(deadline), 2), 1)
      )

    completion = HTTP.EventSource.completion(source)
    %HTTP.EventSource{pid: pid} = source
    monitor = Process.monitor(pid)

    try do
      case case_spec["action"] do
        action when action in ["invalid_identity", "timeout"] ->
          error = event(HTTP.EventSource, source, HTTP.EventSource.Event.Error, deadline)
          expect_error(error, if(action == "timeout", do: :timeout, else: :identity))

        "cancellation" ->
          event(HTTP.EventSource, source, HTTP.EventSource.Event.Open, deadline)

        _ ->
          event(HTTP.EventSource, source, HTTP.EventSource.Event.Open, deadline)
          true = HTTP.EventSource.http_version(source) == :http2
          message = event(HTTP.EventSource, source, HTTP.EventSource.Event.Message, deadline)
          true = message.data == case_spec["expected"]
      end

      :ok = HTTP.EventSource.close(source)
      down(pid, monitor, deadline)
      :ok = HTTP.ClientCompletion.await(completion, remaining(deadline))
      :ok = HTTP.ClientCompletion.await(completion, remaining(deadline))
      %{cleanup: "confirmed", cleanup_kind: "client_completion"}
    after
      HTTP.EventSource.close(source)
      Process.demonitor(monitor, [:flush])
    end
  end

  defp h3(case_spec, deadline) do
    # QUIC owns a session/endpoint, not a TCP SSL.Lifecycle Handle. The public
    # Session close/abort path includes cleanup of its explicitly owned endpoint.
    uri = URI.parse(case_spec["url"])

    identity =
      if case_spec["action"] == "invalid_identity", do: "wrong.invalid", else: "localhost"

    {:ok, initial} = Session.new(timeout: remaining(deadline))
    options = [tls: [cacertfile: case_spec["ca_file"], reference_identity: {:dns_id, identity}]]

    case Session.connect(initial, {127, 0, 0, 1}, uri.port, options) do
      {:ok, session} ->
        h3_connected(session, case_spec, uri, deadline)

      {:error, session, reason} ->
        {:ok, _} = Session.abort(session)
        true = case_spec["action"] == "invalid_identity"
        expect_error(reason, :identity)
        %{cleanup: "confirmed", cleanup_kind: "quic_session_endpoint"}

      {:unknown, session, _ref} ->
        Session.abort(session)
        raise("QUIC connect admission unconfirmed; no replay")
    end
  end

  defp h3_connected(session, case_spec, uri, deadline) do
    case wait_ready(session, deadline) do
      :ready ->
        true = case_spec["action"] != "invalid_identity"
        {:ok, opened} = Session.open(session)

        fields = [
          {":method", "GET"},
          {":scheme", "https"},
          {":authority", uri.authority},
          {":path", uri.path || "/"}
        ]

        {:ok, advanced, ref} = Session.request(opened, fields, "", [])
        finish_h3(advanced, ref, case_spec, deadline)

      {:error, reason} ->
        true = case_spec["action"] == "invalid_identity"
        expect_error(reason, :identity)
        {:ok, _} = Session.abort(session)
    end

    %{cleanup: "confirmed", cleanup_kind: "quic_session_endpoint"}
  rescue
    error ->
      Session.abort(session)
      reraise error, __STACKTRACE__
  end

  defp finish_h3(session, ref, %{"action" => action} = case_spec, deadline)
       when action in ["cancellation", "timeout", "shutdown"] do
    peer_gate(case_spec, deadline)

    if action == "cancellation" do
      {:ok, cancelled} = Session.cancel(session, ref)
      :ok = Session.close(cancelled)
    else
      # This caller-driven API has no Fetch RequestCompletion. Timeout is a
      # bounded response wait through public poll followed by public close.
      # Close submits CONNECTION_CLOSE before retiring the owned endpoint;
      # this is not a fabricated native :deadline_exceeded result.
      if action == "timeout" do
        h3_timeout(session, ref, deadline)
      else
        :ok = Session.close(session)
      end
    end
  end

  defp finish_h3(session, ref, case_spec, deadline) do
    {advanced, body, headers} = h3_response(session, ref, deadline, "", [])
    true = {":status", "200"} in headers
    true = body == case_spec["expected"]
    :ok = Session.close(advanced)
  end

  defp h3_timeout(session, ref, deadline) do
    if now() >= deadline do
      :ok = Session.close(session)
    else
      {:ok, advanced, events} = Session.poll(session, 128, timeout: remaining(deadline))

      false =
        Enum.any?(events, fn
          {:done, ^ref} -> true
          {:stream_reset, ^ref, _, _} -> true
          _ -> false
        end)

      h3_timeout(advanced, ref, deadline)
    end
  end

  defp h3_response(session, ref, deadline, body, headers) do
    remaining(deadline)
    {:ok, advanced, events} = Session.poll(session, 128, timeout: remaining(deadline))

    body =
      Enum.reduce(events, body, fn
        {:data, ^ref, bytes}, value -> value <> bytes
        _, value -> value
      end)

    headers =
      Enum.reduce(events, headers, fn
        {:headers, ^ref, fields}, _value -> fields
        _, value -> value
      end)

    if {:done, ref} in events,
      do: {advanced, body, headers},
      else: h3_response(advanced, ref, deadline, body, headers)
  end

  defp wait_ready(session, deadline) do
    remaining(deadline)

    case Session.ready(session) do
      :pending ->
        Process.sleep(1)
        wait_ready(session, deadline)

      {:error, :closed} ->
        h3_closed_reason(session, deadline)

      result ->
        result
    end
  end

  defp h3_closed_reason(%{connection: %{handle: handle}}, deadline) do
    receive do
      {:quic_closed, ^handle, reason} -> {:error, reason}
    after
      remaining(deadline) -> {:error, :closed}
    end
  end

  defp peer_gate(case_spec, deadline) do
    path = Map.fetch!(case_spec, "gate_file")
    remaining(deadline)

    case File.read(path) do
      {:ok, bytes} ->
        gate = JSON.decode!(bytes)
        true = gate["peer_gate"] == true
        true = gate["nonce"] == Map.fetch!(case_spec, "nonce")
        true = gate["id"] == case_spec["id"]
        :ok

      {:error, :enoent} ->
        Process.sleep(1)
        peer_gate(case_spec, deadline)

      {:error, reason} ->
        raise("independent peer gate read failed: #{reason}")
    end
  end

  defp event(module, target, expected, deadline) do
    receive do
      {^module, ^target, %{__struct__: ^expected} = event} -> event
      {^module, ^target, _event} -> raise("unexpected public client event")
    after
      remaining(deadline) -> raise("public client event deadline exceeded")
    end
  end

  defp down(pid, monitor, deadline) do
    receive do
      {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
    after
      remaining(deadline) -> raise("public client did not terminate")
    end
  end

  defp expect_error(value, kind) do
    # Match observed error categories, not any arbitrary setup/fixture failure.
    text = inspect(value, limit: 30)

    pattern =
      case kind do
        :identity ->
          ~r/hostname_check_failed|bad_certificate|certificate_unknown|unknown_ca|reference_identity_mismatch/

        :timeout ->
          ~r/timeout|deadline_exceeded/

        :aborted ->
          ~r/aborted|cancelled/
      end

    true = Regex.match?(pattern, text)
    :ok
  end

  defp remaining(deadline) do
    value = deadline - now()
    if value <= 0, do: raise("original scenario deadline exceeded"), else: value
  end

  defp now, do: System.monotonic_time(:millisecond)
end
