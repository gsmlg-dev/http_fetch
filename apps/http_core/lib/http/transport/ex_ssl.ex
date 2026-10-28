defmodule HTTP.Transport.ExSSL do
  @moduledoc false

  @behaviour HTTP.Transport

  @impl true
  def connect(host, port, opts, timeout) do
    if HTTP.Transport.AddressFamily.preferred?(opts),
      do: connect_preferred(host, port, opts, timeout),
      else: connect_direct(host, port, opts, timeout)
  end

  defp connect_preferred(host, port, opts, timeout) do
    deadline = setup_deadline(timeout)
    socket_opts = [:binary, packet: :raw, active: false] ++ Keyword.get(opts, :socket_opts, [])

    with {:ok, prepared} <- prepare_upgrade(host, opts),
         {:ok, tcp} <- preferred_tcp(host, port, socket_opts, opts, deadline) do
      HTTP.RequestLifecycle.track_socket(opts, tcp)

      result =
        with {:ok, attempt} <- prepared_attempt(prepared, opts, deadline) do
          case upgrade_prepared_attempt(tcp, attempt, opts) do
            {:ok, _socket} = connected ->
              connected

            error ->
              cancel_prepared(attempt)
              error
          end
        end

      if match?({:error, _}, result), do: close_owned_tcp(tcp)
      result
    end
  end

  defp preferred_tcp(host, port, socket_opts, opts, deadline) do
    case HTTP.Transport.AddressFamily.connect(
           host,
           port,
           socket_opts,
           opts,
           setup_remaining(deadline)
         ) do
      {:ok, _tcp} = connected -> connected
      {:error, reason} -> HTTP.Transport.connect_error(opts, reason)
    end
  end

  defp close_owned_tcp(tcp) do
    if Port.info(tcp, :connected) == {:connected, self()}, do: :gen_tcp.close(tcp)
  end

  defp connect_direct(host, port, opts, timeout) do
    deadline = setup_deadline(timeout)

    with {:ok, ssl_opts} <- tls_options(opts),
         {:ok, ssl_opts} <- lifecycle_options(ssl_opts, opts, deadline) do
      route = if Keyword.get(opts, :connect_address) != nil, do: :pinned, else: :direct
      ssl_opts = origin_identity(host, ssl_opts, route)
      ex_ssl = Keyword.get(ssl_opts, :ex_ssl, [])
      descriptor = if Keyword.keyword?(ex_ssl), do: Keyword.get(ex_ssl, :lifecycle)

      result =
        SSL.connect(
          Keyword.get(opts, :connect_address, connect_host(host)),
          port,
          ssl_opts,
          setup_remaining(deadline)
        )

      finish_attempt(result, opts, deadline, descriptor)
    end
  end

  @doc false
  def upgrade(tcp, _host, _opts, timeout)
      when timeout != :infinity and (not is_integer(timeout) or timeout < 0),
      do: SSL.connect(tcp, [], timeout)

  def upgrade(tcp, host, opts, timeout) do
    deadline = setup_deadline(timeout)

    with {:ok, ssl_opts} <- tls_options(opts),
         {:ok, ssl_opts} <- lifecycle_options(ssl_opts, opts, deadline) do
      tcp
      |> SSL.connect(origin_identity(host, ssl_opts, :upgrade), setup_remaining(deadline))
      |> finish_attempt(opts, deadline)
    end
  end

  @doc false
  def prepare_upgrade(host, opts) do
    with {:ok, ssl_opts} <- tls_options(opts),
         do: SSL.prepare_upgrade(origin_identity(host, ssl_opts, :upgrade))
  end

  # Reusable policy and one-attempt cancellation authority remain separate.
  @doc false
  def prepare_upgrade(host, opts, deadline) do
    with {:ok, prepared} <- prepare_upgrade(host, opts),
         do: prepared_attempt(prepared, opts, deadline)
  end

  @doc false
  def prepare_nested(proxy_host, proxy_opts, host, opts, deadline) do
    tracker = Keyword.get(opts, :request_lifecycle)

    with {:ok, inner} <- prepare_upgrade(host, opts),
         {:ok, outer} <- prepare_upgrade(proxy_host, proxy_opts),
         {:ok, layers} <- nested_layers(tracker, deadline) do
      {:ok, {:nested_attempt, outer, inner, layers, tracker, deadline}}
    end
  end

  defp nested_layers(nil, _deadline), do: {:ok, %{outer: nil, inner: nil}}

  defp nested_layers(tracker, deadline) do
    with {:ok, descriptor} <-
           HTTP.RequestLifecycle.begin_provider(tracker, :ex_ssl_pair, deadline),
         do: SSL.Lifecycle.layers(descriptor)
  end

  @doc false
  def upgrade_nested(tcp, {:nested_attempt, outer, inner, layers, tracker, deadline}, layer, opts)
      when layer in [:outer, :inner] do
    prepared = if layer == :outer, do: outer, else: inner
    descriptor = Map.fetch!(layers, layer)

    result =
      with {:ok, socket} <- nested_attach(tcp, prepared, descriptor, deadline),
           :ok <- nested_adopt(layer, tracker, descriptor, tcp, socket, deadline),
           do: {:ok, socket}

    case result do
      {:error, reason} = error ->
        # A TLS attach timeout is still the HTTP connection phase, including
        # when the provider's original deadline wins the dialer timer race.
        {error, reason} =
          if reason == :timeout,
            do: {{:error, :connect_timeout}, :connect_timeout},
            else: {error, reason}

        result = setup_failure_result(error, reason, opts, descriptor)
        HTTP.RequestLifecycle.provider_failed(tracker)
        result

      connected ->
        connected
    end
  end

  defp nested_attach(tcp, prepared, nil, deadline),
    do: SSL.connect_prepared(tcp, prepared, setup_remaining(deadline))

  defp nested_attach(tcp, prepared, descriptor, deadline),
    do:
      SSL.connect_prepared(
        tcp,
        prepared,
        [ex_ssl: [lifecycle: descriptor]],
        setup_remaining(deadline)
      )

  defp nested_adopt(:outer, tracker, descriptor, tcp, _socket, deadline),
    do: HTTP.RequestLifecycle.adopt_outer_provider(tracker, descriptor, tcp, deadline)

  defp nested_adopt(:inner, tracker, _descriptor, _tcp, socket, deadline),
    do: HTTP.RequestLifecycle.bind_provider(tracker, socket, deadline)

  @doc false
  def cancel_nested({:nested_attempt, _, _, _, tracker, _}),
    do: HTTP.RequestLifecycle.provider_failed(tracker)

  defp prepared_attempt(prepared, opts, deadline) do
    with {:ok, attempt_opts} <- lifecycle_options([], opts, deadline) do
      {:ok,
       {:prepared_attempt, prepared, Keyword.get(attempt_opts, :ex_ssl, [])[:lifecycle],
        Keyword.get(opts, :request_lifecycle), deadline}}
    end
  end

  @doc false
  def upgrade_prepared(tcp, {:prepared_attempt, prepared, nil, _tracker, deadline}, _timeout),
    do: SSL.connect_prepared(tcp, prepared, setup_remaining(deadline))

  def upgrade_prepared(tcp, {:prepared_attempt, _, _, _, _} = attempt, _timeout),
    do: upgrade_prepared_attempt(tcp, attempt, [])

  def upgrade_prepared(tcp, prepared, timeout),
    do: SSL.connect_prepared(tcp, prepared, timeout)

  defp upgrade_prepared_attempt(tcp, {:prepared_attempt, prepared, nil, _, deadline}, _opts),
    do: SSL.connect_prepared(tcp, prepared, setup_remaining(deadline))

  defp upgrade_prepared_attempt(
         tcp,
         {:prepared_attempt, prepared, descriptor, tracker, deadline},
         opts
       ) do
    result =
      with {:ok, socket} <-
             SSL.connect_prepared(
               tcp,
               prepared,
               [ex_ssl: [lifecycle: descriptor]],
               setup_remaining(deadline)
             ),
           :ok <-
             HTTP.RequestLifecycle.adopt_provider(tracker, descriptor, tcp, socket, deadline),
           do: {:ok, socket}

    case result do
      {:error, reason} = error ->
        classified = setup_failure_result(error, reason, opts, descriptor)
        HTTP.RequestLifecycle.provider_failed(tracker)
        classified

      connected ->
        connected
    end
  end

  @doc false
  def cancel_prepared({:prepared_attempt, _prepared, _descriptor, tracker, _deadline}),
    do: HTTP.RequestLifecycle.provider_failed(tracker)

  def cancel_prepared(_prepared), do: :ok

  @impl true
  def controlling_process(socket, pid), do: SSL.controlling_process(socket, pid)

  @impl true
  def send(socket, iodata), do: SSL.send(socket, iodata)

  @doc false
  def send(socket, iodata, {:abs_ms, _deadline} = deadline),
    do: SSL.send(socket, iodata, deadline)

  @doc false
  def enable_duplex_reads(socket, timeout) do
    with :ok <- SSL.setopts(socket, send_timeout: timeout),
         do: SSL.enable_duplex_reads(socket)
  end

  @doc false
  def abandon_send(socket), do: SSL.abandon_send(socket)

  @impl true
  def recv(socket, length, timeout), do: SSL.recv(socket, length, timeout)

  @impl true
  def setopts(socket, opts), do: SSL.setopts(socket, opts)

  @impl true
  def close(socket), do: SSL.close(socket)

  @impl true
  def negotiated_protocol(socket) do
    case SSL.negotiated_protocol(socket) do
      {:error, :protocol_not_negotiated} -> {:ok, nil}
      result -> result
    end
  end

  @impl true
  def normalize_message({:ssl, socket, data}, socket), do: {:data, data}
  def normalize_message({:ssl_closed, socket}, socket), do: :closed
  def normalize_message({:ssl_error, socket, reason}, socket), do: {:error, reason}
  def normalize_message(_, _), do: :unknown

  defp lifecycle_options(ssl_opts, opts, deadline) do
    case Keyword.get(opts, :request_lifecycle) do
      nil ->
        {:ok, ssl_opts}

      tracker ->
        ex_ssl = Keyword.get(ssl_opts, :ex_ssl, [])

        cond do
          not Keyword.keyword?(ex_ssl) or
              (Keyword.has_key?(ssl_opts, :ex_ssl) and ex_ssl == []) ->
            {:error, {:options, {:ex_ssl, :unsupported_or_invalid}}}

          Keyword.has_key?(ex_ssl, :lifecycle) ->
            {:error, {:options, {:lifecycle, :request_owned}}}

          true ->
            with {:ok, descriptor} <-
                   HTTP.RequestLifecycle.begin_provider(tracker, :ex_ssl, deadline),
                 do: {:ok, Keyword.put(ssl_opts, :ex_ssl, [{:lifecycle, descriptor} | ex_ssl])}
        end
    end
  end

  defp setup_deadline(:infinity), do: :infinity
  defp setup_deadline(timeout), do: System.monotonic_time(:millisecond) + timeout
  defp setup_remaining(:infinity), do: :infinity
  defp setup_remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  defp finish_attempt(result, opts, deadline, descriptor \\ nil)

  defp finish_attempt({:error, reason} = error, opts, _deadline, descriptor) do
    result = setup_failure_result(error, reason, opts, descriptor)
    HTTP.RequestLifecycle.provider_failed(Keyword.get(opts, :request_lifecycle))
    result
  end

  defp finish_attempt({:ok, socket} = result, opts, deadline, _descriptor) do
    case HTTP.RequestLifecycle.bind_provider(
           Keyword.get(opts, :request_lifecycle),
           socket,
           deadline
         ) do
      :ok ->
        result

      error ->
        HTTP.RequestLifecycle.provider_failed(Keyword.get(opts, :request_lifecycle))
        error
    end
  end

  defp setup_failure_result(error, reason, opts, {handle, _lease}) do
    if Keyword.get(opts, :tls_setup_evidence) === true and
         is_pid(Keyword.get(opts, :request_lifecycle)) and
         is_reference(Keyword.get(opts, :connect_failure_token)) do
      cond do
        SSL.Lifecycle.connect_failure(handle) == {:ok, %{phase: :connect}} ->
          HTTP.Transport.connect_error(opts, reason)

        SSL.Lifecycle.setup_failure(handle) == {:ok, %{phase: :tls_setup}} ->
          HTTP.Transport.tls_setup_error(opts, reason)

        true ->
          error
      end
    else
      error
    end
  end

  defp setup_failure_result(error, _reason, _opts, _descriptor), do: error

  defp tls_options(opts) do
    ssl_opts = Keyword.get(opts, :ssl, [])
    socket_opts = Keyword.get(opts, :socket_opts, [])

    with :ok <- validate_keyword(ssl_opts),
         :ok <- validate_keyword(socket_opts),
         :ok <- validate_socket_options(socket_opts) do
      # SSL supplies system trust only when neither caller CA option is present,
      # and infers DNS SNI or IP identity from the connection host.
      defaults = [
        mode: :binary,
        packet: :raw,
        active: false,
        verify: :verify_peer,
        versions: Keyword.get_lazy(ssl_opts, :versions, fn -> default_versions(ssl_opts) end),
        depth: 4,
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]

      {:ok, defaults |> Keyword.merge(ssl_opts) |> Keyword.merge(socket_opts)}
    end
  end

  # Concrete profiles retain their ordered version policy. Auto tickets and an
  # explicit cipher policy retain the previous TLS 1.3 context unless versions
  # are explicit. This does not infer protocol versions from cipher spellings.
  # Ordinary HTTP with no concrete policy offers both supported versions.
  defp default_versions(ssl_opts) do
    ex_ssl = Keyword.get(ssl_opts, :ex_ssl, [])
    profile = if Keyword.keyword?(ex_ssl), do: Keyword.get(ex_ssl, :profile)

    case profile do
      %SSL.ClientHello.WireProfile{extensions: extensions} when is_list(extensions) ->
        profile_versions(extensions)

      _ ->
        if Keyword.get(ssl_opts, :session_tickets) == :auto or
             Keyword.has_key?(ssl_opts, :ciphers),
           do: [:"tlsv1.3"],
           else: [:"tlsv1.3", :"tlsv1.2"]
    end
  end

  defp profile_versions(extensions) do
    case List.keyfind(extensions, :supported_versions, 0) do
      {:supported_versions, versions} when is_list(versions) ->
        Enum.flat_map(versions, fn
          {:grease, _slot} -> []
          version when version in [0x0304, :tlsv1_3] -> [:"tlsv1.3"]
          version when version in [0x0303, :tlsv1_2] -> [:"tlsv1.2"]
          version -> [version]
        end)

      _ ->
        [:"tlsv1.3"]
    end
  end

  defp validate_keyword(opts) do
    if Keyword.keyword?(opts) and
         length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) do
      :ok
    else
      {:error, {:options, :invalid_options}}
    end
  end

  defp validate_socket_options(opts) do
    allowed = [
      :send_timeout,
      :send_timeout_close,
      :nodelay,
      :keepalive,
      :sndbuf,
      :recbuf,
      :buffer,
      :tos,
      :tclass,
      :priority,
      :ip,
      :port
    ]

    case Enum.find(opts, fn {key, _} -> key not in allowed end) do
      nil -> :ok
      {key, _} -> {:error, {:options, {key, :unsupported_or_invalid}}}
    end
  end

  defp origin_identity(host, ssl_opts, route) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} ->
        ex_ssl = Keyword.get(ssl_opts, :ex_ssl, [])

        valid_options? =
          not Keyword.has_key?(ssl_opts, :ex_ssl) or
            (Keyword.keyword?(ex_ssl) and ex_ssl != [])

        ip_reference? =
          route == :pinned or Keyword.get(ssl_opts, :server_name_indication) in [nil, :disable]

        if valid_options? and ip_reference? do
          ssl_opts
          |> Keyword.put(:ex_ssl, Keyword.put_new(ex_ssl, :reference_identity, {:ip, address}))
          |> Keyword.put_new(:server_name_indication, :disable)
        else
          ssl_opts
        end

      {:error, _} ->
        if route != :direct,
          do: Keyword.put_new(ssl_opts, :server_name_indication, String.to_charlist(host)),
          else: ssl_opts
    end
  end

  defp connect_host(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> address
      {:error, :einval} -> host
    end
  end
end
