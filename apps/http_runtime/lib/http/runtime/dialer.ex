defmodule HTTP.Runtime.Dialer do
  @moduledoc false
  alias HTTP.Request

  def open(%Request{} = request, unix_socket_path, timeout) do
    with {:ok, transport, host, port} <- select_transport(request, unix_socket_path),
         {:ok, selection} <- protocol_selection(request, transport),
         {:ok, socket} <- connect(transport, host, port, request, selection, timeout) do
      {:ok, transport, socket, selection}
    end
  end

  def connected_protocol(_transport, _socket, %{mode: :http1}), do: {:ok, :http1}
  def connected_protocol(_transport, _socket, %{mode: :h2c}), do: {:ok, :http2}

  def connected_protocol(transport, socket, %{mode: :force_h2})
      when transport in [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    with {:ok, protocol} <- transport.negotiated_protocol(socket) do
      case normalize_alpn_protocol(protocol) do
        "h2" -> {:ok, :http2}
        other -> {:error, {:http2_not_negotiated, other}}
      end
    end
  end

  def connected_protocol(transport, socket, %{mode: :auto_https})
      when transport in [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    with {:ok, protocol} <- transport.negotiated_protocol(socket) do
      case normalize_alpn_protocol(protocol) do
        "h2" -> {:ok, :http2}
        _other -> {:ok, :http1}
      end
    end
  end

  defp normalize_alpn_protocol(nil), do: nil
  defp normalize_alpn_protocol(protocol) when is_binary(protocol), do: protocol

  def connect(transport, host, port, request, selection, timeout, cancel_monitor \\ nil) do
    connect_timeout = min(connect_timeout(request), timeout)

    with :ok <- validate_connect_address_route(request, nil),
         {:ok, proxy} <- HTTP.Proxy.route(request),
         :ok <- validate_transport_option_lists(transport, request),
         :ok <- validate_connect_address(transport, host, request) do
      with {:ok, managed_token} <- HTTP.ManagedTransport.connect_start(request) do
        result =
          interruptible_connect(
            transport,
            host,
            port,
            Keyword.put(transport_opts(request, selection, timeout), :proxy_route, proxy),
            connect_timeout,
            cancel_monitor,
            timeout
          )

        HTTP.ManagedTransport.connect_done(request, managed_token)
        result
      end
    end
  end

  defp validate_connect_address(transport, host, request) do
    case Keyword.get(request.transport_options, :connect_address) do
      nil ->
        :ok

      address ->
        if HTTP.Transport.valid_connect_address?(address),
          do: validate_pinned_identity(transport, host, address, request),
          else: {:error, :invalid_connect_address}
    end
  end

  defp validate_pinned_identity(transport, host, _address, request)
       when transport in [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    sni =
      request.transport_options |> Keyword.get(:ssl, []) |> Keyword.get(:server_name_indication)

    original_ip = :inet.parse_address(String.to_charlist(host))

    cond do
      transport == HTTP.Transport.ExSSL and conflicting_reference_identity?(host, request) ->
        {:error, :connect_address_identity_conflict}

      transport == HTTP.Transport.ExSSL and match?({:ok, _}, original_ip) and sni == :disable ->
        :ok

      not is_nil(sni) and sni not in [host, String.to_charlist(host)] ->
        {:error, :connect_address_sni_conflict}

      true ->
        :ok
    end
  end

  defp validate_pinned_identity(_transport, _host, _address, _request), do: :ok

  defp conflicting_reference_identity?(host, request) do
    ex_ssl = request.transport_options |> Keyword.get(:ssl, []) |> Keyword.get(:ex_ssl, [])

    if Keyword.keyword?(ex_ssl) do
      case Keyword.fetch(ex_ssl, :reference_identity) do
        :error -> false
        {:ok, reference} -> pinned_reference(reference) != pinned_host_reference(host)
      end
    else
      false
    end
  end

  defp pinned_host_reference(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> {:ip, address}
      {:error, _} -> {:dns_id, host}
    end
  end

  defp pinned_reference({:dns_id, name}) when is_binary(name), do: {:dns_id, name}

  defp pinned_reference({:ip, address}) when is_binary(address) do
    if String.valid?(address) do
      case :inet.parse_address(String.to_charlist(address)) do
        {:ok, ip} -> {:ip, ip}
        {:error, _} -> :invalid
      end
    else
      :invalid
    end
  end

  defp pinned_reference({:ip, address}) do
    if HTTP.Transport.valid_connect_address?(address), do: {:ip, address}, else: :invalid
  end

  defp pinned_reference(_reference), do: :invalid

  defp validate_transport_option_lists(HTTP.Transport.ExSSL, request) do
    valid? =
      Enum.all?([:ssl, :socket_opts], fn key ->
        opts = Keyword.get(request.transport_options, key, [])

        Keyword.keyword?(opts) and
          length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts)))
      end)

    if valid? do
      :ok
    else
      {:error, {:options, :invalid_options}}
    end
  end

  defp validate_transport_option_lists(_transport, _request), do: :ok

  defp interruptible_connect(
         transport,
         host,
         port,
         opts,
         timeout,
         cancel_monitor,
         request_timeout
       ) do
    parent = self()
    ref = make_ref()
    # Structured callers need the low-level TCP failure, rather than a timer
    # racing that result. The connect call keeps its smaller timeout; observing
    # its outcome remains bounded by the original request deadline and signal.
    confirmation_timeout =
      if is_reference(Keyword.get(opts, :connect_failure_token)) and
           Keyword.get(opts, :proxy_route) == nil and
           transport in [HTTP.Transport.TCP, HTTP.Transport.SSL],
         do: request_timeout,
         else: timeout

    deadline_at = connect_deadline(confirmation_timeout)

    tracker = Keyword.get(opts, :request_lifecycle)

    case Task.Supervisor.start_child(:http_runtime_task_supervisor, fn ->
           launch_monitor = Process.monitor(parent)

           receive do
             :connect_launch ->
               Process.demonitor(launch_monitor, [:flush])
               Process.put(HTTP.RequestLifecycle, tracker)
               result = connect_in_worker(transport, host, port, opts, timeout, parent, ref)
               HTTP.RequestLifecycle.complete(tracker)
               send(parent, {:connect_result, ref, result})

             {:DOWN, ^launch_monitor, :process, ^parent, _reason} ->
               :ok
           end
         end) do
      {:ok, pid} ->
        HTTP.RequestLifecycle.register(tracker, pid, :dial)
        send(pid, :connect_launch)
        await_connect_result(transport, pid, ref, nil, deadline_at, cancel_monitor)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp await_connect_result(transport, pid, ref, socket, deadline_at, cancel_monitor) do
    receive do
      {:connect_socket, ^ref, connected_socket} ->
        send(pid, {:transfer_socket, ref})
        await_connect_result(transport, pid, ref, connected_socket, deadline_at, cancel_monitor)

      {:connect_result, ^ref, result} ->
        result

      {:DOWN, ^cancel_monitor, :process, _subscriber, _reason}
      when is_reference(cancel_monitor) ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        stop_connect_worker(pid, ref)
        {:error, :subscriber_down}

      :abort ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        stop_connect_worker(pid, ref)
        {:error, :aborted}

      :deadline ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        stop_connect_worker(pid, ref)
        {:error, :request_timeout}
    after
      remaining_timeout(deadline_at) ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        stop_connect_worker(pid, ref)
        {:error, :connect_timeout}
    end
  end

  defp stop_connect_worker(pid, ref) do
    case HTTP.RequestLifecycle.current() do
      nil ->
        Process.exit(pid, :kill)

      tracker ->
        HTTP.RequestLifecycle.abort(tracker)
        send(pid, {:close_socket, ref})
    end
  end

  defp close_connect_socket(_transport, nil), do: :ok
  defp close_connect_socket(transport, socket), do: transport.close(socket)

  defp connect_in_worker(transport, host, port, opts, timeout, owner, ref) do
    result =
      case Keyword.get(opts, :proxy_route) do
        nil -> transport.connect(host, port, Keyword.delete(opts, :proxy_route), timeout)
        proxy -> HTTP.Proxy.connect(transport, host, port, opts, timeout, proxy)
      end

    case result do
      {:ok, socket} ->
        send(owner, {:connect_socket, ref, socket})
        transfer_connected_socket(transport, socket, owner, ref, timeout)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp transfer_connected_socket(transport, socket, owner, ref, timeout) do
    receive do
      {:transfer_socket, ^ref} ->
        case transport.controlling_process(socket, owner) do
          :ok ->
            {:ok, socket}

          {:error, reason} ->
            transport.close(socket)
            {:error, reason}
        end

      {:close_socket, ^ref} ->
        transport.close(socket)
        {:error, :aborted}

      :abort ->
        transport.close(socket)
        {:error, :aborted}
    after
      timeout ->
        transport.close(socket)
        {:error, :connect_timeout}
    end
  end

  def validate_connect_address_route(request, unix_socket_path) do
    options = request.transport_options

    case Keyword.get(options, :connect_address) do
      nil ->
        :ok

      address ->
        cond do
          not HTTP.Transport.valid_connect_address?(address) ->
            {:error, :invalid_connect_address}

          options[:http_version] == :http3 or unix_socket_path != nil or
            options[:unix_socket] != nil or options[:proxy] != nil ->
            {:error, :connect_address_unsupported_route}

          Keyword.get(options, :redirect, :follow) not in [:manual, :error] ->
            {:error, :connect_address_requires_manual_redirect}

          true ->
            :ok
        end
    end
  end

  def select_transport(request, socket_path) do
    with :ok <- validate_connect_address_route(request, socket_path),
         {:ok, proxy} <- HTTP.Proxy.route(request, socket_path),
         {:ok, transport, host, port} <- select_origin_transport(request, socket_path),
         :ok <- validate_connect_address(transport, host, request) do
      transport =
        if proxy != nil and proxy.scheme == :https,
          do: HTTP.TLSBackend.transport(tls_backend(request)),
          else: transport

      {:ok, transport, host, port}
    end
  end

  defp select_origin_transport(_request, socket_path) when is_binary(socket_path) do
    {:ok, HTTP.Transport.Unix, socket_path, 0}
  end

  defp select_origin_transport(
         %Request{url: %URI{scheme: "http", host: host} = uri},
         _socket_path
       )
       when is_binary(host) do
    {:ok, HTTP.Transport.TCP, host, uri.port || 80}
  end

  defp select_origin_transport(
         %Request{url: %URI{scheme: "https", host: host} = uri} = request,
         _socket_path
       )
       when is_binary(host) do
    {:ok, HTTP.TLSBackend.transport(tls_backend(request)), host, uri.port || 443}
  end

  defp select_origin_transport(%Request{url: %URI{scheme: scheme}}, _socket_path) do
    {:error, {:unsupported_scheme, scheme}}
  end

  def protocol_selection(%Request{} = request, HTTP.Transport.Unix) do
    case http_version(request) do
      version when version in [:http1, :auto] ->
        {:ok, %{mode: :http1, alpn_protocols: []}}

      version ->
        {:error, {:unsupported_http_version_for_unix_socket, version}}
    end
  end

  def protocol_selection(%Request{url: %URI{scheme: "http"}} = request, transport)
      when transport in [HTTP.Transport.TCP, HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    case http_version(request) do
      version when version in [:http1, :auto] ->
        if http2_options?(request),
          do: {:error, :http2_options_require_http2},
          else: {:ok, %{mode: :http1, alpn_protocols: []}}

      :h2c ->
        {:ok, %{mode: :h2c, alpn_protocols: []}}

      :http2 ->
        {:error, :http2_requires_tls}
    end
  end

  def protocol_selection(%Request{url: %URI{scheme: "https"}} = request, transport)
      when transport in [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    case http_version(request) do
      :http1 ->
        if http2_options?(request),
          do: {:error, :http2_options_require_http2},
          else: {:ok, %{mode: :http1, alpn_protocols: []}}

      :http2 ->
        {:ok, %{mode: :force_h2, alpn_protocols: [<<"h2">>]}}

      :auto ->
        if http2_profile?(request) do
          {:ok, %{mode: :force_h2, alpn_protocols: [<<"h2">>]}}
        else
          if http2_options?(request) do
            {:error, :http2_options_require_http2}
          else
            {:ok, %{mode: :auto_https, alpn_protocols: [<<"h2">>, <<"http/1.1">>]}}
          end
        end

      :h2c ->
        {:error, :h2c_requires_cleartext}
    end
  end

  defp connect_timeout(%Request{} = request),
    do:
      Keyword.get(
        request.transport_options,
        :connect_timeout,
        min(request_timeout(request), 30_000)
      )

  defp transport_opts(%Request{} = request, selection, timeout) do
    socket_opts =
      request.transport_options
      |> Keyword.get(:socket_opts, [])
      |> Keyword.put_new(:send_timeout, max(timeout, 1))
      |> Keyword.put_new(:send_timeout_close, true)

    [
      cancellable:
        Keyword.get(request.transport_options, :request_lifecycle) != nil or
          (selection.mode in [:http1, :auto_https] and
             (is_pid(request.body) or Keyword.get(request.transport_options, :http1_reuse, false))) or
          is_reference(Keyword.get(request.transport_options, :connect_failure_token)),
      connect_failure_token: Keyword.get(request.transport_options, :connect_failure_token),
      request_lifecycle: Keyword.get(request.transport_options, :request_lifecycle),
      managed_coordinator: Keyword.get(request.transport_options, :managed_coordinator),
      connect_address: Keyword.get(request.transport_options, :connect_address),
      ssl:
        request.transport_options
        |> Keyword.get(:ssl, [])
        |> put_alpn(selection.alpn_protocols),
      socket_opts: socket_opts
    ]
    |> Enum.reject(fn {key, value} -> key == :connect_address and is_nil(value) end)
  end

  defp put_alpn(ssl_opts, []), do: ssl_opts

  defp put_alpn(ssl_opts, protocols),
    do: Keyword.put_new(ssl_opts, :alpn_advertised_protocols, protocols)

  defp http_version(%Request{} = request) do
    Keyword.get(request.transport_options, :http_version, :http1)
  end

  defp http2_profile?(%Request{} = request),
    do: Keyword.get(request.transport_options, :http2_profile) != nil

  defp http2_options?(%Request{} = request) do
    http2_profile?(request) or
      Keyword.has_key?(request.transport_options, :http2_scope) or
      Keyword.has_key?(request.transport_options, :http2_priority) or
      Keyword.get(request.transport_options, :http2_reuse) == false
  end

  defp tls_backend(%Request{} = request), do: Keyword.get(request.transport_options, :tls_backend)

  defp request_timeout(request), do: Keyword.get(request.transport_options, :timeout, 30_000)
  defp connect_deadline(:infinity), do: :infinity
  defp connect_deadline(timeout), do: System.monotonic_time(:millisecond) + timeout
  defp remaining_timeout(:infinity), do: :infinity
  defp remaining_timeout(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
