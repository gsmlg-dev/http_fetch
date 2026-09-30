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

    with :ok <- validate_transport_option_lists(transport, request) do
      interruptible_connect(
        transport,
        host,
        port,
        transport_opts(request, selection, timeout),
        connect_timeout,
        cancel_monitor
      )
    end
  end

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

  defp interruptible_connect(transport, host, port, opts, timeout, cancel_monitor) do
    parent = self()
    ref = make_ref()
    deadline_at = System.monotonic_time(:millisecond) + timeout

    case Task.Supervisor.start_child(:http_runtime_task_supervisor, fn ->
           result = connect_in_worker(transport, host, port, opts, timeout, parent, ref)
           send(parent, {:connect_result, ref, result})
         end) do
      {:ok, pid} ->
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
        Process.exit(pid, :kill)
        {:error, :subscriber_down}

      :abort ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        Process.exit(pid, :kill)
        {:error, :aborted}

      :deadline ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        Process.exit(pid, :kill)
        {:error, :request_timeout}
    after
      remaining_timeout(deadline_at) ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        Process.exit(pid, :kill)
        {:error, :connect_timeout}
    end
  end

  defp close_connect_socket(_transport, nil), do: :ok
  defp close_connect_socket(transport, socket), do: transport.close(socket)

  defp connect_in_worker(transport, host, port, opts, timeout, owner, ref) do
    case transport.connect(host, port, opts, timeout) do
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
    after
      timeout ->
        transport.close(socket)
        {:error, :connect_timeout}
    end
  end

  def select_transport(_request, socket_path) when is_binary(socket_path) do
    {:ok, HTTP.Transport.Unix, socket_path, 0}
  end

  def select_transport(%Request{url: %URI{scheme: "http", host: host} = uri}, _socket_path)
      when is_binary(host) do
    {:ok, HTTP.Transport.TCP, host, uri.port || 80}
  end

  def select_transport(
        %Request{url: %URI{scheme: "https", host: host} = uri} = request,
        _socket_path
      )
      when is_binary(host) do
    {:ok, HTTP.TLSBackend.transport(tls_backend(request)), host, uri.port || 443}
  end

  def select_transport(%Request{url: %URI{scheme: scheme}}, _socket_path) do
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

  def protocol_selection(%Request{url: %URI{scheme: "http"}} = request, HTTP.Transport.TCP) do
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
      ssl:
        request.transport_options
        |> Keyword.get(:ssl, [])
        |> put_alpn(selection.alpn_protocols),
      socket_opts: socket_opts
    ]
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
  defp remaining_timeout(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
