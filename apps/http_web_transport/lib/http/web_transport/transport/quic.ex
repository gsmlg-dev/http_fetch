defmodule HTTP.WebTransport.Transport.QUIC do
  @moduledoc false

  @behaviour HTTP.WebTransport.Transport

  alias HTTP.H3.Settings
  alias HTTP.H3.Varint
  alias HTTP.H3.WebTransport, as: H3WebTransport
  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.Stats

  @wt_bidi_signal 0x41
  @wt_stream 0x54

  @impl true
  def connect(uri, %Options{} = options) do
    with {:ok, pseudo_headers} <- H3WebTransport.connect_pseudo_headers(uri),
         {:ok, _validated_headers} <-
           H3WebTransport.validate_connect_pseudo_headers(pseudo_headers),
         :ok <- validate_client_settings(options),
         :ok <- ensure_started(),
         {:ok, conn} <- connect_h3(uri, options) do
      connect_session(conn, pseudo_headers, options)
    else
      {:error, _reason} = error ->
        error
    end
  end

  def connect(_uri, _options), do: {:error, :invalid_quic_connect_options}

  @impl true
  def close(%{conn: conn}, _close_info) do
    :quic_h3.close(conn)
  catch
    _kind, _reason -> :ok
  end

  def close(_session_ref, _close_info), do: {:error, :invalid_quic_session}

  @impl true
  def get_stats(_session_ref), do: {:ok, %Stats{}}

  @impl true
  def open_bidirectional_stream(%{conn: conn, quic_conn: quic_conn}, _options) do
    with {:ok, stream_id} <- :quic_h3.open_bidi_stream(conn, @wt_bidi_signal),
         :ok <- :quic.send_data(quic_conn, stream_id, Varint.encode!(@wt_bidi_signal), false) do
      {:ok, stream_ref(conn, quic_conn, stream_id)}
    end
  end

  def open_bidirectional_stream(_session_ref, _options), do: {:error, :invalid_quic_session}

  @impl true
  def open_unidirectional_stream(%{conn: conn, quic_conn: quic_conn}, _options) do
    with {:ok, stream_id} <- :quic.open_unidirectional_stream(quic_conn),
         :ok <- :quic.send_data(quic_conn, stream_id, Varint.encode!(@wt_stream), false) do
      {:ok, stream_ref(conn, quic_conn, stream_id)}
    end
  end

  def open_unidirectional_stream(_session_ref, _options), do: {:error, :invalid_quic_session}

  @impl true
  def send_datagram(%{conn: conn, stream_id: stream_id}, bytes, _options) do
    :quic_h3.send_datagram(conn, stream_id, bytes)
  end

  def send_datagram(_session_ref, _bytes, _options), do: {:error, :invalid_quic_session}

  @impl true
  def recv_stream(_stream_ref, _timeout), do: {:error, :not_supported_by_quic_backend}

  @impl true
  def send_stream(%{quic_conn: quic_conn, stream_id: stream_id}, data, _options) do
    :quic.send_data(quic_conn, stream_id, data, false)
  end

  def send_stream(_stream_ref, _data, _options), do: {:error, :invalid_quic_stream}

  @impl true
  def close_send_stream(%{quic_conn: quic_conn, stream_id: stream_id}) do
    :quic.send_data(quic_conn, stream_id, "", true)
  end

  def close_send_stream(_stream_ref), do: {:error, :invalid_quic_stream}

  @impl true
  def abort_send_stream(%{quic_conn: quic_conn, stream_id: stream_id}, code) do
    :quic.reset_stream(quic_conn, stream_id, code)
  end

  def abort_send_stream(_stream_ref, _code), do: {:error, :invalid_quic_stream}

  @impl true
  def cancel_receive_stream(%{quic_conn: quic_conn, stream_id: stream_id}, code) do
    :quic.stop_sending(quic_conn, stream_id, code)
  end

  def cancel_receive_stream(_stream_ref, _code), do: {:error, :invalid_quic_stream}

  defp ensure_started do
    case Application.ensure_all_started(:quic) do
      {:ok, _apps} -> :ok
      {:error, reason} -> {:error, {:quic_start_failed, reason}}
    end
  end

  defp connect_session(conn, pseudo_headers, %Options{} = options) do
    ops = quic_ops(options)

    with {:ok, stream_id} <-
           ops.request(conn, encode_headers(pseudo_headers ++ options.headers), %{
             end_stream: false
           }),
         {:ok, status, response_headers} <-
           await_connect_response(conn, stream_id, options.connect_timeout),
         :ok <- validate_connect_response(status),
         :ok <- validate_peer_settings(conn, ops),
         {:ok, info} <- transport_info(conn, stream_id, response_headers, options, ops) do
      {:ok, session_ref(conn, stream_id), info}
    else
      {:error, _reason} = error ->
        :ok = close_connection(conn, ops)
        error
    end
  end

  defp connect_h3(%URI{} = uri, %Options{} = options) do
    ops = quic_ops(options)

    case ops.connect(uri.host, port(uri), connect_options(options)) do
      {:ok, conn} ->
        case ops.wait_connected(conn, options.connect_timeout) do
          :ok ->
            {:ok, conn}

          {:error, :timeout} ->
            :ok = close_connection(conn, ops)
            {:error, :connect_timeout}
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp port(%URI{port: port}) when is_integer(port) and port in 1..65_535, do: port
  defp port(%URI{}), do: 443

  defp connect_options(%Options{} = options) do
    %{
      settings:
        options
        |> client_settings()
        |> quic_h3_settings(),
      h3_datagram_enabled: true,
      stream_type_handler: &claim_webtransport_stream/3,
      quic_opts:
        options.quic
        |> Keyword.delete(:quic_ops)
        |> Map.new()
    }
    |> Map.merge(ssl_options(options.ssl))
  end

  defp ssl_options(ssl) do
    Enum.reduce(ssl, %{}, fn
      {:verify, :verify_none}, acc -> Map.put(acc, :verify, :verify_none)
      {:verify, :verify_peer}, acc -> Map.put(acc, :verify, :verify_peer)
      {:cacerts, cacerts}, acc -> Map.put(acc, :cacerts, cacerts)
      {:cert, cert}, acc -> Map.put(acc, :cert, cert)
      {:key, key}, acc -> Map.put(acc, :key, key)
      {_key, _value}, acc -> acc
    end)
  end

  defp claim_webtransport_stream(:uni, _stream_id, @wt_stream), do: :claim
  defp claim_webtransport_stream(:bidi, _stream_id, @wt_bidi_signal), do: :claim
  defp claim_webtransport_stream(_kind, _stream_id, _type), do: :ignore

  defp await_connect_response(conn, stream_id, timeout) do
    receive do
      {:quic_h3, ^conn, {:response, ^stream_id, status, headers}} ->
        {:ok, status, normalize_headers(headers)}

      {:quic_h3, ^conn, {:stream_reset, ^stream_id, reason}} ->
        {:error, {:stream_reset, reason}}

      {:quic_h3, ^conn, {:error, reason}} ->
        {:error, reason}

      {:quic_h3, ^conn, {:closed, reason}} ->
        {:error, {:closed, reason}}
    after
      timeout -> {:error, :connect_timeout}
    end
  end

  defp validate_connect_response(status) when status in 200..299, do: :ok
  defp validate_connect_response(status), do: {:error, {:webtransport_connect_failed, status}}

  defp validate_peer_settings(conn, ops) do
    case ops.get_peer_settings(conn) do
      :undefined -> :ok
      settings -> H3WebTransport.validate_server_settings(settings)
    end
  end

  defp transport_info(conn, stream_id, response_headers, %Options{} = options, ops) do
    unreliable? = ops.h3_datagrams_enabled(conn)

    if options.require_unreliable and not unreliable? do
      {:error, :h3_datagram_disabled}
    else
      {:ok,
       %{
         protocol: negotiated_protocol(options, response_headers),
         reliability: if(unreliable?, do: "supports-unreliable", else: "reliable-only"),
         response_headers: response_headers,
         max_datagram_size: max_datagram_size(conn, stream_id, options, ops)
       }}
    end
  end

  defp negotiated_protocol(%Options{protocols: [protocol | _rest]}, _headers), do: protocol

  defp negotiated_protocol(_options, headers),
    do: header_value(headers, "sec-webtransport-protocol") || ""

  defp max_datagram_size(conn, stream_id, options, ops) do
    case ops.max_datagram_size(conn, stream_id) do
      size when is_integer(size) and size > 0 -> min(size, options.max_datagram_size)
      _size -> options.max_datagram_size
    end
  end

  defp session_ref(conn, stream_id) do
    stream_ref(conn, :quic_h3.get_quic_conn(conn), stream_id)
  end

  defp stream_ref(conn, quic_conn, stream_id) do
    %{conn: conn, quic_conn: quic_conn, stream_id: stream_id}
  end

  defp quic_ops(%Options{quic: quic}) do
    Keyword.get(quic, :quic_ops, __MODULE__)
  end

  defp close_connection(conn, ops) do
    ops.close(conn)
  catch
    _kind, _reason -> :ok
  end

  @doc false
  def connect(host, port, options), do: apply(:quic_h3, :connect, [host, port, options])

  @doc false
  def wait_connected(conn, timeout), do: :quic_h3.wait_connected(conn, timeout)

  @doc false
  def request(conn, headers, options), do: :quic_h3.request(conn, headers, options)

  @doc false
  def close(conn), do: :quic_h3.close(conn)

  @doc false
  def get_peer_settings(conn), do: :quic_h3.get_peer_settings(conn)

  @doc false
  def h3_datagrams_enabled(conn), do: :quic_h3.h3_datagrams_enabled(conn)

  @doc false
  def max_datagram_size(conn, stream_id), do: :quic_h3.max_datagram_size(conn, stream_id)

  defp encode_headers(headers) do
    Enum.map(headers, fn {name, value} -> {to_string(name), to_string(value)} end)
  end

  defp normalize_headers(headers) do
    headers
    |> Enum.reject(fn {name, _value} -> String.starts_with?(to_string(name), ":") end)
    |> Enum.map(fn {name, value} ->
      {name |> to_string() |> HTTP.Headers.normalize_name(), to_string(value)}
    end)
  end

  defp header_value(headers, name) do
    normalized = String.downcase(name)

    Enum.find_value(headers, fn {header_name, value} ->
      if String.downcase(header_name) == normalized, do: value
    end)
  end

  defp validate_client_settings(%Options{} = options) do
    options
    |> client_settings()
    |> H3WebTransport.validate_client_settings()
  end

  defp client_settings(%Options{} = options) do
    H3WebTransport.client_settings(
      initial_max_streams_uni:
        options.anticipated_concurrent_incoming_unidirectional_streams || 0,
      initial_max_streams_bidi: options.anticipated_concurrent_incoming_bidirectional_streams || 0
    )
  end

  defp quic_h3_settings(settings) do
    settings
    |> Settings.normalize()
    |> case do
      {:ok, normalized} ->
        Map.new(normalized, fn {id, value} -> {Settings.name(id) || id, value} end)

      {:error, _reason} ->
        %{}
    end
  end
end
