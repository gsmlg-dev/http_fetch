defmodule HTTP.HTTP3 do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.Request

  @request_body_chunk_size 16_384
  @flow_control_retry_interval 10

  @type response :: %{
          required(:status) => non_neg_integer(),
          required(:headers) => Headers.t(),
          required(:body) => binary()
        }

  @type event :: {:headers, non_neg_integer(), Headers.t()} | {:body, binary()} | :done

  @spec request(Request.t()) :: {:ok, response()} | {:error, term()}
  def request(%Request{} = request) do
    initial = %{status: nil, headers: Headers.new(), chunks: []}

    case request(request, initial, &collect_event/2) do
      {:ok, %{status: status, headers: headers, chunks: chunks}} when is_integer(status) ->
        body = chunks |> Enum.reverse() |> IO.iodata_to_binary()
        {:ok, %{status: status, headers: headers, body: body}}

      {:ok, _state} ->
        {:error, :invalid_http_response}

      {:error, reason, _state} ->
        {:error, reason}
    end
  end

  @spec request(Request.t(), acc, (acc, event() ->
                                     {:cont, acc} | {:halt, acc} | {:error, term(), acc})) ::
          {:ok, acc} | {:error, term(), acc}
        when acc: term()
  def request(%Request{url: %URI{scheme: "https", host: host} = uri} = request, state, handler)
      when is_binary(host) and is_function(handler, 2) do
    timeout = request_timeout(request)
    connect_timeout = connect_timeout(request, timeout)

    case ensure_started() do
      :ok ->
        case connect(uri, request, connect_timeout) do
          {:ok, conn} ->
            try do
              do_request(conn, request, state, handler, timeout)
            after
              :ok = close(conn)
            end

          {:error, reason} ->
            {:error, reason, state}
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  def request(%Request{url: %URI{scheme: scheme}}, state, _handler),
    do: {:error, {:http3_requires_https, scheme}, state}

  def request(%Request{}, state, _handler), do: {:error, :invalid_http3_url, state}

  defp ensure_started do
    case Application.ensure_all_started(:quic) do
      {:ok, _apps} -> :ok
      {:error, reason} -> {:error, {:quic_start_failed, reason}}
    end
  end

  defp connect(uri, request, connect_timeout) do
    case :quic_h3.connect(uri.host, port(uri), connect_options(request)) do
      {:ok, conn} ->
        await_connected(conn, connect_timeout)

      {:error, _reason} = error ->
        error
    end
  end

  defp await_connected(conn, connect_timeout) do
    receive do
      {:quic_h3, ^conn, :connected} ->
        {:ok, conn}

      :abort ->
        :ok = close(conn)
        {:error, :aborted}
    after
      connect_timeout ->
        :ok = close(conn)
        {:error, :connect_timeout}
    end
  end

  defp port(%URI{port: port}) when is_integer(port) and port in 1..65_535, do: port
  defp port(%URI{}), do: 443

  defp connect_options(%Request{} = request), do: ssl_options(request)

  defp ssl_options(%Request{} = request) do
    request.transport_options
    |> Keyword.get(:ssl, [])
    |> Enum.reduce(%{}, fn
      {:verify, :verify_none}, acc ->
        Map.put(acc, :verify, :verify_none)

      {:verify, :verify_peer}, acc ->
        Map.put(acc, :verify, :verify_peer)

      {:cacerts, cacerts}, acc ->
        Map.put(acc, :cacerts, cacerts)

      {:cert, cert}, acc ->
        Map.put(acc, :cert, cert)

      {:key, key}, acc ->
        Map.put(acc, :key, key)

      {_key, _value}, acc ->
        acc
    end)
  end

  defp do_request(conn, request, state, handler, timeout) do
    deadline_at = System.monotonic_time(:millisecond) + timeout
    {headers, body} = request |> request_headers() |> Request.put_body_headers(request)

    with {:ok, stream_id} <-
           :quic_h3.request(
             conn,
             pseudo_headers(request) ++ regular_headers(headers),
             request_options(body)
           ),
         :ok <- send_body(conn, stream_id, body, deadline_at),
         {:ok, state} <- await_response(conn, stream_id, state, handler, deadline_at) do
      {:ok, state}
    else
      {:error, reason, state} -> {:error, reason, state}
      {:error, reason} -> {:error, reason, state}
    end
  rescue
    error -> {:error, error, state}
  end

  defp send_body(_conn, _stream_id, "", _deadline_at), do: :ok

  defp send_body(conn, stream_id, body, deadline_at) do
    body
    |> IO.iodata_to_binary()
    |> send_body_chunks(conn, stream_id, deadline_at)
  end

  defp send_body_chunks("", _conn, _stream_id, _deadline_at), do: :ok

  defp send_body_chunks(body, conn, stream_id, deadline_at) do
    chunk_size = min(byte_size(body), @request_body_chunk_size)
    <<chunk::binary-size(chunk_size), rest::binary>> = body
    fin? = rest == ""

    with :ok <- send_body_chunk(conn, stream_id, chunk, fin?, deadline_at) do
      send_body_chunks(rest, conn, stream_id, deadline_at)
    end
  end

  defp send_body_chunk(conn, stream_id, chunk, fin?, deadline_at) do
    case :quic_h3.send_data(conn, stream_id, chunk, fin?) do
      :ok ->
        :ok

      {:error, {:flow_control_blocked, _reason}} ->
        with :ok <- wait_for_send_window(deadline_at) do
          send_body_chunk(conn, stream_id, chunk, fin?, deadline_at)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp wait_for_send_window(deadline_at) do
    timeout = min(remaining_timeout(deadline_at), @flow_control_retry_interval)

    if timeout <= 0 do
      {:error, :request_timeout}
    else
      receive do
        :abort -> {:error, :aborted}
      after
        timeout -> :ok
      end
    end
  end

  defp request_options(""), do: %{end_stream: true}
  defp request_options(_body), do: %{end_stream: false}

  defp await_response(conn, stream_id, state, handler, deadline_at) do
    with {:ok, status, headers} <- await_headers(conn, stream_id, deadline_at),
         {:cont, state} <- emit(handler, state, {:headers, status, Headers.new(headers)}) do
      await_body(conn, stream_id, state, handler, deadline_at)
    else
      {:halt, state} -> {:ok, state}
      {:error, reason, state} -> {:error, reason, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp await_headers(conn, stream_id, deadline_at) do
    receive do
      {:quic_h3, ^conn, {:response, ^stream_id, status, headers}} ->
        if status in 100..199 do
          await_headers(conn, stream_id, deadline_at)
        else
          {:ok, status, normalize_headers(headers)}
        end

      {:quic_h3, ^conn, {:stream_reset, ^stream_id, reason}} ->
        {:error, {:stream_reset, reason}}

      :abort ->
        {:error, :aborted}

      {:quic_h3, ^conn, {:error, reason}} ->
        {:error, reason}

      {:quic_h3, ^conn, {:closed, reason}} ->
        {:error, {:closed, reason}}
    after
      remaining_timeout(deadline_at) -> {:error, :request_timeout}
    end
  end

  defp await_body(conn, stream_id, state, handler, deadline_at) do
    receive do
      {:quic_h3, ^conn, {:data, ^stream_id, data, true}} ->
        with {:cont, state} <- emit(handler, state, {:body, data}),
             {:cont, state} <- emit(handler, state, :done) do
          {:ok, state}
        else
          {:halt, state} -> {:ok, state}
          {:error, reason, state} -> {:error, reason, state}
        end

      {:quic_h3, ^conn, {:data, ^stream_id, data, false}} ->
        case emit(handler, state, {:body, data}) do
          {:cont, state} -> await_body(conn, stream_id, state, handler, deadline_at)
          {:halt, state} -> {:ok, state}
          {:error, reason, state} -> {:error, reason, state}
        end

      {:quic_h3, ^conn, {:trailers, ^stream_id, _trailers}} ->
        case emit(handler, state, :done) do
          {:cont, state} -> {:ok, state}
          {:halt, state} -> {:ok, state}
          {:error, reason, state} -> {:error, reason, state}
        end

      {:quic_h3, ^conn, {:stream_reset, ^stream_id, reason}} ->
        {:error, {:stream_reset, reason}}

      {:quic_h3, ^conn, {:goaway, _stream_id}} ->
        await_body(conn, stream_id, state, handler, deadline_at)

      :abort ->
        {:error, :aborted}

      {:quic_h3, ^conn, {:error, reason}} ->
        {:error, reason}

      {:quic_h3, ^conn, {:closed, reason}} ->
        {:error, {:closed, reason}}
    after
      remaining_timeout(deadline_at) -> {:error, :request_timeout}
    end
  end

  defp emit(handler, state, event) do
    case handler.(state, event) do
      {:cont, state} -> {:cont, state}
      {:halt, state} -> {:halt, state}
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp collect_event(state, {:headers, status, headers}) do
    {:cont, %{state | status: status, headers: headers}}
  end

  defp collect_event(state, {:body, chunk}) do
    {:cont, %{state | chunks: [chunk | state.chunks]}}
  end

  defp collect_event(state, :done), do: {:halt, state}

  defp close(conn) do
    :quic_h3.close(conn)
  catch
    _kind, _reason -> :ok
  end

  defp request_headers(%Request{} = request) do
    request.headers
    |> Request.reject_unsupported_request_framing!()
    |> Headers.set_default("User-Agent", Headers.user_agent())
  end

  defp pseudo_headers(%Request{} = request) do
    [
      {":method", Request.method_token(request.method)},
      {":scheme", "https"},
      {":authority", Request.authority(request.url)},
      {":path", Request.origin_form(request.url)}
    ]
    |> encode_headers()
  end

  defp regular_headers(%Headers{} = headers) do
    headers.headers
    |> Enum.reduce([], fn {name, value}, acc ->
      name = String.downcase(to_string(name))
      value = to_string(value)

      if request_header_allowed?(name, value) do
        [{name, value} | acc]
      else
        acc
      end
    end)
    |> Enum.reverse()
    |> encode_headers()
  end

  defp request_header_allowed?(name, _value)
       when name in [
              "connection",
              "host",
              "keep-alive",
              "proxy-connection",
              "transfer-encoding",
              "upgrade"
            ] do
    false
  end

  defp request_header_allowed?("te", value), do: String.downcase(String.trim(value)) == "trailers"
  defp request_header_allowed?(_name, _value), do: true

  defp normalize_headers(headers) do
    headers
    |> Enum.reject(fn {name, _value} -> String.starts_with?(to_string(name), ":") end)
    |> Enum.map(fn {name, value} ->
      {name |> to_string() |> Headers.normalize_name(), to_string(value)}
    end)
  end

  defp encode_headers(headers) do
    Enum.map(headers, fn {name, value} ->
      {to_string(name), to_string(value)}
    end)
  end

  defp request_timeout(%Request{} = request),
    do: Keyword.get(request.transport_options, :timeout, 30_000)

  defp connect_timeout(%Request{} = request, timeout),
    do: Keyword.get(request.transport_options, :connect_timeout, min(timeout, 30_000))

  defp remaining_timeout(deadline_at) do
    max(deadline_at - System.monotonic_time(:millisecond), 0)
  end
end
