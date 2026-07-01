defmodule HTTP.HTTP3 do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.Request

  @type response :: %{
          required(:status) => non_neg_integer(),
          required(:headers) => Headers.t(),
          required(:body) => binary()
        }

  @spec request(Request.t()) :: {:ok, response()} | {:error, term()}
  def request(%Request{url: %URI{scheme: "https", host: host} = uri} = request)
      when is_binary(host) do
    timeout = request_timeout(request)
    connect_timeout = connect_timeout(request, timeout)

    with :ok <- ensure_started(),
         {:ok, conn} <- connect(uri, request, connect_timeout) do
      try do
        do_request(conn, request, timeout)
      after
        :ok = close(conn)
      end
    end
  end

  def request(%Request{url: %URI{scheme: scheme}}), do: {:error, {:http3_requires_https, scheme}}
  def request(%Request{}), do: {:error, :invalid_http3_url}

  defp ensure_started do
    case Application.ensure_all_started(:quic) do
      {:ok, _apps} -> :ok
      {:error, reason} -> {:error, {:quic_start_failed, reason}}
    end
  end

  defp connect(uri, request, connect_timeout) do
    case :quic_h3.connect(uri.host, port(uri), connect_options(request)) do
      {:ok, conn} ->
        case :quic_h3.wait_connected(conn, connect_timeout) do
          :ok ->
            {:ok, conn}

          {:error, :timeout} ->
            :ok = close(conn)
            {:error, :connect_timeout}
        end

      {:error, _reason} = error ->
        error
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

  defp do_request(conn, request, timeout) do
    {headers, body} = request |> request_headers() |> Request.put_body_headers(request)

    with {:ok, stream_id} <-
           :quic_h3.request(
             conn,
             pseudo_headers(request) ++ regular_headers(headers),
             request_options(body)
           ),
         :ok <- send_body(conn, stream_id, body),
         {:ok, status, response_headers, body} <- await_response(conn, stream_id, timeout) do
      {:ok, %{status: status, headers: Headers.new(response_headers), body: body}}
    end
  rescue
    error -> {:error, error}
  end

  defp send_body(_conn, _stream_id, ""), do: :ok

  defp send_body(conn, stream_id, body) do
    :quic_h3.send_data(conn, stream_id, IO.iodata_to_binary(body), true)
  end

  defp request_options(""), do: %{end_stream: true}
  defp request_options(_body), do: %{end_stream: false}

  defp await_response(conn, stream_id, timeout) do
    deadline_at = System.monotonic_time(:millisecond) + timeout

    with {:ok, status, headers} <- await_headers(conn, stream_id, deadline_at) do
      await_body(conn, stream_id, status, headers, [], deadline_at)
    end
  end

  defp await_headers(conn, stream_id, deadline_at) do
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
      remaining_timeout(deadline_at) -> {:error, :request_timeout}
    end
  end

  defp await_body(conn, stream_id, status, headers, chunks, deadline_at) do
    receive do
      {:quic_h3, ^conn, {:data, ^stream_id, data, true}} ->
        {:ok, status, headers, IO.iodata_to_binary(Enum.reverse([data | chunks]))}

      {:quic_h3, ^conn, {:data, ^stream_id, data, false}} ->
        await_body(conn, stream_id, status, headers, [data | chunks], deadline_at)

      {:quic_h3, ^conn, {:trailers, ^stream_id, _trailers}} ->
        {:ok, status, headers, IO.iodata_to_binary(Enum.reverse(chunks))}

      {:quic_h3, ^conn, {:stream_reset, ^stream_id, reason}} ->
        {:error, {:stream_reset, reason}}

      {:quic_h3, ^conn, {:goaway, _stream_id}} ->
        await_body(conn, stream_id, status, headers, chunks, deadline_at)

      {:quic_h3, ^conn, {:error, reason}} ->
        {:error, reason}

      {:quic_h3, ^conn, {:closed, reason}} ->
        {:error, {:closed, reason}}
    after
      remaining_timeout(deadline_at) -> {:error, :request_timeout}
    end
  end

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
