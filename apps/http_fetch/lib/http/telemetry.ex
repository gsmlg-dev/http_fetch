defmodule HTTP.Telemetry do
  @moduledoc """
  Telemetry integration for comprehensive HTTP request and response monitoring.

  This module provides automatic telemetry event emission for all HTTP operations,
  enabling observability, metrics collection, and performance monitoring. All
  events use the `[:http_fetch, ...]` prefix.

  ## Automatic Events

  All `HTTP.fetch/2` operations automatically emit telemetry events. No
  configuration is required - simply attach handlers to receive events.

  Request metadata contains only finite method, scheme, protocol and error
  categories plus numeric status. Headers and all URI components (including
  host, path, userinfo, query and fragment) are omitted. Arbitrary exception
  details are replaced with `:request_failed`.

  Pass `telemetry: false` to `HTTP.fetch/2` to suppress request events and its
  response streams and internally created upload streams/bridges. A producer
  stream created independently before the request has its own telemetry setting.
  Shared HTTP/2 connection/pool events contain only safe aggregate measurements
  and finite categories and remain independent of a single request's option.
  For a strict global opt-out, configure `config :http_fetch, telemetry: false`;
  this suppresses both `[:http_fetch, ...]` and the shared runtime's
  `[:http_runtime, ...]` events, including other clients using that runtime.
  `config :http_runtime, telemetry: false` independently suppresses all shared
  runtime events. The bundled TLS and QUIC engines emit no telemetry events.

  ## Event Types

  ### Request Events

  **`[:http_fetch, :request, :start]`** - Emitted when a request begins

  - Measurements: `%{start_time: integer}` (microseconds)
  - Metadata: `%{method: atom, scheme: :http | :https | :other}`

  **`[:http_fetch, :request, :stop]`** - Emitted when a request completes successfully

  - Measurements: `%{duration: integer, status: integer, response_size: integer}`
    - `duration` - Request duration in microseconds
    - `status` - HTTP status code
    - `response_size` - Response body size in bytes
  - Metadata: `%{scheme: atom, status: integer, http_version: atom}`

  **`[:http_fetch, :request, :exception]`** - Emitted when a request fails

  - Measurements: `%{duration: integer}` (microseconds)
  - Metadata: `%{scheme: atom, error: atom}`

  ### Streaming Events

  **`[:http_fetch, :streaming, :start]`** - Emitted when response streaming begins

  - Measurements: `%{content_length: integer}` (0 if unknown)
  - Metadata: `%{}`

  **`[:http_fetch, :streaming, :chunk]`** - Emitted for each stream chunk received

  - Measurements: `%{bytes_received: integer, total_bytes: integer}`
  - Metadata: `%{}`

  **`[:http_fetch, :streaming, :stop]`** - Emitted when streaming completes

  - Measurements: `%{total_bytes: integer, duration: integer}` (duration in microseconds)
  - Metadata: `%{}`

  ### Response Body Events

  **`[:http_fetch, :response, :body_read_start]`** - Emitted when reading response body

  - Measurements: `%{content_length: integer}`
  - Metadata: `%{}`

  **`[:http_fetch, :response, :body_read_stop]`** - Emitted when body read completes

  - Measurements: `%{bytes_read: integer, duration: integer}`
  - Metadata: `%{}`

  ### HTTP/2 Runtime Events

  `[:http_fetch, :http2, :connection]` reports `active_streams`, `protocol_streams`,
  `buffered_receive_bytes`, `pending_upload_bytes`, `receive_budget_bytes`,
  and `writer_batch_peak_bytes`. Metadata contains only `event` and
  `lifecycle`; it excludes headers, bodies, URLs, scope and TLS identity.
  Events are emitted on stream admission/release, receive admission/consumption,
  and connection termination. Receive bytes include padding and deliveries
  awaiting application acknowledgement; upload bytes count pending owner slices.
  BodyBridge separately exposes its bounded source-chunk budget through status/1.

  `[:http_fetch, :http2, :pool]` reports aggregate `reservations`, `waiters`,
  `connecting`, `connections`, `draining`, and `queue_wait_us` measurements.
  Metadata contains only finite `event` and `outcome` atoms. Pool keys, URLs,
  request tokens, owner PIDs, and connector identities are excluded.

  `[:http_fetch, :http2, :runtime]` reports connection close, peer reset,
  GOAWAY, and upload flow-control stall events. Metadata contains only fixed
  `event` and `outcome` atoms. Peer error codes and stall durations are numeric
  measurements, never tags. `[:http_fetch, :http2, :body_bridge]` reports a
  bridge's final byte count, peak buffer size, and lifetime in microseconds;
  its `outcome` is a fixed atom, with no source or owner identity.

  ## Usage Example

      # Attach a simple logger handler
      :telemetry.attach_many(
        "http-logger",
        [
          [:http_fetch, :request, :start],
          [:http_fetch, :request, :stop],
          [:http_fetch, :request, :exception]
        ],
        fn event_name, measurements, metadata, _config ->
          case event_name do
            [:http_fetch, :request, :start] ->
              IO.puts("Request started: " <> Atom.to_string(metadata.scheme))

            [:http_fetch, :request, :stop] ->
              duration_ms = measurements.duration / 1000
              IO.puts("Request completed in " <> Float.to_string(duration_ms) <> "ms")

            [:http_fetch, :request, :exception] ->
              IO.puts("Request failed: " <> inspect(metadata.error))
          end
        end,
        nil
      )

  ## Metrics Collection

      # Collect request duration metrics
      :telemetry.attach(
        "http-metrics",
        [:http_fetch, :request, :stop],
        fn _event, measurements, metadata, _config ->
          # Send to your metrics system
          MyMetrics.record_http_request(
            scheme: metadata.scheme,
            status: metadata.status,
            duration_us: measurements.duration
          )
        end,
        nil
      )

  ## Integration with Telemetry.Metrics

      # Define metrics for visualization
      import Telemetry.Metrics

      [
        # Request duration histogram
        distribution("http_fetch.request.duration",
          unit: {:native, :millisecond},
          tags: [:status]
        ),

        # Request count by status
        counter("http_fetch.request.count",
          tags: [:status]
        ),

        # Response size summary
        summary("http_fetch.request.response_size",
          unit: :byte
        ),

        # Streaming throughput
        distribution("http_fetch.streaming.chunk.bytes_received",
          unit: :byte
        )
      ]
  """

  @doc """
  Emits a telemetry event for request start.

  ## Examples
      iex> HTTP.Telemetry.request_start("GET", URI.parse("https://example.com"), %HTTP.Headers{})
      :ok
  """
  @spec request_start(atom() | String.t(), URI.t(), HTTP.Headers.t()) :: :ok
  def request_start(method, url, _headers) do
    measurements = %{start_time: System.system_time(:microsecond)}

    metadata = %{method: safe_method(method), scheme: safe_scheme(url)}

    execute([:http_fetch, :request, :start], measurements, metadata)
  end

  @doc """
  Emits a telemetry event for request completion. Network requests include the
  actual protocol as `metadata.http_version` when supplied.

  ## Examples
      iex> HTTP.Telemetry.request_stop(200, URI.parse("https://example.com"), 1024, 1500)
      :ok
  """
  @spec request_stop(integer(), URI.t(), integer(), integer()) :: :ok
  @spec request_stop(integer(), URI.t(), integer(), integer(), atom() | nil) :: :ok
  def request_stop(status, url, response_size, duration_us, http_version \\ nil) do
    measurements = %{
      duration: duration_us,
      status: status,
      response_size: response_size
    }

    metadata = %{scheme: safe_scheme(url), status: status}

    metadata =
      if http_version,
        do: Map.put(metadata, :http_version, safe_protocol(http_version)),
        else: metadata

    execute([:http_fetch, :request, :stop], measurements, metadata)
  end

  @doc """
  Emits a telemetry event for request failure.

  ## Examples
      iex> HTTP.Telemetry.request_exception(URI.parse("https://example.com"), :timeout, 5000)
      :ok
  """
  @spec request_exception(URI.t(), term(), integer()) :: :ok
  def request_exception(url, error, duration_us) do
    measurements = %{duration: duration_us}
    metadata = %{scheme: safe_scheme(url), error: safe_error(error)}

    execute([:http_fetch, :request, :exception], measurements, metadata)
  end

  @doc """
  Emits a telemetry event for response body reading start.

  ## Examples
      iex> HTTP.Telemetry.response_body_read_start(1024)
      :ok
  """
  @spec response_body_read_start(integer()) :: :ok
  def response_body_read_start(content_length) do
    measurements = %{content_length: content_length}
    execute([:http_fetch, :response, :body_read_start], measurements, %{})
  end

  @doc """
  Emits a telemetry event for response body reading completion.

  ## Examples
      iex> HTTP.Telemetry.response_body_read_stop(1024, 500)
      :ok
  """
  @spec response_body_read_stop(integer(), integer()) :: :ok
  def response_body_read_stop(bytes_read, duration_us) do
    measurements = %{bytes_read: bytes_read, duration: duration_us}
    execute([:http_fetch, :response, :body_read_stop], measurements, %{})
  end

  @doc """
  Emits a telemetry event for streaming start.

  ## Examples
      iex> HTTP.Telemetry.streaming_start(5242880)
      :ok
  """
  @spec streaming_start(integer()) :: :ok
  def streaming_start(content_length) do
    measurements = %{content_length: content_length}
    execute([:http_fetch, :streaming, :start], measurements, %{})
  end

  @doc """
  Emits a telemetry event for streaming chunk received.

  ## Examples
      iex> HTTP.Telemetry.streaming_chunk(8192, 16384)
      :ok
  """
  @spec streaming_chunk(integer(), integer()) :: :ok
  def streaming_chunk(bytes_received, total_bytes) do
    measurements = %{
      bytes_received: bytes_received,
      total_bytes: total_bytes
    }

    execute([:http_fetch, :streaming, :chunk], measurements, %{})
  end

  @doc """
  Emits a telemetry event for streaming completion.

  ## Examples
      iex> HTTP.Telemetry.streaming_stop(5242880, 10000)
      :ok
  """
  @spec streaming_stop(integer(), integer()) :: :ok
  def streaming_stop(total_bytes, duration_us) do
    measurements = %{total_bytes: total_bytes, duration: duration_us}
    execute([:http_fetch, :streaming, :stop], measurements, %{})
  end

  @doc false
  def http2_connection(event, lifecycle, measurements) do
    execute([:http_fetch, :http2, :connection], measurements, %{
      event: event,
      lifecycle: lifecycle
    })
  end

  @doc false
  def http2_pool(event, outcome, measurements) do
    execute([:http_fetch, :http2, :pool], measurements, %{
      event: event,
      outcome: outcome
    })
  end

  @doc false
  def http2_runtime(event, outcome, measurements) do
    execute([:http_fetch, :http2, :runtime], measurements, %{
      event: event,
      outcome: outcome
    })
  end

  @doc false
  def http2_body_bridge(outcome, measurements) do
    execute([:http_fetch, :http2, :body_bridge], measurements, %{outcome: outcome})
  end

  @doc false
  def enabled?(request_enabled \\ true),
    do: request_enabled and Application.get_env(:http_fetch, :telemetry, true) != false

  defp execute(event, measurements, metadata) do
    if enabled?(), do: :telemetry.execute(event, measurements, metadata), else: :ok
  end

  defp safe_scheme(%URI{scheme: "http"}), do: :http
  defp safe_scheme(%URI{scheme: "https"}), do: :https
  defp safe_scheme(_url), do: :other

  defp safe_method(method)
       when method in [:get, :head, :post, :put, :patch, :delete, :options, :connect, :trace],
       do: method

  defp safe_method(method) when is_binary(method) do
    case String.upcase(method) do
      "GET" -> :get
      "HEAD" -> :head
      "POST" -> :post
      "PUT" -> :put
      "PATCH" -> :patch
      "DELETE" -> :delete
      "OPTIONS" -> :options
      "CONNECT" -> :connect
      "TRACE" -> :trace
      _ -> :other
    end
  end

  defp safe_method(_method), do: :other

  defp safe_protocol(value) when value in [:http1, :http2, :http3], do: value
  defp safe_protocol(_value), do: :other

  defp safe_error(value)
       when value in [
              :aborted,
              :timeout,
              :request_timeout,
              :connect_timeout,
              :closed,
              :econnrefused,
              :nxdomain,
              :enetunreach,
              :ehostunreach,
              :redirect,
              :too_many_redirects,
              :invalid_http_response,
              :content_length_mismatch
            ],
       do: value

  defp safe_error(_error), do: :request_failed
end
