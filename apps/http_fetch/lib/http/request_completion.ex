defmodule HTTP.RequestCompletion do
  @moduledoc """
  A request-scoped cleanup barrier obtained from `HTTP.Promise.completion/1`.

  Supported for HTTP/1 (including reuse) and HTTP/2 requests, manual/error
  redirects, and direct TCP or OTP TLS transport, including explicit HTTP and
  HTTPS proxies. HTTP proxies support HTTP/1 forwarding and HTTP/1 or HTTP/2
  CONNECT tunnels to HTTPS origins. HTTPS proxies support HTTP/1 forwarding to
  HTTP origins. Nested TLS and proxy h2c routes remain unsupported.
  Awaiting the Promise or monitoring its response stream alone does not
  establish request cleanup.

  A finite timeout covers the entire wait. `:ok` confirms termination of tracked
  request resources; `{:error, :cleanup_pending}` leaves cleanup in progress.
  `{:error, :cleanup_unconfirmed}` means evidence was lost (for example, an
  owner died without completing cleanup). Repeated and concurrent waits are safe
  from any process. This barrier does not prove remote receipt of request bytes.
  Pooled completion confirms return of an HTTP/1 connection or release of the
  HTTP/2 stream and reservation; healthy shared connections remain open.
  """
  @opaque t :: %__MODULE__{
            tracker: pid() | nil,
            latch: reference() | nil,
            unsupported: atom() | nil
          }
  defstruct [:tracker, :latch, :unsupported]

  @type result ::
          :ok
          | {:error, :cleanup_pending | :cleanup_unconfirmed | {:unsupported_completion, atom()}}

  @doc false
  @spec new(HTTP.FetchOptions.t(), HTTP.Request.t() | nil) :: %__MODULE__{}
  def new(options, request \\ nil) do
    cond do
      options.http_version not in [:http1, :http2, :h2c] ->
        %__MODULE__{unsupported: :http_version}

      options.redirect == :follow ->
        %__MODULE__{unsupported: :redirect}

      options.proxy != nil and not supported_proxy?(options, request) ->
        %__MODULE__{unsupported: :proxy}

      options.unix_socket != nil ->
        %__MODULE__{unsupported: :unix_socket}

      options.tls_backend == :ex_ssl ->
        %__MODULE__{unsupported: :tls_backend}

      true ->
        {tracker, latch} = HTTP.RequestLifecycle.start()
        %__MODULE__{tracker: tracker, latch: latch}
    end
  end

  defp supported_proxy?(options, %HTTP.Request{} = request) do
    case HTTP.Proxy.route(request, options.unix_socket) do
      {:ok, %{scheme: :http}} ->
        (request.url.scheme == "http" and options.http_version == :http1) or
          (request.url.scheme == "https" and options.http_version in [:http1, :http2])

      {:ok, %{scheme: :https}} ->
        request.url.scheme == "http" and options.http_version == :http1

      _ ->
        false
    end
  end

  defp supported_proxy?(_options, _request), do: false

  @doc "Waits for cleanup with a finite timeout in milliseconds."
  @spec await(t(), non_neg_integer()) :: result()
  def await(handle, timeout \\ 5_000)

  def await(%__MODULE__{unsupported: reason}, timeout)
      when reason != nil and is_integer(timeout) and timeout >= 0,
      do: {:error, {:unsupported_completion, reason}}

  def await(%__MODULE__{} = handle, timeout) when is_integer(timeout) and timeout >= 0 do
    deadline = System.monotonic_time(:millisecond) + timeout
    monitor = Process.monitor(handle.tracker)

    try do
      wait(handle, monitor, deadline)
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  @doc "Cancels this request and awaits cleanup using the same finite deadline."
  @spec abort_and_await(t(), non_neg_integer()) :: result()
  def abort_and_await(handle, timeout \\ 5_000)

  def abort_and_await(%__MODULE__{} = handle, timeout)
      when is_integer(timeout) and timeout >= 0 do
    if handle.tracker, do: send(handle.tracker, :abort)
    await(handle, timeout)
  end

  defp terminal_result(handle) do
    case :atomics.get(handle.latch, 1) do
      2 -> :ok
      _ -> {:error, :cleanup_unconfirmed}
    end
  end

  defp wait(handle, monitor, deadline) do
    case :atomics.get(handle.latch, 1) do
      2 ->
        :ok

      3 ->
        {:error, :cleanup_unconfirmed}

      1 ->
        remaining = max(deadline - System.monotonic_time(:millisecond), 0)

        if remaining == 0 do
          if Process.alive?(handle.tracker),
            do: {:error, :cleanup_pending},
            else: terminal_result(handle)
        else
          receive do
            {:DOWN, ^monitor, :process, _pid, _reason} ->
              case :atomics.get(handle.latch, 1) do
                2 -> :ok
                _ -> {:error, :cleanup_unconfirmed}
              end
          after
            min(remaining, 10) -> wait(handle, monitor, deadline)
          end
        end
    end
  end
end
