defmodule HTTP.RequestError do
  @moduledoc """
  Opt-in failure evidence returned with `error_mode: :structured`.

  `reason` retains the original error. `phase: :connect` and
  `request_started: false` prove that the TCP connection failed before it was
  established, for direct TCP and OTP TLS routes using `redirect: :manual` or
  `:error`. Automatic redirect chains always give conservative evidence.
  `phase: :tls_setup` confirms a fatal handshake or certificate alert after
  ServerHello and before HTTP transmission on a direct, unpooled HTTP/1 OTP
  TLS route. It requires the ordinary handshake (no custom `handshake` or
  `early_data` option) and tracking of both TLS processes before continuation.
  Await cleanup separately before trying another validated pin.

  All other failures report
  `phase: :unknown` and `request_started: :unknown`, including earlier TLS failures,
  pooled connections, cancellation, source/send/response errors, and deadlines
  whose connection state cannot be confirmed. ExSSL failures are conservative.

  `pre_send?/1` identifies the only evidence suitable for caller-managed
  validated-address failover. Fetch never retries an attempt automatically.
  The caller must preserve its original absolute deadline and cancellation
  signal across attempts, and validate every address before providing a pin.
  A stream stopped by a failed attempt must be replaced for another attempt.
  This evidence does not replace the request cleanup completion barrier.
  """
  defstruct [:reason, phase: :unknown, request_started: :unknown]

  @type t :: %__MODULE__{
          reason: term(),
          phase: :connect | :tls_setup | :unknown,
          request_started: false | :unknown
        }

  @doc "True only for a confirmed TCP or TLS setup failure before HTTP transmission."
  @spec pre_send?(term()) :: boolean()
  def pre_send?(%__MODULE__{phase: phase, request_started: false})
      when phase in [:connect, :tls_setup],
      do: true

  def pre_send?(_error), do: false

  @doc false
  def new({:connect_failure, token, reason}, token) when is_reference(token),
    do: %__MODULE__{reason: reason, phase: :connect, request_started: false}

  def new({:tls_setup_failure, token, reason}, token) when is_reference(token),
    do: %__MODULE__{reason: reason, phase: :tls_setup, request_started: false}

  def new(reason, _token), do: %__MODULE__{reason: reason}
end
