defmodule HTTP.Retry do
  @moduledoc false

  # Request-scoped retry policy for `HTTP.fetch/2`. The policy is validated in
  # the caller; classification and delays run in the Promise worker between
  # attempts. The `retry`, `max_retries` and `retry_delay` options are
  # documented on `HTTP.fetch/2` and `HTTP.FetchOptions`.

  @default_max_retries 3
  @default_base_delay 500
  @max_default_delay 10_000

  @idempotent_methods ~w(GET HEAD OPTIONS PUT DELETE TRACE)
  @transient_statuses [408, 429, 500, 502, 503, 504]
  @retry_after_statuses [429, 503]

  # Failures where no response was received from the peer.
  @transport_reasons [
    :econnrefused,
    :connect_timeout,
    :closed,
    :econnreset,
    :ehostunreach,
    :enetunreach
  ]

  @months ~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)

  defstruct mode: :transient, max_retries: @default_max_retries, delay: nil

  @type mode ::
          :transient
          | :safe_transient
          | (HTTP.Request.t(), HTTP.Response.t() | {:error, term()} -> boolean())
  @type t :: %__MODULE__{
          mode: mode(),
          max_retries: non_neg_integer(),
          delay: non_neg_integer() | (pos_integer() -> non_neg_integer()) | nil
        }

  @doc false
  @spec normalize(term(), term(), term()) :: t() | nil
  def normalize(retry, max_retries, delay) do
    mode = normalize_mode(retry)
    max_retries = normalize_max_retries(max_retries)
    delay = normalize_delay(delay)

    if mode, do: %__MODULE__{mode: mode, max_retries: max_retries, delay: delay}
  end

  defp normalize_mode(value) when value in [nil, false], do: nil
  defp normalize_mode(value) when value in [:transient, "transient"], do: :transient

  defp normalize_mode(value) when value in [:safe_transient, "safe_transient"],
    do: :safe_transient

  defp normalize_mode(fun) when is_function(fun, 2), do: fun

  defp normalize_mode(value),
    do:
      raise(
        ArgumentError,
        "invalid retry: #{inspect(value)}; expected false, :transient, :safe_transient " <>
          "or a 2-arity function"
      )

  @doc false
  @spec normalize_max_retries(non_neg_integer() | nil) :: non_neg_integer()
  def normalize_max_retries(nil), do: @default_max_retries
  def normalize_max_retries(value) when is_integer(value) and value >= 0, do: value

  def normalize_max_retries(value),
    do:
      raise(
        ArgumentError,
        "invalid max_retries: #{inspect(value)}; expected a non-negative integer"
      )

  defp normalize_delay(nil), do: nil
  defp normalize_delay(value) when is_integer(value) and value >= 0, do: value
  defp normalize_delay(fun) when is_function(fun, 1), do: fun

  defp normalize_delay(value),
    do:
      raise(
        ArgumentError,
        "invalid retry_delay: #{inspect(value)}; expected non-negative milliseconds " <>
          "or a 1-arity function"
      )

  @doc false
  @spec default_delay(pos_integer()) :: non_neg_integer()
  def default_delay(retry) when is_integer(retry) and retry > 0,
    do: min(@default_base_delay * Integer.pow(2, retry - 1), @max_default_delay)

  @doc """
  Decides whether attempt number `attempt` (1-based) is retried.

  Returns `{:retry, delay_ms, reason}` or `:stop`. `result` carries the public
  reason for failures. `remaining` is the request deadline budget in
  milliseconds or `:infinity`.
  """
  @spec decide(t(), HTTP.Request.t(), term(), pos_integer(), non_neg_integer() | :infinity) ::
          {:retry, non_neg_integer(), non_neg_integer() | term()} | :stop
  def decide(%__MODULE__{} = policy, request, result, attempt, remaining) do
    if attempt <= policy.max_retries and replayable?(request, result) and
         retry?(policy.mode, request, result) do
      delay = delay(policy, result, attempt)

      if remaining == :infinity or delay < remaining,
        do: {:retry, delay, reason(result)},
        else: :stop
    else
      :stop
    end
  end

  # Hard rules that a custom function cannot override.
  defp replayable?(%HTTP.Request{body: body, duplex: duplex}, result) do
    not is_pid(body) and duplex != :half and
      result not in [{:error, :aborted}, {:error, :timeout}]
  end

  defp retry?(:transient, request, %HTTP.Response{status: status}),
    do: status in @transient_statuses and idempotent?(request)

  defp retry?(:safe_transient, _request, %HTTP.Response{}), do: false

  defp retry?(mode, request, {:error, reason}) when mode in [:transient, :safe_transient],
    do: reason in @transport_reasons and idempotent?(request)

  defp retry?(fun, request, result) when is_function(fun, 2) do
    case fun.(request, result) do
      decision when is_boolean(decision) ->
        decision

      other ->
        raise ArgumentError, "retry function must return a boolean, got: #{inspect(other)}"
    end
  end

  defp idempotent?(%HTTP.Request{method: method}),
    do: (method |> HTTP.Request.method_token() |> String.upcase()) in @idempotent_methods

  defp delay(policy, %HTTP.Response{status: status} = response, attempt)
       when status in @retry_after_statuses do
    case HTTP.Headers.get(response.headers, "retry-after") do
      value when is_binary(value) ->
        case retry_after(value, DateTime.utc_now()) do
          {:ok, delay} -> delay
          :error -> configured_delay(policy.delay, attempt)
        end

      _ ->
        configured_delay(policy.delay, attempt)
    end
  end

  defp delay(policy, _result, attempt), do: configured_delay(policy.delay, attempt)

  defp configured_delay(nil, attempt), do: default_delay(attempt)
  defp configured_delay(delay, _attempt) when is_integer(delay), do: delay

  defp configured_delay(fun, attempt) do
    case fun.(attempt) do
      delay when is_integer(delay) and delay >= 0 ->
        delay

      other ->
        raise ArgumentError,
              "retry_delay function must return non-negative milliseconds, got: #{inspect(other)}"
    end
  end

  defp reason(%HTTP.Response{status: status}), do: status
  defp reason({:error, reason}), do: reason

  @doc """
  Parses a `Retry-After` value (RFC 9110 delta-seconds or HTTP-date) into a
  non-negative delay in milliseconds relative to `now`.
  """
  @spec retry_after(String.t(), DateTime.t()) :: {:ok, non_neg_integer()} | :error
  def retry_after(value, %DateTime{} = now) when is_binary(value) do
    value = String.trim(value)

    if value =~ ~r/\A[0-9]+\z/ do
      {:ok, String.to_integer(value) * 1_000}
    else
      with {:ok, date} <- http_date(value),
           do: {:ok, max(DateTime.diff(date, now, :millisecond), 0)}
    end
  end

  # IMF-fixdate, obsolete RFC 850 and asctime forms (RFC 9110 section 5.6.7).
  defp http_date(value) do
    patterns = [
      ~r/\A[A-Z][a-z]{2}, (?<d>\d{2}) (?<mon>[A-Z][a-z]{2}) (?<y>\d{4}) (?<t>\d{2}:\d{2}:\d{2}) GMT\z/,
      ~r/\A[A-Z][a-z]+, (?<d>\d{2})-(?<mon>[A-Z][a-z]{2})-(?<y>\d{2}) (?<t>\d{2}:\d{2}:\d{2}) GMT\z/,
      ~r/\A[A-Z][a-z]{2} (?<mon>[A-Z][a-z]{2}) (?<d>[ \d]\d) (?<t>\d{2}:\d{2}:\d{2}) (?<y>\d{4})\z/
    ]

    case Enum.find_value(patterns, &Regex.named_captures(&1, value)) do
      %{"y" => year, "mon" => month, "d" => day, "t" => time} ->
        year = if byte_size(year) == 2, do: rfc850_year(year), else: String.to_integer(year)
        [hour, minute, second] = time |> String.split(":") |> Enum.map(&String.to_integer/1)
        day = day |> String.trim() |> String.to_integer()
        build_date(year, month, day, {hour, minute, second})

      nil ->
        :error
    end
  end

  # RFC 9110: a two-digit year more than 50 years in the future is in the past century.
  defp rfc850_year(year) do
    current = DateTime.utc_now().year
    candidate = div(current, 100) * 100 + String.to_integer(year)
    if candidate > current + 50, do: candidate - 100, else: candidate
  end

  defp build_date(year, month, day, {hour, minute, second}) do
    with index when is_integer(index) <- Enum.find_index(@months, &(&1 == month)),
         {:ok, naive} <- NaiveDateTime.new(year, index + 1, day, hour, minute, second) do
      {:ok, DateTime.from_naive!(naive, "Etc/UTC")}
    else
      _ -> :error
    end
  end
end
