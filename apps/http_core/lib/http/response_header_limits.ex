defmodule HTTP.ResponseHeaderLimits do
  @moduledoc """
  Request-local HTTP/1 response and proxy CONNECT header budgets.

  Pass `response_header_limits: [...]` to `HTTP.fetch/2`. Supported positive
  integer limits are `:max_head_bytes` (65,540), `:max_field_bytes` (65,536),
  `:max_fields` (32,768), `:max_connect_head_bytes` (16,384),
  `:max_informational_responses` (16) and `:max_informational_bytes` (1,048,576).
  Head bytes include the status line and terminating CRLFs; field bytes include
  the field name, colon and value, excluding CRLF. Body bytes are not charged.
  Informational counts and bytes accumulate until the final response.

  Failures are `{:response_header_limit, %{stage: :response | :connect,
  limit: atom, maximum: integer, observed: integer}}`. No header values appear
  in this evidence. Callers omitting the option retain the legacy head-limit
  errors; informational responses still have finite default budgets.
  """

  @defaults %{
    max_head_bytes: 65_540,
    max_field_bytes: 65_536,
    max_fields: 32_768,
    max_connect_head_bytes: 16_384,
    max_informational_responses: 16,
    max_informational_bytes: 1_048_576
  }

  @doc false
  def normalize(nil), do: nil

  def normalize(options) when is_map(options), do: normalize(Map.to_list(options))

  def normalize(options) when is_list(options) do
    valid =
      Keyword.keyword?(options) and
        length(options) == length(Enum.uniq_by(options, &elem(&1, 0))) and
        Enum.all?(options, fn {key, value} ->
          Map.has_key?(@defaults, key) and is_integer(value) and value > 0
        end)

    if valid do
      Map.merge(@defaults, Map.new(options))
    else
      raise ArgumentError, "response_header_limits requires known positive integer budgets"
    end
  end

  def normalize(_),
    do: raise(ArgumentError, "response_header_limits must be a keyword list or map")

  @doc false
  def check(options, bytes, stage, head_end \\ nil) do
    limits = options || @defaults
    size = if head_end, do: head_end + 4, else: byte_size(bytes)
    key = if stage == :connect, do: :max_connect_head_bytes, else: :max_head_bytes
    maximum = Map.fetch!(limits, key)

    # Preserve the old parser's partial-head threshold as well as its final
    # threshold (64 KiB before the separator) when no policy was supplied.
    maximum =
      if is_nil(options) and stage == :response and is_nil(head_end),
        do: maximum - 4,
        else: maximum

    with :ok <- check_limit(options, stage, key, maximum, size),
         do: check_fields(options, limits, bytes, head_end, stage)
  end

  defp check_fields(nil, _limits, _bytes, _head_end, _stage), do: :ok

  defp check_fields(options, limits, bytes, head_end, stage) do
    head = if head_end, do: binary_part(bytes, 0, head_end), else: bytes
    [_status | fields] = :binary.split(head, "\r\n", [:global])

    last_index = length(fields) - 1

    fields =
      fields
      |> Enum.with_index()
      |> Enum.reject(fn {field, index} ->
        is_nil(head_end) and index == last_index and field in ["", "\r"]
      end)

    with :ok <- check_limit(options, stage, :max_fields, limits.max_fields, length(fields)) do
      Enum.reduce_while(fields, :ok, fn {field, index}, :ok ->
        partial_cr? = is_nil(head_end) and index == last_index and String.ends_with?(field, "\r")
        size = byte_size(field) - if(partial_cr?, do: 1, else: 0)

        case check_limit(options, stage, :max_field_bytes, limits.max_field_bytes, size) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end)
    end
  end

  @doc false
  def informational(options, stage, count, bytes) do
    limits = options || @defaults

    with :ok <-
           check_limit(
             options,
             stage,
             :max_informational_responses,
             limits.max_informational_responses,
             count
           ),
         do:
           check_limit(
             options,
             stage,
             :max_informational_bytes,
             limits.max_informational_bytes,
             bytes
           )
  end

  defp check_limit(_options, _stage, _key, maximum, observed) when observed <= maximum,
    do: :ok

  defp check_limit(nil, :response, :max_head_bytes, _maximum, _observed),
    do: {:error, :headers_too_large}

  defp check_limit(nil, :connect, :max_connect_head_bytes, _maximum, _observed),
    do: {:error, :proxy_response_too_large}

  defp check_limit(_options, stage, key, maximum, observed),
    do:
      {:error,
       {:response_header_limit, %{stage: stage, limit: key, maximum: maximum, observed: observed}}}
end
