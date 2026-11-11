defmodule HTTP.H3.Capsule do
  @moduledoc """
  Incremental bounded RFC 9297 capsules. Known capsules are limited to
  `max_capsule_bytes`; unknown payloads of any length are skipped without retention.
  """
  alias HTTP.H3.Varint
  defstruct prefix: <<>>, frame: nil, max_capsule_bytes: 65_536, known_types: [0x2843, 0x78AE]

  def new(opts \\ []), do: struct!(__MODULE__, opts)

  def retained_bytes(state),
    do: byte_size(state.prefix) + if(state.frame, do: byte_size(elem(state.frame, 2)), else: 0)

  def encode(type, payload) when is_binary(payload) do
    with {:ok, type} <- Varint.encode(type),
         {:ok, length} <- Varint.encode(byte_size(payload)),
         do: {:ok, type <> length <> payload}
  end

  def feed(state, bytes) when is_binary(bytes), do: parse(state, bytes, [])
  def finish(%{prefix: <<>>, frame: nil}), do: :ok
  def finish(_), do: {:error, :truncated_capsule}

  defp parse(%{frame: nil} = state, bytes, events) do
    input = state.prefix <> bytes

    with {:ok, type, rest} <- Varint.decode(input),
         {:ok, length, rest} <- Varint.decode(rest) do
      # Only retained (known) capsules are bounded; unknown ones are skipped.
      if length <= state.max_capsule_bytes or type not in state.known_types,
        do: parse(%{state | prefix: <<>>, frame: {type, length, <<>>}}, rest, events),
        else: {:error, :capsule_too_large}
    else
      :more -> {:ok, %{state | prefix: :binary.copy(input)}, Enum.reverse(events)}
    end
  end

  defp parse(%{frame: {type, 0, payload}} = state, bytes, events) do
    events = if type in state.known_types, do: [{:capsule, type, payload} | events], else: events
    parse(%{state | frame: nil}, bytes, events)
  end

  defp parse(state, <<>>, events), do: {:ok, state, Enum.reverse(events)}

  defp parse(%{frame: {type, left, payload}} = state, bytes, events) do
    size = min(left, byte_size(bytes))
    <<chunk::binary-size(^size), rest::binary>> = bytes
    payload = if type in state.known_types, do: payload <> chunk, else: <<>>
    parse(%{state | frame: {type, left - size, payload}}, rest, events)
  end
end
