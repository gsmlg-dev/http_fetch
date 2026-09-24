defmodule HTTP.HTTP2.Settings do
  @moduledoc "Pure, directional HTTP/2 SETTINGS state."

  @max_window 2_147_483_647
  @ids %{
    1 => :header_table_size,
    2 => :enable_push,
    3 => :max_concurrent_streams,
    4 => :initial_window_size,
    5 => :max_frame_size,
    6 => :max_header_list_size
  }
  @keys Map.new(@ids, fn {id, key} -> {key, id} end)
  @default %{
    header_table_size: 4096,
    enable_push: 1,
    max_concurrent_streams: :infinity,
    initial_window_size: 65_535,
    max_frame_size: 16_384,
    max_header_list_size: :infinity
  }
  defstruct values: @default, pending_ack?: false, last_entries: []
  @type entry :: {atom() | non_neg_integer(), non_neg_integer()}
  @type t :: %__MODULE__{values: map(), pending_ack?: boolean(), last_entries: [entry()]}

  def new(opts \\ []),
    do: %__MODULE__{values: Map.merge(@default, Keyword.get(opts, :values, %{}))}

  def defaults, do: @default
  def id(key) when is_atom(key), do: Map.get(@keys, key)
  def key(id) when is_integer(id), do: Map.get(@ids, id)

  def encode(entries) when is_list(entries) do
    with :ok <- validate_entries(entries) do
      {:ok, IO.iodata_to_binary(for {id, value} <- entries, do: <<wire_id(id)::16, value::32>>)}
    end
  end

  def encode(_), do: {:error, :invalid_settings}

  def decode(payload) when is_binary(payload) and rem(byte_size(payload), 6) == 0 do
    {:ok, for(<<id::16, value::32 <- payload>>, do: {Map.get(@ids, id, id), value})}
  end

  def decode(_), do: {:error, :invalid_settings_length}

  def apply(%__MODULE__{} = state, entries), do: apply_peer(state, entries)

  def apply_peer(%__MODULE__{} = state, entries) when is_list(entries) do
    with :ok <- validate_entries(entries) do
      old = state.values
      values = Enum.reduce(entries, old, &put_value/2)

      {:ok, %{state | values: values, last_entries: entries, pending_ack?: false},
       %{
         old: old,
         new: values,
         initial_window_delta: values.initial_window_size - old.initial_window_size
       }}
    end
  end

  def apply_peer(_, _), do: {:error, :invalid_settings}

  def begin_local(%__MODULE__{} = state, entries) do
    with :ok <- validate_entries(entries) do
      values = Enum.reduce(entries, state.values, &put_value/2)
      {:ok, %{state | values: values, last_entries: entries, pending_ack?: true}}
    end
  end

  def ack(%__MODULE__{pending_ack?: true} = state), do: {:ok, %{state | pending_ack?: false}}
  def ack(%__MODULE__{pending_ack?: false}), do: {:error, :unexpected_settings_ack}
  def validate(entries) when is_list(entries), do: validate_entries(entries)
  def validate(_), do: {:error, :invalid_settings}

  defp wire_id(id) when is_integer(id) and id in 0..65_535, do: id
  defp wire_id(key) when is_atom(key), do: Map.fetch!(@keys, key)

  defp put_value({key, value}, values) when is_atom(key),
    do: Map.put(values, key, normalize(key, value))

  defp put_value({key, value}, values) when is_integer(key) do
    case Map.get(@ids, key) do
      nil -> values
      atom -> Map.put(values, atom, normalize(atom, value))
    end
  end

  defp put_value({_unknown, _value}, values), do: values
  defp normalize(_, value), do: value

  defp validate_entries(entries) do
    Enum.reduce_while(entries, :ok, fn {id, value}, _ ->
      case validate_entry(id, value) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_entry(id, value) when is_integer(value) and value >= 0 do
    numeric_id = if is_atom(id), do: Map.get(@keys, id), else: id

    cond do
      not is_integer(numeric_id) or numeric_id not in 0..65_535 ->
        {:error, :invalid_settings_entry}

      numeric_id == 2 and value not in [0, 1] ->
        {:error, :invalid_enable_push}

      numeric_id == 4 and value > @max_window ->
        {:error, :invalid_initial_window_size}

      numeric_id == 5 and value not in 16_384..16_777_215 ->
        {:error, :invalid_max_frame_size}

      true ->
        :ok
    end
  end

  defp validate_entry(_, _), do: {:error, :invalid_settings_entry}
end
