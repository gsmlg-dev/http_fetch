defmodule HTTP.H3.Settings do
  @moduledoc false

  alias HTTP.H3.Varint

  @qpack_max_table_capacity 0x01
  @max_field_section_size 0x06
  @qpack_blocked_streams 0x07
  @enable_connect_protocol 0x08
  @h3_datagram 0x33
  @wt_enabled 0x2C7C_F000
  @wt_initial_max_streams_uni 0x2B64
  @wt_initial_max_streams_bidi 0x2B65
  @wt_initial_max_data 0x2B61
  @max_varint 4_611_686_018_427_387_903

  @setting_ids %{
    qpack_max_table_capacity: @qpack_max_table_capacity,
    max_field_section_size: @max_field_section_size,
    qpack_blocked_streams: @qpack_blocked_streams,
    enable_connect_protocol: @enable_connect_protocol,
    h3_datagram: @h3_datagram,
    wt_enabled: @wt_enabled,
    wt_initial_max_streams_uni: @wt_initial_max_streams_uni,
    wt_initial_max_streams_bidi: @wt_initial_max_streams_bidi,
    wt_initial_max_data: @wt_initial_max_data
  }

  @setting_names Map.new(@setting_ids, fn {name, id} -> {id, name} end)
  @reserved_setting_ids [0x00, 0x02, 0x03, 0x04, 0x05]
  @boolean_setting_ids [@enable_connect_protocol, @h3_datagram, @wt_enabled]

  @type setting_id :: non_neg_integer()
  @type setting :: {setting_id(), non_neg_integer()}
  @type settings :: %{optional(atom() | setting_id()) => non_neg_integer()} | [setting()]

  @spec qpack_max_table_capacity() :: 1
  def qpack_max_table_capacity, do: @qpack_max_table_capacity

  @spec max_field_section_size() :: 6
  def max_field_section_size, do: @max_field_section_size

  @spec qpack_blocked_streams() :: 7
  def qpack_blocked_streams, do: @qpack_blocked_streams

  @spec enable_connect_protocol() :: 8
  def enable_connect_protocol, do: @enable_connect_protocol

  @spec h3_datagram() :: 51
  def h3_datagram, do: @h3_datagram

  @spec wt_enabled() :: 746_385_408
  def wt_enabled, do: @wt_enabled

  @spec wt_initial_max_streams_uni() :: 11_108
  def wt_initial_max_streams_uni, do: @wt_initial_max_streams_uni

  @spec wt_initial_max_streams_bidi() :: 11_109
  def wt_initial_max_streams_bidi, do: @wt_initial_max_streams_bidi

  @spec wt_initial_max_data() :: 11_105
  def wt_initial_max_data, do: @wt_initial_max_data

  @spec name(setting_id()) :: atom() | nil
  def name(setting_id), do: Map.get(@setting_names, setting_id)

  @spec id(atom() | setting_id()) :: {:ok, setting_id()} | {:error, term()}
  def id(setting_name) when is_atom(setting_name) do
    case Map.fetch(@setting_ids, setting_name) do
      {:ok, setting_id} -> {:ok, setting_id}
      :error -> {:error, {:unknown_setting, setting_name}}
    end
  end

  def id(setting_id)
      when is_integer(setting_id) and setting_id >= 0 and setting_id <= @max_varint do
    {:ok, setting_id}
  end

  def id(_setting_id), do: {:error, :invalid_setting_identifier}

  @spec normalize(settings()) :: {:ok, [setting()]} | {:error, term()}
  def normalize(settings) when is_map(settings), do: settings |> Map.to_list() |> normalize()

  def normalize(settings) when is_list(settings) do
    Enum.reduce_while(settings, {:ok, []}, fn setting, {:ok, acc} ->
      case normalize_setting(setting) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      {:error, reason} -> {:error, reason}
    end
  end

  def normalize(_settings), do: {:error, :invalid_settings}

  @spec validate(settings()) :: :ok | {:error, term()}
  def validate(settings) do
    with {:ok, normalized} <- normalize(settings) do
      validate_normalized(normalized)
    end
  end

  @spec encode(settings()) :: {:ok, binary()} | {:error, term()}
  def encode(settings) do
    with {:ok, normalized} <- normalize(settings),
         :ok <- validate_normalized(normalized) do
      encoded =
        Enum.map(normalized, fn {setting_id, value} ->
          [Varint.encode!(setting_id), Varint.encode!(value)]
        end)

      {:ok, IO.iodata_to_binary(encoded)}
    end
  end

  @spec encode!(settings()) :: binary()
  def encode!(settings) do
    case encode(settings) do
      {:ok, encoded} -> encoded
      {:error, reason} -> raise ArgumentError, "invalid HTTP/3 SETTINGS: #{inspect(reason)}"
    end
  end

  @spec decode(binary()) :: {:ok, [setting()]} | {:error, term()}
  def decode(payload) when is_binary(payload), do: decode_settings(payload, [])

  defp normalize_setting({setting_name, value}) do
    with {:ok, setting_id} <- id(setting_name),
         {:ok, value} <- normalize_value(value) do
      {:ok, {setting_id, value}}
    end
  end

  defp normalize_setting(_setting), do: {:error, :invalid_setting}

  defp normalize_value(value) when is_integer(value) and value >= 0 and value <= @max_varint do
    {:ok, value}
  end

  defp normalize_value(_value), do: {:error, :invalid_setting_value}

  defp validate_normalized(settings) do
    with :ok <- reject_duplicate_settings(settings) do
      Enum.reduce_while(settings, :ok, fn {setting_id, value}, :ok ->
        case validate_setting(setting_id, value) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
    end
  end

  defp reject_duplicate_settings(settings) do
    settings
    |> Enum.reduce_while(MapSet.new(), fn {setting_id, _value}, seen ->
      if MapSet.member?(seen, setting_id) do
        {:halt, {:error, {:duplicate_setting, setting_id}}}
      else
        {:cont, MapSet.put(seen, setting_id)}
      end
    end)
    |> case do
      %MapSet{} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_setting(setting_id, _value) when setting_id in @reserved_setting_ids do
    {:error, {:reserved_setting, setting_id}}
  end

  defp validate_setting(setting_id, value)
       when setting_id in @boolean_setting_ids and value not in [0, 1] do
    {:error, {:invalid_setting_value, setting_id, value}}
  end

  defp validate_setting(_setting_id, _value), do: :ok

  defp decode_settings(<<>>, acc) do
    settings = Enum.reverse(acc)

    with :ok <- validate_normalized(settings) do
      {:ok, settings}
    end
  end

  defp decode_settings(payload, acc) do
    with {:ok, setting_id, rest} <- decode_varint(payload, :truncated_setting_identifier),
         {:ok, value, rest} <- decode_varint(rest, :truncated_setting_value) do
      decode_settings(rest, [{setting_id, value} | acc])
    end
  end

  defp decode_varint(payload, truncated_reason) do
    case Varint.decode(payload) do
      {:ok, value, rest} -> {:ok, value, rest}
      :more -> {:error, truncated_reason}
    end
  end
end
