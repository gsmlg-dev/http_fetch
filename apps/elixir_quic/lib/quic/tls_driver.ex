defmodule Quic.TLSDriver do
  @moduledoc """
  Serialized adapter around the public `SSL.QUIC` action protocol.

  The driver owns CRYPTO offsets and sparse reassembly.  A TLS adapter is
  injectable for deterministic tests; production defaults to `SSL.QUIC`.
  """

  alias Quic.CryptoReassembly

  @levels [:initial, :handshake, :application]
  @level_order Map.new(Enum.with_index(@levels))
  defstruct [
    :adapter,
    :tls,
    :role,
    levels: %{},
    terminal: nil,
    future_bytes: 0,
    max_future_bytes: 262_144,
    emitted_bytes: 0,
    max_emitted_bytes: 262_144,
    facts: %{
      tls_complete: false,
      peer_authenticated: false,
      peer_transport_parameters: nil,
      peer_parameters_authenticated: false,
      address_validated: false,
      quic_confirmed: false
    }
  ]

  defmodule Emission do
    @moduledoc false
    defstruct [:level, :offset, :bytes]
  end

  @type t :: %__MODULE__{}

  @spec new(:client | :server, keyword()) :: {:ok, t(), list()} | {:error, term()}
  def new(role, opts \\ []) when role in [:client, :server] do
    adapter = Keyword.get(opts, :adapter, SSL.QUIC)

    adapter_opts =
      Keyword.delete(opts, :adapter)
      |> Keyword.delete(:max_crypto_bytes)
      |> Keyword.delete(:max_crypto_intervals)
      |> Keyword.delete(:max_emitted_bytes)

    limits = [
      max_bytes: Keyword.get(opts, :max_crypto_bytes, 262_144),
      max_intervals: Keyword.get(opts, :max_crypto_intervals, 256)
    ]

    max_future_bytes = Keyword.get(opts, :max_crypto_bytes, 262_144)
    max_emitted_bytes = Keyword.get(opts, :max_emitted_bytes, max_future_bytes)

    with {:ok, tls, actions} <- call_new(adapter, role, adapter_opts) do
      state = base(role, adapter, tls, limits, max_future_bytes, max_emitted_bytes)

      case fold_actions(state, actions) do
        {:ok, next, effects} -> {:ok, next, effects}
        {:error, error, _next, _effects} -> {:error, error}
      end
    end
  end

  @spec feed(t(), atom(), non_neg_integer(), binary()) ::
          {:ok, t(), list()} | {:error, term(), t(), list()}
  def feed(%__MODULE__{terminal: terminal} = state, _level, _offset, _bytes)
      when not is_nil(terminal),
      do: {:error, terminal_error(), state, []}

  def feed(%__MODULE__{} = state, level, offset, bytes)
      when level in @levels and is_integer(offset) and offset >= 0 and is_binary(bytes) do
    current = receive_level(state)

    cond do
      state.levels[level].retired -> {:ok, state, []}
      current == nil -> {:error, terminal_error(), state, []}
      order(level) < order(current) -> old_level(state, level, offset, bytes)
      true -> ingest_current(state, level, offset, bytes, current)
    end
  end

  def feed(state, _, _, _),
    do: {:error, %{kind: :configuration, reason: :invalid_input}, state, []}

  def feed_crypto(state, level, offset, bytes), do: feed(state, level, offset, bytes)

  @spec retransmit(t(), atom(), non_neg_integer(), non_neg_integer()) ::
          {:ok, binary()} | {:error, atom()}
  def retransmit(%__MODULE__{} = state, level, offset, length)
      when level in @levels and is_integer(offset) and offset >= 0 and is_integer(length) and
             length >= 0 do
    if state.levels[level].retired do
      {:error, :retired_level}
    else
      emissions = state.levels[level].sent

      case Enum.find(emissions, fn %Emission{offset: start, bytes: bytes} ->
             offset >= start and offset + length <= start + byte_size(bytes)
           end) do
        %Emission{offset: start, bytes: bytes} ->
          {:ok, binary_part(bytes, offset - start, length)}

        nil ->
          {:error, :unknown_crypto_range}
      end
    end
  end

  @doc "Release QUIC-owned CRYPTO buffers without changing the provider's private state."
  @spec retire_level(t(), :initial | :handshake) :: t()
  def retire_level(state, level) when level in [:initial, :handshake] do
    current = state.levels[level]

    if current.retired do
      state
    else
      bytes = Enum.reduce(current.sent, 0, &(byte_size(&1.bytes) + &2))

      next = %{
        current
        | retired: true,
          pending: <<>>,
          sent: [],
          recv: %{current.recv | intervals: [], buffered_bytes: 0}
      }

      %{
        state
        | levels: Map.put(state.levels, level, next),
          emitted_bytes: state.emitted_bytes - bytes,
          future_bytes: state.future_bytes - byte_size(current.pending)
      }
    end
  end

  def mark_address_validated(state), do: put_in(state.facts.address_validated, true)
  def mark_quic_confirmed(state), do: put_in(state.facts.quic_confirmed, true)
  def facts(%__MODULE__{facts: facts}), do: facts
  def info(%__MODULE__{} = state), do: state.adapter.info(state.tls)

  def abort(%__MODULE__{terminal: nil} = state, reason) do
    %{state | tls: state.adapter.abort(state.tls, reason), terminal: :aborted}
  end

  def abort(state, _reason), do: state

  defp base(role, adapter, tls, limits, max_future_bytes, max_emitted_bytes) do
    levels =
      Map.new(@levels, fn level ->
        {level,
         %{
           retired: false,
           recv: CryptoReassembly.new(limits),
           pending: <<>>,
           sent: [],
           next_send: 0
         }}
      end)

    %__MODULE__{
      role: role,
      adapter: adapter,
      tls: tls,
      levels: levels,
      max_future_bytes: max_future_bytes,
      max_emitted_bytes: max_emitted_bytes
    }
  end

  defp ingest_current(state, level, offset, bytes, current) do
    original = state
    level_state = state.levels[level]

    case CryptoReassembly.put(level_state.recv, offset, bytes) do
      {:error, reason} ->
        {:error, %{kind: :quic, reason: reason}, state, []}

      {:ok, recv, contiguous} ->
        state = put_in(state.levels[level].recv, recv)

        cond do
          order(level) > order(current) ->
            if state.future_bytes + byte_size(contiguous) > state.max_future_bytes do
              {:error, %{kind: :quic, reason: :future_crypto_buffer_limit}, original, []}
            else
              next =
                put_in(state.levels[level].pending, state.levels[level].pending <> contiguous)

              {:ok, %{next | future_bytes: state.future_bytes + byte_size(contiguous)}, []}
            end

          contiguous == <<>> ->
            {:ok, state, []}

          true ->
            apply_tls(state, level, contiguous)
        end
    end
  end

  defp old_level(state, level, offset, bytes) do
    case CryptoReassembly.put(state.levels[level].recv, offset, bytes) do
      {:ok, recv, <<>>} -> {:ok, put_in(state.levels[level].recv, recv), []}
      {:ok, _recv, _bytes} -> {:error, %{kind: :quic, reason: :wrong_encryption_level}, state, []}
      {:error, reason} -> {:error, %{kind: :quic, reason: reason}, state, []}
    end
  end

  defp apply_tls(state, level, bytes) do
    case state.adapter.feed(state.tls, level, bytes) do
      {:ok, tls, actions} ->
        with {:ok, folded, effects} <- fold_actions(%{state | tls: tls}, actions),
             {:ok, drained, more} <- drain_pending(folded) do
          {:ok, drained, effects ++ more}
        end

      {:error, error, tls, actions} ->
        next = %{state | tls: tls}

        case fold_actions(next, actions) do
          {:ok, folded, effects} ->
            {:error, error, %{folded | terminal: :failed}, effects}

          {:error, fold_error, folded, effects} ->
            {:error, fold_error, %{folded | terminal: :failed}, effects}
        end
    end
  end

  defp drain_pending(state) do
    current = receive_level(state)

    if current in @levels and not state.levels[current].retired and
         state.levels[current].pending != <<>> do
      bytes = state.levels[current].pending
      state = put_in(state.levels[current].pending, <<>>)
      state = %{state | future_bytes: state.future_bytes - byte_size(bytes)}

      case state.adapter.feed(state.tls, current, bytes) do
        {:ok, tls, actions} ->
          case fold_actions(%{state | tls: tls}, actions) do
            {:ok, folded, effects} -> drain_pending(folded) |> add_effects(effects)
            error -> error
          end

        {:error, error, tls, actions} ->
          next = %{state | tls: tls}

          case fold_actions(next, actions) do
            {:ok, folded, effects} ->
              {:error, error, %{folded | terminal: :failed}, effects}

            {:error, fold_error, folded, effects} ->
              {:error, fold_error, %{folded | terminal: :failed}, effects}
          end
      end
    else
      {:ok, state, []}
    end
  end

  defp add_effects({:ok, state, effects}, prior), do: {:ok, state, prior ++ effects}
  defp add_effects(error, _prior), do: error

  defp fold_actions(state, actions) when is_list(actions) do
    Enum.reduce_while(actions, {:ok, state, []}, fn action, {:ok, current, effects} ->
      case action do
        {:emit, level, bytes} when level in @levels and is_binary(bytes) ->
          cond do
            current.levels[level].retired ->
              {:halt, {:error, %{kind: :quic, reason: :retired_level}, current, effects}}

            current.emitted_bytes + byte_size(bytes) > current.max_emitted_bytes ->
              {:halt, {:error, %{kind: :quic, reason: :tls_output_limit}, current, effects}}

            true ->
              emission = %Emission{
                level: level,
                offset: current.levels[level].next_send,
                bytes: bytes
              }

              level_state = current.levels[level]

              next_level = %{
                level_state
                | next_send: emission.offset + byte_size(bytes),
                  sent: level_state.sent ++ [emission]
              }

              next = put_in(current.levels[level], next_level)

              {:cont,
               {:ok, %{next | emitted_bytes: current.emitted_bytes + byte_size(bytes)},
                effects ++ [action]}}
          end

        :handshake_complete ->
          {:cont, {:ok, put_in(current.facts.tls_complete, true), effects ++ [action]}}

        {:peer_authenticated, _} ->
          {:cont, {:ok, put_in(current.facts.peer_authenticated, true), effects ++ [action]}}

        {:peer_transport_parameters, bytes, status}
        when is_binary(bytes) and status in [:unverified, :authenticated] ->
          facts = %{
            current.facts
            | peer_transport_parameters: bytes,
              peer_parameters_authenticated: status == :authenticated
          }

          {:cont, {:ok, %{current | facts: facts}, effects ++ [action]}}

        %SSL.QUIC.Secret{} ->
          {:cont, {:ok, current, effects ++ [action]}}

        {:negotiated_alpn, _} ->
          {:cont, {:ok, current, effects ++ [action]}}

        {:error, error} ->
          {:halt, {:error, error, current, effects ++ [action]}}

        _ ->
          {:halt, {:error, %{kind: :quic, reason: :invalid_tls_action}, current, effects}}
      end
    end)
  end

  defp call_new(adapter, role, opts), do: adapter.new(role, opts)
  defp receive_level(state), do: state.adapter.info(state.tls).receive_level
  defp order(level), do: Map.fetch!(@level_order, level)
  defp terminal_error, do: %{kind: :closed, reason: :terminal}
end
