defmodule Quic.TLSDriverTest do
  use ExUnit.Case, async: true

  defmodule RecordedTLS do
    defstruct [:role, :phase, :feeds]

    def new(role, _opts),
      do:
        {:ok, %__MODULE__{role: role, phase: :initial, feeds: []}, [{:emit, :initial, <<1, 2>>}]}

    def info(%__MODULE__{phase: phase}), do: %{receive_level: phase}

    def abort(state, _reason), do: %{state | phase: :aborted}

    def feed(%__MODULE__{phase: :initial} = state, :initial, <<1, 2>>) do
      {:ok, %{state | phase: :handshake, feeds: state.feeds ++ [{:initial, <<1, 2>>}]},
       [{:emit, :handshake, <<3, 4>>}]}
    end

    def feed(%__MODULE__{phase: :handshake} = state, :handshake, <<3, 4>>) do
      {:ok, %{state | phase: :application, feeds: state.feeds ++ [{:handshake, <<3, 4>>}]},
       [
         {:peer_authenticated, :server},
         {:peer_transport_parameters, <<9>>, :authenticated},
         :handshake_complete
       ]}
    end

    def feed(state, _level, <<255>>) do
      error = %{kind: :tls, alert: :decode_error, reason: :recorded_failure}
      {:error, error, %{state | phase: :failed}, [{:error, error}]}
    end

    def feed(%__MODULE__{phase: :handshake} = state, :handshake, <<254>>) do
      error = %{kind: :tls, alert: :decrypt_error, reason: :corrupted_finished}
      {:error, error, %{state | phase: :failed}, []}
    end

    def feed(_state, _level, _bytes),
      do:
        {:error, %{kind: :quic, reason: :unexpected_recorded_input}, %__MODULE__{phase: :failed},
         []}
  end

  test "reassembles fragments and folds each contiguous TLS feed once" do
    assert {:ok, state, [{:emit, :initial, <<1, 2>>}]} =
             Quic.TLSDriver.new(:client, adapter: RecordedTLS)

    assert {:ok, state, []} = Quic.TLSDriver.feed(state, :initial, 1, <<2>>)

    assert {:ok, state, [{:emit, :handshake, <<3, 4>>}]} =
             Quic.TLSDriver.feed(state, :initial, 0, <<1>>)

    assert {:ok, state, []} = Quic.TLSDriver.feed(state, :handshake, 1, <<4>>)
    assert {:ok, state, effects} = Quic.TLSDriver.feed(state, :handshake, 0, <<3>>)
    assert :handshake_complete in effects
    assert Quic.TLSDriver.facts(state).tls_complete
    assert {:ok, <<4>>} = Quic.TLSDriver.retransmit(state, :handshake, 1, 1)
  end

  test "future levels buffer and old duplicate bytes are ignored" do
    assert {:ok, state, _} = Quic.TLSDriver.new(:client, adapter: RecordedTLS)
    assert {:ok, state, []} = Quic.TLSDriver.feed(state, :handshake, 0, <<3, 4>>)
    assert {:ok, state, effects} = Quic.TLSDriver.feed(state, :initial, 0, <<1, 2>>)
    assert :handshake_complete in effects
    assert {:ok, state, []} = Quic.TLSDriver.feed(state, :initial, 0, <<1, 2>>)
    assert {:ok, _state, _} = Quic.TLSDriver.feed(state, :handshake, 0, <<3, 4>>)
  end

  test "future-level pending bytes use an aggregate bound" do
    assert {:ok, state, [{:emit, :initial, <<1, 2>>}]} =
             Quic.TLSDriver.new(
               :client,
               adapter: RecordedTLS,
               max_crypto_bytes: 2,
               max_emitted_bytes: 10
             )

    assert {:ok, state, []} = Quic.TLSDriver.feed(state, :handshake, 0, <<3, 4>>)

    assert {:error, %{kind: :quic, reason: :future_crypto_buffer_limit}, ^state, []} =
             Quic.TLSDriver.feed(state, :application, 0, <<5>>)
  end

  test "conflicting overlap and sparse limits are explicit" do
    state = Quic.CryptoReassembly.new(max_bytes: 4, max_intervals: 1)
    assert {:ok, state, <<>>} = Quic.CryptoReassembly.put(state, 4, <<1>>)
    assert {:error, :conflicting_overlap} = Quic.CryptoReassembly.put(state, 4, <<2>>)
    assert {:error, :crypto_buffer_limit} = Quic.CryptoReassembly.put(state, 0, <<1, 2, 3, 4>>)
  end

  test "fatal TLS result is terminal and does not invent actions" do
    assert {:ok, state, _} = Quic.TLSDriver.new(:client, adapter: RecordedTLS)

    assert {:error, %{kind: :tls, reason: :recorded_failure}, failed, [{:error, _}]} =
             Quic.TLSDriver.feed(state, :initial, 0, <<255>>)

    assert {:error, %{kind: :closed, reason: :terminal}, ^failed, []} =
             Quic.TLSDriver.feed(failed, :initial, 0, <<>>)

    assert ^failed = Quic.TLSDriver.abort(failed, :again)
  end

  test "a corrupted Finished is terminal and emits no replacement flight" do
    assert {:ok, state, _} = Quic.TLSDriver.new(:client, adapter: RecordedTLS)
    assert {:ok, state, _} = Quic.TLSDriver.feed(state, :initial, 0, <<1, 2>>)

    assert {:error, %{reason: :corrupted_finished}, failed, []} =
             Quic.TLSDriver.feed(state, :handshake, 0, <<254>>)

    assert failed.terminal == :failed

    assert {:error, %{kind: :closed, reason: :terminal}, ^failed, []} =
             Quic.TLSDriver.feed(failed, :handshake, 1, <<>>)
  end

  test "retained TLS output has an explicit aggregate budget" do
    assert {:error, %{kind: :quic, reason: :tls_output_limit}} =
             Quic.TLSDriver.new(:client, adapter: RecordedTLS, max_emitted_bytes: 1)
  end

  test "default adapter uses the pinned public SSL.QUIC API" do
    options = [
      cacerts: :public_key.cacerts_get(),
      reference_identity: {:dns_id, "example.test"},
      alpn: ["test"],
      transport_parameters: <<>>
    ]

    assert {:ok, state, [{:emit, :initial, hello}]} = Quic.TLSDriver.new(:client, options)
    assert <<1, _::binary>> = hello
    assert Quic.TLSDriver.info(state).receive_level == :initial
  end
end
