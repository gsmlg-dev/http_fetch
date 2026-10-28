defmodule Quic.TLSAlertCloseTest do
  use ExUnit.Case, async: true

  alias Quic.{Connection, HandshakeScheduler}

  defmodule RecordedIO do
    def monotonic_time, do: 0

    def send(pid, bytes, _remote) do
      Kernel.send(pid, {:sent_close, bytes})
      {:ok, 0}
    end
  end

  defmodule FailingTLS do
    def new(role, options) do
      level = Keyword.fetch!(options, :test_level)
      error = Keyword.fetch!(options, :test_error)

      secrets =
        if level == :initial do
          []
        else
          secret = %SSL.QUIC.Secret{
            level: level,
            direction: :read,
            cipher_suite: 0x1301,
            aead: :aes_128_gcm,
            hkdf: :sha256,
            secret: :binary.copy(<<1>>, 32)
          }

          [secret, %{secret | direction: :write}]
        end

      emission = if role == :server, do: [{:emit, level, <<1, 2>>}], else: []
      {:ok, {level, error}, secrets ++ emission}
    end

    def info({level, _error}), do: %{receive_level: level}

    def feed({_level, error} = state, _received_level, _bytes),
      do: {:error, error, state, [{:error, error}]}

    def abort(state, _reason), do: state
  end

  defp flight(level, error) do
    options = [
      dcid: <<1, 2, 3, 4>>,
      scid: <<5, 6, 7, 8>>,
      adapter: FailingTLS,
      test_level: level,
      test_error: error
    ]

    {:ok, :handshaking, data, _actions} =
      Connection.init(
        role: :client,
        owner: self(),
        io: {RecordedIO, self()},
        remote: {{127, 0, 0, 1}, 443},
        closing_timeout: 40,
        draining_timeout: 40,
        scheduler: options
      )

    {:ok, scheduler, []} = HandshakeScheduler.new(:client, options)

    peer_options =
      Keyword.merge(options,
        dcid: options[:scid],
        scid: <<9, 10, 11, 12>>,
        original_dcid: options[:dcid]
      )

    {:ok, peer, [packet]} = HandshakeScheduler.new(:server, peer_options)
    {%{data | scheduler: scheduler}, peer, packet.bytes}
  end

  defp deliver(data, bytes, from) do
    Connection.handle_event(
      {:call, from},
      {:datagram, data.generation, bytes, 0},
      :handshaking,
      data
    )
  end

  test "fatal TLS errors send their alert code and preserve the public reason" do
    for {alert, code} <- [
          bad_certificate: 42,
          certificate_unknown: 46,
          unknown_ca: 48,
          decode_error: 50,
          decrypt_error: 51,
          internal_error: 80
        ] do
      error = %SSL.QUIC.Error{kind: :tls, alert: alert, reason: :fixture_failure}
      reason = {:tls, :tls, alert, :fixture_failure}
      {data, peer, bytes} = flight(:handshake, error)
      from = {self(), make_ref()}

      assert {:stop_and_reply, :normal, [{:reply, ^from, {:error, ^reason}}], closed} =
               deliver(data, bytes, from)

      assert closed.reason == reason
      assert_receive {:sent_close, close}

      assert {:ok, _peer, [%{type: :connection_close, error_code: received}]} =
               HandshakeScheduler.receive_datagram(peer, close, 1)

      assert received == 0x100 + code
    end
  end

  test "TLS alerts retain their transport code at every available encryption level" do
    for level <- [:initial, :handshake, :application] do
      error = %SSL.QUIC.Error{kind: :tls, alert: :certificate_unknown, reason: :hostname_mismatch}
      {data, peer, bytes} = flight(level, error)

      assert {:stop_and_reply, :normal, _replies, _closed} =
               deliver(data, bytes, {self(), make_ref()})

      assert_receive {:sent_close, close}

      assert {:ok, _peer, [%{type: :connection_close, error_code: 0x12E}]} =
               HandshakeScheduler.receive_datagram(peer, close, 1)
    end
  end

  test "unauthenticated ciphertext cannot trigger a fatal close" do
    error = %SSL.QUIC.Error{kind: :tls, alert: :certificate_unknown, reason: :hostname_mismatch}
    {data, _peer, bytes} = flight(:handshake, error)
    size = byte_size(bytes) - 1
    <<prefix::binary-size(size), last>> = bytes
    from = {self(), make_ref()}

    assert {:keep_state_and_data, [{:reply, ^from, :ok}]} =
             deliver(data, prefix <> <<Bitwise.bxor(last, 1)>>, from)

    refute_receive {:sent_close, _}, 0
  end

  test "non-TLS provider failures do not manufacture a TLS alert" do
    error = %SSL.QUIC.Error{kind: :configuration, alert: nil, reason: :invalid_input}
    {data, _peer, bytes} = flight(:handshake, error)
    from = {self(), make_ref()}
    reason = {:tls, :configuration, nil, :invalid_input}

    assert {:stop_and_reply, :normal, [{:reply, ^from, {:error, ^reason}}], _data} =
             deliver(data, bytes, from)

    refute_receive {:sent_close, _}, 0
  end
end
