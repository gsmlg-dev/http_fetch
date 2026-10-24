defmodule Quic.IdleTimeoutTest do
  use ExUnit.Case, async: true
  alias Quic.{Connection, HandshakeScheduler, Recovery}

  defmodule ClockIO do
    def monotonic_time, do: Process.get(:idle_test_clock, 0)

    def send(pid, bytes, _) do
      Kernel.send(pid, {:sent, bytes})
      {:ok, Process.get(:idle_test_sent_at, monotonic_time())}
    end
  end

  defmodule ApplicationTLS do
    def new(_, _) do
      secret = %SSL.QUIC.Secret{
        level: :application,
        direction: :read,
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: :binary.copy(<<1>>, 32)
      }

      {:ok, nil, [secret, %{secret | direction: :write}]}
    end

    def info(_), do: %{receive_level: :application}
    def abort(state, _), do: state
  end

  defmodule InitialTLS do
    def new(_, _), do: {:ok, nil, [{:emit, :initial, <<1, 2>>}]}
    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
  end

  defp options(extra) do
    Keyword.merge(
      [
        role: :client,
        owner: self(),
        io: {ClockIO, self()},
        remote: {{127, 0, 0, 1}, 443},
        scheduler: [
          dcid: <<1, 2, 3, 4>>,
          scid: <<5, 6, 7, 8>>,
          adapter: ApplicationTLS,
          streams: [delivery: :manual]
        ]
      ],
      extra
    )
  end

  defp established(timeout \\ 10_000) do
    opts = options(idle_timeout: timeout)
    {:ok, :handshaking, data, _} = Connection.init(opts)
    {:ok, scheduler, []} = HandshakeScheduler.new(:client, opts[:scheduler])

    %{
      data
      | scheduler: scheduler,
        ready: true,
        ready_notified: true,
        idle_last_activity: 0,
        idle_deadline: if(timeout == :infinity, do: nil, else: timeout * 1000)
    }
  end

  defp ping(data, ref \\ make_ref(), deadline \\ System.monotonic_time(:millisecond) + 1_000) do
    Connection.handle_event(
      {:call, {self(), make_ref()}},
      {:operation, data.generation, ref, deadline, {:ping}},
      :established,
      data
    )
  end

  defp peer(data) do
    {:ok, scheduler, []} =
      HandshakeScheduler.new(:server,
        dcid: data.scheduler.scid,
        scid: data.scheduler.dcid,
        adapter: ApplicationTLS
      )

    scheduler
  end

  defp deliver(data, bytes) do
    Connection.handle_event(
      {:call, {self(), make_ref()}},
      {:datagram, data.generation, bytes, ClockIO.monotonic_time()},
      :established,
      data
    )
  end

  defp protected(data, number, plaintext) do
    keys = data.scheduler.keys.application.read
    cid = data.scheduler.scid
    aad = <<0x43, cid::binary, number::32>>
    {:ok, ciphertext} = Quic.Protection.aead_encrypt(keys.key, keys.iv, number, aad, plaintext)
    bytes = aad <> ciphertext
    offset = 1 + byte_size(cid)

    {:ok, mask} =
      Quic.Protection.header_protection_mask(
        keys.hp,
        binary_part(bytes, offset + 4, 16),
        keys.aead
      )

    cid_size = byte_size(cid)
    <<first, cid::binary-size(cid_size), pn::binary-size(4), tail::binary>> = bytes
    pn = :crypto.exor(pn, binary_part(mask, 1, 4))

    <<Bitwise.bxor(first, Bitwise.band(:binary.at(mask, 0), 0x1F)), cid::binary, pn::binary,
      tail::binary>>
  end

  test "disabled local idle expiry is an explicit supported connection option" do
    assert {:ok, :handshaking, data, actions} = Connection.init(options(idle_timeout: :infinity))
    assert data.idle_timeout == :infinity
    assert data.idle_deadline == nil
    assert {{:timeout, :handshake}, 10_000, data.generation} in actions

    for option <- [:handshake_timeout, :closing_timeout, :draining_timeout] do
      assert {:stop, :invalid_connection_options} =
               Connection.init(options([{:idle_timeout, :infinity}, {option, :infinity}]))
    end

    for invalid <- [0, -1, nil, 1.5] do
      assert {:stop, :invalid_connection_options} =
               Connection.init(options(idle_timeout: invalid))
    end
  end

  test "disabled negotiated expiry cancels finite timers and ignores stale expiry" do
    data = established(:infinity)
    Process.put(:idle_test_clock, 100_000_000)

    assert {:keep_state, next, [{{:timeout, :idle}, :cancel}]} =
             Connection.handle_event({:timeout, :idle}, data.generation, :established, data)

    assert next.idle_deadline == nil

    assert :keep_state_and_data =
             Connection.handle_event({:timeout, :idle}, make_ref(), :established, next)

    assert {:next_state, :established, next, actions} = ping(next)
    assert next.idle_deadline == nil
    assert {{:timeout, :idle}, :cancel} in actions
  end

  test "current PTO floors finite expiry and can extend an already armed deadline" do
    data = established(10)
    floor = 3 * Recovery.pto_duration(data.scheduler.recovery)

    assert {:keep_state, next, _} =
             Connection.handle_event({:timeout, :idle}, data.generation, :established, data)

    assert next.idle_deadline == floor

    next = put_in(next.scheduler.recovery.rtt.smoothed, 10_000_000)
    Process.put(:idle_test_clock, floor)

    assert {:keep_state, next, _} =
             Connection.handle_event({:timeout, :idle}, data.generation, :established, next)

    assert next.idle_deadline > floor

    Process.put(:idle_test_clock, next.idle_deadline)

    assert {:stop, :normal, %{reason: :idle_timeout}} =
             Connection.handle_event({:timeout, :idle}, data.generation, :established, next)
  end

  test "only first ack-eliciting local send since receive refreshes idle, with bounded ledger" do
    data = established()
    Process.put(:idle_test_clock, 1_000_000)
    ref = make_ref()
    assert {:next_state, :established, next, _} = ping(data, ref)
    assert next.idle_deadline == 11_000_000
    refute next.idle_send_allowed
    assert_receive {:sent, _}

    Process.put(:idle_test_clock, 2_000_000)
    assert {:keep_state_and_data, _} = ping(next, ref)
    refute_receive {:sent, _}, 0
    assert {:next_state, :established, next, _} = ping(next)
    assert next.idle_deadline == 11_000_000

    expired = System.monotonic_time(:millisecond) - 1

    assert {:keep_state, rejected, [{:reply, _, {:error, :deadline_expired}}]} =
             ping(next, make_ref(), expired)

    assert rejected.idle_deadline == next.idle_deadline

    for _ <- 1..20, reduce: %{next | operation_limit: 4} do
      current ->
        assert {:next_state, :established, updated, _} = ping(current)
        assert map_size(updated.operations) <= 4
        assert updated.idle_deadline == 11_000_000
        updated
    end
  end

  test "send restart uses writer completion timestamp rather than delayed receipt handling" do
    data = established()
    Process.put(:idle_test_clock, 3_000_000)
    Process.put(:idle_test_sent_at, 1_000_000)
    assert {:next_state, :established, next, _} = ping(data)
    assert next.idle_deadline == 11_000_000
  end

  test "successful authenticated receive including duplicates resets, ACK-only send does not" do
    data = established()
    {:ok, peer, [effect]} = HandshakeScheduler.ping(peer(data))

    {:ok, peer, _} =
      HandshakeScheduler.local_send(peer, :application, effect.packet_number, :ok, 0)

    Process.put(:idle_test_clock, 1_000_000)

    assert {:next_state, :established, next, _} = deliver(data, effect.bytes)
    assert next.idle_deadline == 11_000_000
    assert next.idle_send_allowed
    assert next.scheduler.authenticated_packets == 1
    assert_receive {:sent, ack}
    {:ok, _, [%{type: :ack}]} = HandshakeScheduler.receive_datagram(peer, ack, 1_000_000)

    Process.put(:idle_test_clock, 2_000_000)
    assert {:next_state, :established, next, _} = deliver(next, effect.bytes)
    assert next.idle_deadline == 12_000_000
    assert next.idle_send_allowed
    assert next.scheduler.authenticated_packets == 2

    Process.put(:idle_test_clock, 3_000_000)
    assert {:next_state, :established, next, _} = ping(next)
    assert next.idle_deadline == 13_000_000
    refute next.idle_send_allowed
  end

  test "bad tags, ignored retired packets and local empty reads cannot fake activity" do
    data = established()
    {:ok, _, [effect]} = HandshakeScheduler.ping(peer(data))
    size = byte_size(effect.bytes) - 1
    <<prefix::binary-size(size), last>> = effect.bytes
    Process.put(:idle_test_clock, 1_000_000)
    assert {:keep_state_and_data, _} = deliver(data, prefix <> <<Bitwise.bxor(last, 1)>>)

    {:ok, _, [initial]} =
      HandshakeScheduler.new(:server,
        dcid: data.scheduler.scid,
        scid: data.scheduler.dcid,
        adapter: InitialTLS
      )

    data = put_in(data.scheduler.recovery.spaces.initial.retired, true)
    assert {:next_state, :established, next, _} = deliver(data, initial.bytes)
    assert next.idle_deadline == data.idle_deadline
    assert next.scheduler.authenticated_packets == 0

    {:ok, scheduler, 0} = HandshakeScheduler.open_stream(data.scheduler, :bidi)
    data = %{data | scheduler: scheduler}

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               {:call, {self(), make_ref()}},
               {:stream_consume, 0, 1},
               :established,
               data
             )

    assert next.idle_deadline == data.idle_deadline
  end

  test "authenticated packets discarded below the receive floor cannot postpone expiry" do
    data = established()
    {:ok, _, [effect]} = HandshakeScheduler.ping(peer(data))
    data = put_in(data.scheduler.recovery.spaces.application.receive_floor, 1)
    Process.put(:idle_test_clock, 1_000_000)
    assert {:next_state, :established, next, _} = deliver(data, effect.bytes)
    assert next.idle_deadline == data.idle_deadline
    assert next.scheduler.authenticated_packets == 0
  end

  test "malformed authenticated duplicate does not restart idle expiry" do
    data = established()
    {:ok, recovery} = Recovery.note_received(data.scheduler.recovery, :application, 0)
    data = %{data | scheduler: %{data.scheduler | recovery: recovery}}
    Process.put(:idle_test_clock, 1_000_000)
    bytes = protected(data, 0, <<0x1F, 0, 0, 0>>)
    assert {:next_state, :established, next, _} = deliver(data, bytes)
    assert next.idle_deadline == data.idle_deadline
    assert next.scheduler.authenticated_packets == 0
  end

  test "PING respects scheduler queue and recovery retention bounds" do
    data = established()
    scheduler = %{data.scheduler | max_queue: 0}
    assert {:blocked, :send_queue_limit} = HandshakeScheduler.ping(scheduler)

    scheduler = %{data.scheduler | recovery: %{data.scheduler.recovery | max_sent_packets: 1}}
    {:ok, scheduler, [_]} = HandshakeScheduler.ping(scheduler)
    {:ok, scheduler, []} = HandshakeScheduler.ping(scheduler)
    assert map_size(scheduler.recovery.spaces.application.sent) == 1
    assert scheduler.pending_control.application == [%{type: :ping}]
    {:ok, scheduler, []} = HandshakeScheduler.ping(scheduler)
    assert scheduler.pending_control.application == [%{type: :ping}]
  end

  test "disabled idle expiry retains finite handshake, closing and draining bounds" do
    {:ok, :handshaking, data, _} = Connection.init(options(idle_timeout: :infinity))

    assert {:stop, :normal, %{reason: :handshake_timeout}} =
             Connection.handle_event({:timeout, :handshake}, data.generation, :handshaking, data)

    data = established(:infinity)

    assert {:next_state, :closing, closing, actions} =
             Connection.handle_event({:call, {self(), make_ref()}}, :close, :established, data)

    assert closing.closing_timeout > 0
    assert closing.draining_timeout > 0
    assert {{:timeout, :idle}, :cancel} in actions

    assert :keep_state_and_data =
             Connection.handle_event({:timeout, :idle}, data.generation, :closing, closing)

    Process.put(:idle_test_clock, closing.closing_deadline)

    assert {:next_state, :draining, draining, _} =
             Connection.handle_event({:timeout, :closing}, data.generation, :closing, closing)

    Process.put(:idle_test_clock, draining.draining_deadline)

    assert {:stop, :normal, _} =
             Connection.handle_event({:timeout, :draining}, data.generation, :draining, draining)
  end
end
