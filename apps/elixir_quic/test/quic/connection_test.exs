defmodule Quic.ConnectionTest do
  use ExUnit.Case, async: true

  alias Quic.{Connection, HandshakeScheduler}
  alias Quic.IO.GenUDP

  defmodule RecordedTLS do
    def new(_, _), do: {:ok, 0, [{:emit, :initial, <<1, 2>>}]}
    def info(_), do: %{receive_level: :initial}
    def feed(state, :initial, _bytes), do: {:ok, state + 1, []}
    def abort(state, _), do: state
  end

  defmodule HandshakeTLS do
    def new(role, _) do
      secret = %SSL.QUIC.Secret{
        level: :handshake,
        direction: if(role == :server, do: :read, else: :write),
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: :binary.copy(<<1>>, 32)
      }

      secrets = [secret, %{secret | direction: if(role == :server, do: :write, else: :read)}]
      actions = if role == :client, do: secrets ++ [{:emit, :handshake, <<1, 2>>}], else: secrets
      {:ok, 0, actions}
    end

    def info(_), do: %{receive_level: :handshake}
    def feed(state, :handshake, _), do: {:ok, state + 1, []}
    def abort(state, _), do: state
  end

  defmodule InvalidParametersTLS do
    def new(_, _), do: {:ok, :initial, []}
    def info(phase), do: %{receive_level: phase}

    def feed(_, :initial, _),
      do:
        {:ok, :application,
         [{:peer_transport_parameters, <<15, 1, 99>>, :authenticated}, :handshake_complete]}

    def abort(state, _), do: state
  end

  defmodule UnverifiedParametersTLS do
    def new(_, _), do: {:ok, :initial, []}
    def info(phase), do: %{receive_level: phase}

    def feed(_, :initial, _),
      do:
        {:ok, :application,
         [{:peer_transport_parameters, <<15, 1, 99>>, :unverified}, :handshake_complete]}

    def abort(state, _), do: state
  end

  defmodule InvalidValueParametersTLS do
    def new(_, _), do: {:ok, :initial, []}
    def info(phase), do: %{receive_level: phase}

    def feed(_, :initial, _),
      do:
        {:ok, :application,
         [
           # max_udp_payload_size=1199 followed by the client's initial source CID
           {:peer_transport_parameters, <<3, 2, 0x44, 0xAF, 15, 4, 5, 6, 7, 8>>, :authenticated},
           :handshake_complete
         ]}

    def abort(state, _), do: state
  end

  defmodule FailedWriter do
    def send(_pid, _bytes, _remote), do: {:error, :writer_failed}
    def monotonic_time, do: System.monotonic_time(:microsecond)
  end

  defp options(io, extra \\ []) do
    Keyword.merge(
      [
        role: :client,
        io: io,
        remote: {{127, 0, 0, 1}, 1234},
        handshake_timeout: 2_000,
        scheduler: [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: RecordedTLS]
      ],
      extra
    )
  end

  test "connection sends a protected Initial over UDP and keeps local send distinct from ACK" do
    {:ok, peer} = GenUDP.open()
    {:ok, writer} = GenUDP.open()
    {:ok, conn} = Connection.start_link(options({GenUDP, writer}, remote: GenUDP.local(peer)))
    assert_receive {:quic_udp, _, _, _, packet, _}, 1_000
    assert byte_size(packet) >= 1200
    status = Connection.status(conn)
    assert status.phase == :handshaking
    assert status.packets.initial == %{sent: 1, acked: 0, queued: 0, failed: 0}
    assert status.bytes_sent == byte_size(packet)
    assert :ok = Connection.close(conn)
    assert Process.alive?(writer)
    :ok = GenUDP.close(writer)
    :ok = GenUDP.close(peer)
  end

  test "runtime PTO retransmits a retained Initial with a fresh packet number" do
    {:ok, peer} = GenUDP.open()
    {:ok, writer} = GenUDP.open()

    {:ok, conn} =
      Connection.start_link(
        options({GenUDP, writer}, remote: GenUDP.local(peer), handshake_timeout: 3_000)
      )

    assert_receive {:quic_udp, generation, credit, _, first, _}, 1_000
    :ok = GenUDP.consumed(peer, generation, credit)
    assert_receive {:quic_udp, ^generation, _, _, retry, _}, 1_500
    refute retry == first
    status = Connection.status(conn)
    assert status.packets.initial.sent == 2
    assert status.packets.initial.acked == 0
    :ok = Connection.close(conn)
    :ok = GenUDP.close(writer)
    :ok = GenUDP.close(peer)
  end

  test "server holds its flight until it has amplification credit" do
    {:ok, peer} = GenUDP.open()
    {:ok, writer} = GenUDP.open()
    opts = options({GenUDP, writer}, role: :server, remote: GenUDP.local(peer))
    {:ok, conn} = Connection.start_link(opts)
    status = Connection.status(conn)
    assert status.pending_datagrams == 1
    assert status.bytes_sent == 0
    refute_receive {:quic_udp, _, _, _, _, _}, 30
    {:ok, sender, [initial]} = HandshakeScheduler.new(:client, opts[:scheduler])

    assert :ok =
             Connection.deliver(conn, status.generation, initial.bytes, GenUDP.monotonic_time())

    assert_receive {:quic_udp, generation, credit, _, response, _}, 1_000
    :ok = GenUDP.consumed(peer, generation, credit)
    assert_receive {:quic_udp, ^generation, _, _, ack, _}, 1_000
    {:ok, sender, _} = HandshakeScheduler.receive_datagram(sender, response, 0)
    {:ok, _, events} = HandshakeScheduler.receive_datagram(sender, ack, 1)
    assert Enum.any?(events, &(&1.type == :ack))
    status = Connection.status(conn)
    assert status.bytes_sent == byte_size(response) + byte_size(ack)
    assert status.bytes_sent <= 3 * byte_size(initial.bytes)
    refute status.address_validated
    :ok = Connection.close(conn)
    :ok = GenUDP.close(writer)
    :ok = GenUDP.close(peer)
  end

  test "authenticated Handshake validates the server path without a 1200 byte minimum" do
    {:ok, writer} = GenUDP.open()
    opts = options({GenUDP, writer}, role: :server)
    scheduler_opts = Keyword.put(opts[:scheduler], :adapter, HandshakeTLS)
    {:ok, conn} = Connection.start_link(Keyword.put(opts, :scheduler, scheduler_opts))
    generation = Connection.status(conn).generation
    {:ok, _, [effect]} = HandshakeScheduler.new(:client, scheduler_opts)
    assert byte_size(effect.bytes) < 1200
    assert :ok = Connection.deliver(conn, generation, effect.bytes, GenUDP.monotonic_time())
    assert Connection.status(conn).address_validated
    :ok = Connection.close(conn)
    :ok = GenUDP.close(writer)
  end

  test "TLS completion cannot bypass parameter authentication or CID validation" do
    for {adapter, reason} <- [
          {InvalidParametersTLS, {:transport_parameters, :connection_id_mismatch}},
          {InvalidValueParametersTLS, {:transport_parameters, :invalid_max_udp_payload_size}},
          {UnverifiedParametersTLS, :incomplete_authentication}
        ] do
      {:ok, writer} = GenUDP.open()
      opts = options({GenUDP, writer}, role: :server)

      {:ok, conn} =
        Connection.start_link(
          Keyword.put(opts, :scheduler, Keyword.put(opts[:scheduler], :adapter, adapter))
        )

      generation = Connection.status(conn).generation
      {:ok, _, [initial]} = HandshakeScheduler.new(:client, opts[:scheduler])

      assert {:error, ^reason} =
               Connection.deliver(conn, generation, initial.bytes, GenUDP.monotonic_time())

      assert_receive {:quic_closed, ^conn, ^generation, ^reason}, 1_000
      refute_receive {:quic_udp, ^generation, _, _, _, _}, 100
      :ok = GenUDP.close(writer)
    end
  end

  test "stale datagrams cannot change credit and a handshake deadline terminates" do
    {:ok, writer} = GenUDP.open()

    {:ok, conn} =
      Connection.start_link(options({GenUDP, writer}, role: :server, handshake_timeout: 100))

    monitor = Process.monitor(conn)
    generation = Connection.status(conn).generation
    assert {:error, :stale_generation} = Connection.deliver(conn, make_ref(), <<0::9600>>, 0)
    assert Connection.status(conn).bytes_received == 0
    assert_receive {:quic_closed, ^conn, ^generation, :handshake_timeout}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^conn, :normal}, 1_000
    assert Process.alive?(writer)
    :ok = GenUDP.close(writer)
  end

  test "local writer failure closes the connection without claiming a send or ACK" do
    {:ok, conn} = Connection.start_link(options({FailedWriter, self()}))
    assert_receive {:quic_closed, ^conn, _, {:local_send, :writer_failed}}, 1_000
  end

  test "writer death terminates a waiting connection" do
    {:ok, writer} = GenUDP.open()
    {:ok, conn} = Connection.start_link(options({GenUDP, writer}, role: :server))
    generation = Connection.status(conn).generation
    :ok = GenUDP.close(writer)
    assert_receive {:quic_closed, ^conn, ^generation, {:writer_down, :normal}}, 1_000
  end

  test "close enters closing, ignores late datagrams, then drains and cleans up" do
    {:ok, peer} = GenUDP.open()
    {:ok, writer} = GenUDP.open()

    {:ok, conn} =
      Connection.start_link(
        options({GenUDP, writer},
          remote: GenUDP.local(peer),
          closing_timeout: 40,
          draining_timeout: 40
        )
      )

    generation = Connection.status(conn).generation
    monitor = Process.monitor(conn)
    assert :ok = Connection.close(conn)
    assert Connection.status(conn).phase == :closing
    assert :ok = Connection.deliver(conn, generation, <<0>>, GenUDP.monotonic_time())
    assert Connection.status(conn).phase == :closing
    assert_receive {:quic_closing, ^conn, ^generation, :closed}, 1_000
    assert_receive {:quic_closed, ^conn, ^generation, :closed}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^conn, :normal}, 1_000
    refute Process.alive?(conn)

    :ok = GenUDP.close(writer)
    :ok = GenUDP.close(peer)
  end
end
