defmodule Quic.Phase1IOTLSTest do
  use ExUnit.Case, async: true
  alias Quic.{Endpoint, HandshakeScheduler}

  defmodule Recorded do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      secrets =
        for {direction, byte} <- [read: read, write: write] do
          %SSL.QUIC.Secret{
            level: :application,
            direction: direction,
            cipher_suite: 0x1301,
            aead: :aes_128_gcm,
            hkdf: :sha256,
            secret: <<byte::256>>
          }
        end

      {:ok, [], secrets}
    end

    def info(_), do: %{receive_level: :application}
    def abort(state, _), do: state
    def feed(state, :application, bytes), do: {:ok, state ++ [bytes], []}
  end

  defmodule Initial do
    def new(_, _), do: {:ok, nil, [{:emit, :initial, <<1, 2>>}]}
    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _, _), do: {:ok, state, []}
  end

  test "short headers use the receiver's local CID length" do
    {:ok, sender, []} =
      HandshakeScheduler.new(:client,
        adapter: Recorded,
        dcid: <<1, 2, 3>>,
        scid: <<4, 5, 6, 7, 8, 9, 10, 11>>
      )

    {:ok, receiver, []} =
      HandshakeScheduler.new(:server, adapter: Recorded, dcid: sender.scid, scid: sender.dcid)

    {:ok, sender, 0} = HandshakeScheduler.open_stream(sender, :bidi)
    {:ok, _, [effect]} = HandshakeScheduler.send_stream(sender, 0, "hello", true)

    assert {:ok, _, [%{type: :stream, events: [{:data, 0, "hello"}, {:fin, 0}]}]} =
             HandshakeScheduler.receive_datagram(receiver, effect.bytes, 0)
  end

  test "application CRYPTO reaches bounded reassembly and the TLS provider" do
    {:ok, sender, []} =
      HandshakeScheduler.new(:server,
        adapter: Recorded,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>
      )

    {:ok, receiver, []} =
      HandshakeScheduler.new(:client, adapter: Recorded, dcid: sender.scid, scid: sender.dcid)

    # Syntactically valid TLS NewSessionTicket. TLS parsing is tested with real SSL.QUIC separately.
    ticket = <<4, 0, 0, 14, 0::32, 0::32, 0, 0, 1, 1, 0, 0>>
    sender = %{sender | pending: [%{level: :application, offset: 0, bytes: ticket}]}
    {:ok, _, [effect]} = HandshakeScheduler.schedule(sender)

    assert {:ok, receiver, [%{type: :crypto}]} =
             HandshakeScheduler.receive_datagram(receiver, effect.bytes, 0)

    assert receiver.tls.tls == [ticket]
    assert {:ok, receiver, _} = HandshakeScheduler.receive_datagram(receiver, effect.bytes, 1)
    assert receiver.tls.tls == [ticket]
  end

  test "external Retry sends only through the injected capability" do
    caller = self()
    remote = {{127, 0, 0, 1}, 45_001}

    {:ok, endpoint} =
      Endpoint.start_link(
        role: :server,
        retry: true,
        io:
          {:external, {{127, 0, 0, 1}, 45_000},
           fn address, bytes ->
             send(caller, {:sent, address, bytes})
             :ok
           end},
        tls: [adapter: Initial]
      )

    on_exit(fn -> if Process.alive?(endpoint), do: GenServer.stop(endpoint) end)

    {:ok, _, [initial]} =
      HandshakeScheduler.new(:client,
        adapter: Initial,
        dcid: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        scid: <<9, 10, 11, 12, 13, 14, 15, 16>>
      )

    assert :ok = Endpoint.receive_datagram(endpoint, remote, initial.bytes, 0)
    assert_receive {:sent, ^remote, retry}
    assert Bitwise.band(:binary.at(retry, 0), 0xF0) == 0xF0
    assert Endpoint.stats(endpoint).retry_sent == 1
  end
end
