defmodule SSL.Protocol.SetupPhaseProgressTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.{AST, Extension}
  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.KeyExchange
  alias SSL.Protocol.{ClientOffer, HandshakeFramer, HandshakeMachine, Record, ServerFlight}

  test "TLS12 accepted hello survives a certificate failure in the same record" do
    machine = tls12_machine()
    hello = server_hello()
    der = leaf_der()
    chain = <<byte_size(der)::24, der::binary>>
    certificate = <<11, byte_size(chain) + 3::24, byte_size(chain)::24, chain::binary>>
    payload = hello <> certificate
    record = <<22, 3, 3, byte_size(payload)::16, payload::binary>>

    assert {:error, {:fatal_alert, :bad_certificate, _}} = HandshakeMachine.feed(machine, record)

    assert {{:error, {:fatal_alert, :bad_certificate, _}}, true} =
             HandshakeMachine.feed_with_progress(machine, record)
  end

  test "TLS12 single execution invokes a rejecting callback only once after accepted hello" do
    parent = self()

    callback = fn _, event, state ->
      send(parent, {:verification_event, event})
      {:fail, state}
    end

    machine = %{tls12_machine() | options: [verify_fun: {callback, :rejected}]}
    chain = <<byte_size(leaf_der())::24, leaf_der()::binary>>
    certificate = <<11, byte_size(chain) + 3::24, byte_size(chain)::24, chain::binary>>

    assert {{:error, {:fatal_alert, :bad_certificate, _}}, true} =
             HandshakeMachine.feed_with_progress(
               machine,
               plaintext(server_hello() <> certificate)
             )

    assert_receive {:verification_event, {:bad_cert, _}}
    refute_receive {:verification_event, _}, 0
  end

  test "TLS12 partial, malformed, rejected hello and early alerts never establish progress" do
    machine = tls12_machine()
    hello = server_hello()
    <<first::binary-size(10), _::binary>> = hello

    assert {{:ok, _, [], []}, false} =
             HandshakeMachine.feed_with_progress(machine, plaintext(first))

    assert {{:error, _}, false} =
             HandshakeMachine.feed_with_progress(machine, plaintext(<<2, 1::24, 0>>))

    rejected = :binary.replace(hello, <<0xC02F::16>>, <<0xC030::16>>)

    assert {{:error, _}, false} =
             HandshakeMachine.feed_with_progress(machine, plaintext(rejected))

    assert {{:error, {:peer_alert, 2, 40}}, false} =
             HandshakeMachine.feed_with_progress(machine, <<21, 3, 3, 0, 2, 2, 40>>)
  end

  test "TLS13 accepted negotiation and verifier initialization retain authenticated fatal progress" do
    {initial, peer} = tls13_machine()
    hello = tls13_hello(<<6::256>>, 0x001D, peer.public_key)

    assert {{:ok, accepted, [], []}, true} =
             HandshakeMachine.feed_with_progress(initial, plaintext(hello))

    {:ok, certificate} = ServerFlight.encode_client_certificate(<<>>, [leaf_der()])
    flight = <<8, 2::24, 0::16>> <> certificate
    {:ok, record, _} = Record.encrypt(accepted.read_state, :handshake, flight)

    assert {{:error, {:fatal_alert, :bad_certificate, :empty_trust_anchors}}, true} =
             HandshakeMachine.feed_with_progress(accepted, record)

    {:ok, alert, _} = Record.encrypt(accepted.read_state, :alert, <<2, 40>>)

    assert {{:error, {:peer_alert, 2, 40}}, true} =
             HandshakeMachine.feed_with_progress(accepted, alert)
  end

  test "TLS13 rejected hello, partial hello, early alert and HRR alone remain false" do
    {initial, peer} = tls13_machine()
    hello = tls13_hello(<<6::256>>, 0x001D, peer.public_key)
    <<first::binary-size(12), _::binary>> = hello

    assert {{:ok, _, [], []}, false} =
             HandshakeMachine.feed_with_progress(initial, plaintext(first))

    rejected = :binary.replace(hello, <<0x1301::16>>, <<0x1302::16>>)

    assert {{:error, _}, false} =
             HandshakeMachine.feed_with_progress(initial, plaintext(rejected))

    assert {{:error, {:peer_alert, 2, 40}}, false} =
             HandshakeMachine.feed_with_progress(initial, <<21, 3, 3, 0, 2, 2, 40>>)

    random = Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
    hrr = tls13_hello(random, 0x0017, nil)

    assert {{:ok, retried, [<<22, 3, 3, _::binary>>], []}, false} =
             HandshakeMachine.feed_with_progress(initial, plaintext(hrr))

    assert retried.phase == :await_server_hello_after_retry
  end

  defp tls13_machine do
    {:ok, pair} = KeyExchange.generate(:x25519)
    {:ok, peer} = KeyExchange.generate(:x25519)
    {:ok, versions} = Extension.encode({:supported_versions, [0x0304]})
    {:ok, groups} = Extension.encode({:supported_groups, [0x001D, 0x0017]})
    {:ok, shares} = Extension.encode({:key_share, [{0x001D, pair.public_key}]})
    {:ok, signatures} = Extension.encode({:signature_algorithms, [0x0403]})

    ast = %AST{
      legacy_version: 0x0303,
      random: <<5::256>>,
      session_id: <<>>,
      cipher_suites: [0x1301],
      compression_methods: [0],
      extensions: [versions, groups, shares, signatures]
    }

    {:ok, machine, [_]} =
      HandshakeMachine.init(
        %Materialized{client_hello: ast, key_pairs: [pair]},
        [],
        {:dns_id, "example.test"}
      )

    {machine, peer}
  end

  defp tls13_hello(random, group, key) do
    share = if key, do: <<group::16, byte_size(key)::16, key::binary>>, else: <<group::16>>
    extensions = <<43::16, 2::16, 0x0304::16, 51::16, byte_size(share)::16, share::binary>>

    body =
      <<3, 3, random::binary, 0, 0x1301::16, 0, byte_size(extensions)::16, extensions::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end

  defp plaintext(payload), do: <<22, 3, 3, byte_size(payload)::16, payload::binary>>

  defp leaf_der,
    do:
      Base.decode64!(
        "MIIBujCCAWCgAwIBAgIUZEVhdlnst+wJk+6gosvIF7t0lc4wCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQZXhfc3NsIFRlc3QgUm9vdDAeFw0yNjA5MTEwMTUzNDNaFw0zNjA5MDgwMTUzNDNaMBwxGjAYBgNVBAMMEXVucmVsYXRlZC5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAED3kaNzjuH/2+t9LA9KqdPqKHPqX+m7CwU940oBOPQDOgiG2j/OpL4LcHmw2H5ZAT4hdg0JmvQ/D0ubwBFSt2YKOBgDB+MBcGA1UdEQQQMA6CDGV4YW1wbGUudGVzdDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFKdb+S+J4Y/YXoOn+0y8J3hFE2VwMB8GA1UdIwQYMBaAFGBLpjzGkzeIWDI3krMVLfq137/3MAoGCCqGSM49BAMCA0gAMEUCIQDeT1h9e0TfVVa6N+S4yTd8AJZW4znUCW/Szy8L9gc+fgIgLdvN5i81UBEhJ3sh8LmufMhVJhNnaDTsJM2OZA5qO1o="
      )

  defp tls12_machine do
    extensions = <<43::16, 3::16, 2, 3, 3, 23::16, 0::16, 0xFF01::16, 1::16, 0>>

    body =
      <<3, 3, 0::256, 0, 2::16, 0xC02F::16, 1, 0, byte_size(extensions)::16, extensions::binary>>

    hello = <<1, byte_size(body)::24, body::binary>>
    {:ok, offer} = ClientOffer.from_client_hello(hello)

    %HandshakeMachine{
      client_hello: hello,
      offer: offer,
      trust_source: [],
      identity: {:dns_id, "phase.test"},
      framer: HandshakeFramer.new(),
      phase: :await_server_hello
    }
  end

  defp server_hello do
    extensions = <<23::16, 0::16, 0xFF01::16, 1::16, 0>>
    body = <<3, 3, 7::256, 0, 0xC02F::16, 0, byte_size(extensions)::16, extensions::binary>>
    <<2, byte_size(body)::24, body::binary>>
  end
end
