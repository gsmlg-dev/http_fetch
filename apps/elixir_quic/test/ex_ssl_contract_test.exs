defmodule Quic.ExSSLContractTest do
  use ExUnit.Case, async: true

  @client_options [
    cacerts: :public_key.cacerts_get(),
    reference_identity: {:dns_id, "example.test"},
    alpn: ["test"],
    transport_parameters: <<>>
  ]

  test "pinned public QUIC API exposes the expected capability boundary" do
    assert {:module, SSL.QUIC} = Code.ensure_loaded(SSL.QUIC)
    assert {:module, SSL.Fingerprint} = Code.ensure_loaded(SSL.Fingerprint)
    assert function_exported?(SSL.QUIC, :capabilities, 0)
    assert function_exported?(SSL.QUIC, :new, 2)
    assert function_exported?(SSL.QUIC, :feed, 3)
    assert function_exported?(SSL.QUIC, :info, 1)
    assert function_exported?(SSL.QUIC, :abort, 2)
    assert Code.ensure_loaded?(SSL.QUIC.Secret)
    assert Code.ensure_loaded?(SSL.QUIC.Error)
    assert function_exported?(SSL.Fingerprint, :new, 1)
    assert function_exported?(SSL.Fingerprint, :feed, 2)

    capabilities = SSL.QUIC.capabilities()
    assert capabilities.tls_versions == [0x0304]
    assert capabilities.roles.client.certificate_handshake
    assert capabilities.roles.server.certificate_handshake
    refute capabilities.quic_packet_protection
    refute capabilities.tls_records
  end

  test "client emits exact record-free ClientHello and fingerprint observes those bytes" do
    assert {:ok, client, [{:emit, :initial, client_hello}]} =
             SSL.QUIC.new(:client, @client_options)

    assert <<1, _body_length::24, _rest::binary>> = client_hello
    assert SSL.QUIC.info(client).receive_level == :initial

    assert {:ok, observer} = SSL.Fingerprint.new(:quic)

    {observer, results} =
      client_hello
      |> :binary.bin_to_list()
      |> Enum.reduce({observer, []}, fn byte, {state, results} ->
        assert {:ok, state, emitted} = SSL.Fingerprint.feed(state, <<byte>>)
        {state, results ++ emitted}
      end)

    assert [%{transport: :quic, source: :visible_client_hello} = fingerprint] = results
    assert fingerprint.observation.encoded == client_hello
    assert is_binary(fingerprint.ja3.hash)
    assert is_binary(fingerprint.ja4.hash)
    assert {:error, :observer_complete} = SSL.Fingerprint.feed(observer, <<0>>)
  end

  test "public feed semantics preserve level and terminal error categories" do
    assert {:ok, client, []} =
             SSL.QUIC.new(:client, @client_options)
             |> then(fn {:ok, state, _} ->
               SSL.QUIC.feed(state, :initial, <<>>)
             end)

    assert {:error, %{kind: :quic, reason: :wrong_encryption_level}, failed, [_]} =
             SSL.QUIC.feed(client, :handshake, <<8, 0, 0, 2, 0, 0>>)

    assert %{phase: :failed} = SSL.QUIC.info(failed)

    assert {:error, %{kind: :closed, reason: :terminal}, ^failed, []} =
             SSL.QUIC.feed(failed, :initial, <<>>)

    assert %{phase: :aborted} = SSL.QUIC.info(SSL.QUIC.abort(client, :cancelled))
  end
end
