defmodule SSL.Protocol.ResumptionVerifierTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.KeyExchange
  alias SSL.Protocol.{ClientOffer, Resumption, ServerFlightVerifier, ServerHello}
  alias SSL.Protocol.ServerFlightVerifier.Input
  alias SSL.SessionTicket

  test "selected identity and cipher hash must bind to the offered ticket" do
    {input, _} = input()
    assert {:ok, _} = ServerFlightVerifier.start_incremental(input)

    wrong_ticket = %{input.ticket | ticket: "different-ticket"}

    assert {:error, {:fatal_alert, :illegal_parameter, :invalid_resumption_selection}} =
             ServerFlightVerifier.start_incremental(%{input | ticket: wrong_ticket})

    wrong_hash = %{input.ticket | hash: :sha384, psk: :binary.copy(<<7>>, 48)}

    assert {:error, {:fatal_alert, :illegal_parameter, :invalid_resumption_selection}} =
             ServerFlightVerifier.start_incremental(%{input | ticket: wrong_hash})
  end

  test "selected PSK still requires a fresh ECDHE ServerHello share" do
    {input, server_pair} = input()
    assert {:ok, _} = ServerFlightVerifier.start_incremental(input)

    no_share = server_hello(input.client_hello, server_pair.public_key, 0x1301, false)

    assert {:error, {:fatal_alert, :illegal_parameter, {:psk_key_exchange_mode_not_offered, 0}}} =
             ServerFlightVerifier.start_incremental(%{input | server_hello: no_share})
  end

  test "resumed flight rejects changed ALPN, early data, certificate and request" do
    {input, _} = input()
    assert {:ok, state} = ServerFlightVerifier.start_incremental(input)

    assert {:error, {:fatal_alert, :illegal_parameter, :resumption_alpn_changed}} =
             ServerFlightVerifier.process_message(state, encrypted_extensions("http/1.1"))

    assert {:error, {:fatal_alert, :unsupported_extension, {:unsolicited_extension, 42}}} =
             ServerFlightVerifier.process_message(state, encrypted_extensions("h2", true))

    assert {:ok, awaiting_finished} =
             ServerFlightVerifier.process_message(state, encrypted_extensions("h2"))

    # Nonempty Certificate passes framing so this isolates resumed flight order.
    entry = <<3::24, 1, 2, 3, 0::16>>
    body = <<0, byte_size(entry)::24, entry::binary>>
    certificate = <<11, byte_size(body)::24, body::binary>>

    assert {:error, {:fatal_alert, :unexpected_message, _}} =
             ServerFlightVerifier.process_message(awaiting_finished, certificate)

    signature_extension = ext(13, <<2::16, 0x0804::16>>)
    request_body = <<0, byte_size(signature_extension)::16, signature_extension::binary>>
    request = <<13, byte_size(request_body)::24, request_body::binary>>

    assert {:error, {:fatal_alert, :unexpected_message, _}} =
             ServerFlightVerifier.process_message(awaiting_finished, request)
  end

  test "resumed Finished still requires transcript authentication" do
    {input, _} = input()
    assert {:ok, state} = ServerFlightVerifier.start_incremental(input)
    assert {:ok, state} = ServerFlightVerifier.process_message(state, encrypted_extensions("h2"))

    assert {:error, {:fatal_alert, :decrypt_error, _}} =
             ServerFlightVerifier.process_message(state, <<20, 0, 0, 32, 0::256>>)
  end

  defp input do
    {:ok, client_pair} = KeyExchange.generate(:x25519)
    {:ok, server_pair} = KeyExchange.generate(:x25519)
    now = System.monotonic_time(:millisecond)

    ticket = %SessionTicket{
      ticket: "resumption-one",
      psk: :binary.copy(<<9>>, 32),
      hash: :sha256,
      age_add: 3,
      issued_at: now - 10,
      expires_at: now + 60_000,
      peer: %{chain: [<<1, 2, 3>>]},
      alpn: "h2"
    }

    {:ok, psk} = Resumption.psk_extension(ticket, now)
    hello = client_hello(client_pair.public_key, psk)
    {:ok, hello} = Resumption.bind(hello, ticket)
    server = server_hello(hello, server_pair.public_key, 0x1301, true)

    {%Input{
       client_hello: hello,
       server_hello: server,
       client_key_pair: client_pair,
       records: [],
       trust_source: [],
       identity: {:dns_id, "exssl.test"},
       ticket: ticket
     }, server_pair}
  end

  defp client_hello(public, psk) do
    extensions =
      [
        ext(43, <<2, 0x0304::16>>),
        ext(10, <<2::16, 0x001D::16>>),
        ext(13, <<2::16, 0x0804::16>>),
        ext(51, <<36::16, 0x001D::16, 32::16, public::binary-size(32)>>),
        ext(16, <<12::16, 2, "h2", 8, "http/1.1">>),
        ext(45, <<1, 1>>),
        ext(41, psk)
      ]
      |> IO.iodata_to_binary()

    body =
      <<0x0303::16, 0::256, 0, 2::16, 0x1301::16, 1, 0, byte_size(extensions)::16,
        extensions::binary>>

    <<1, byte_size(body)::24, body::binary>>
  end

  defp server_hello(client_hello, public, cipher, share?) do
    {:ok, offer} = ClientOffer.from_client_hello(client_hello)
    share = if share?, do: ext(51, <<0x001D::16, 32::16, public::binary-size(32)>>), else: <<>>
    extensions = IO.iodata_to_binary([ext(43, <<0x0304::16>>), share, ext(41, <<0::16>>)])

    body = <<0x0303::16, 1::256, 0, cipher::16, 0, byte_size(extensions)::16, extensions::binary>>

    encoded = <<2, byte_size(body)::24, body::binary>>

    expectations = %{
      legacy_session_id: offer.legacy_session_id,
      offered_versions: offer.offered_versions,
      offered_ciphers: offer.cipher_suites,
      offered_groups: offer.supported_groups,
      offered_key_share_groups: Enum.map(offer.key_shares, & &1.group),
      offered_extension_ids: offer.extension_ids,
      offered_psk_key_exchange_modes: offer.psk_key_exchange_modes,
      offered_psk_count: offer.psk_count
    }

    case ServerHello.decode(encoded, expectations) do
      {:ok, parsed, <<>>} ->
        parsed

      {:error, _} ->
        %ServerHello{
          kind: :server_hello,
          legacy_version: 0x0303,
          random: <<1::256>>,
          legacy_session_id_echo: <<>>,
          cipher_suite: cipher,
          compression_method: 0,
          extensions: [{:supported_versions, 0x0304}, {:pre_shared_key, 0}],
          encoded: encoded
        }
    end
  end

  defp encrypted_extensions(protocol, early_data? \\ false) do
    alpn = ext(16, <<byte_size(protocol) + 1::16, byte_size(protocol), protocol::binary>>)
    extensions = if early_data?, do: alpn <> ext(42, <<>>), else: alpn
    <<8, byte_size(extensions) + 2::24, byte_size(extensions)::16, extensions::binary>>
  end

  defp ext(id, payload), do: <<id::16, byte_size(payload)::16, payload::binary>>
end
