defmodule SSL.Protocol.ServerFlightVerifierTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Crypto.{AEAD, KeyExchange, KeySchedule}
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.Protocol.{HandshakeFramer, Record, ServerFlightVerifier, ServerHello, Transcript}
  alias SSL.Protocol.ServerFlightVerifier.{Input, Result}

  @fixture_dir Path.expand("../../fixtures/server_flight", __DIR__)
  @capture @fixture_dir
           |> Path.join("capture.txt")
           |> File.read!()
           |> String.split("\n", trim: true)
           |> Map.new(fn line ->
             [name, value] = String.split(line, "=", parts: 2)
             {String.to_atom(name), Base.decode16!(value)}
           end)
  @root_pem File.read!(Path.join(@fixture_dir, "root.pem"))
  @wrong_root_pem File.read!(Path.expand("../../fixtures/pkix/wrong_root.pem", __DIR__))
  @leaf_key_path Path.join(@fixture_dir, "leaf-key.pem")
  @leaf_path Path.join(@fixture_dir, "leaf.pem")
  @rsa_leaf_path Path.join(@fixture_dir, "leaf-rsa.pem")
  @rsa_leaf_key_path Path.join(@fixture_dir, "leaf-rsa-key.pem")

  test "verifies the constructed fragmented and coalesced server flight" do
    assert {:ok,
            %Result{
              verified_peer: %{leaf_der: leaf_der},
              server_handshake_state: %{sequence: 3},
              client_handshake_state: %{sequence: 1},
              client_finished_record: client_finished_record,
              client_application_state: client_application,
              server_application_state: server_application,
              transcript: transcript
            } = result} = ServerFlightVerifier.verify(input())

    assert client_finished_record == @capture.client_finished_record
    assert Transcript.digest(transcript) == @capture.transcript_digest
    assert transcript.hash == :sha384
    assert client_application.key == @capture.client_app_key
    assert client_application.iv == @capture.client_app_iv
    assert server_application.key == @capture.server_app_key
    assert server_application.iv == @capture.server_app_iv
    assert leaf_der == pem_der(Path.join(@fixture_dir, "leaf.pem"))

    inspected = inspect(result)
    refute inspected =~ Base.encode16(client_application.key)
    refute inspected =~ Base.encode16(server_application.key)
    refute inspected =~ Base.encode16(@capture.client_private)
  end

  test "record-free client core reproduces independently constructed flight secrets and bytes" do
    core_input = input() |> Map.from_struct() |> Map.delete(:records)
    assert {:ok, core} = SSL.Protocol.HandshakeCore.start_client(core_input, [])
    refute Map.has_key?(core.secrets, :client_handshake_state)
    refute Map.has_key?(core.secrets, :server_handshake_state)

    [ee, cert, cv, finished] = captured_messages()
    assert {:ok, core} = SSL.Protocol.HandshakeCore.process_message(core, ee)
    assert {:ok, core} = SSL.Protocol.HandshakeCore.process_message(core, cert)
    assert {:ok, core} = SSL.Protocol.HandshakeCore.process_message(core, cv)

    assert {:connected, result, [client_finished]} =
             SSL.Protocol.HandshakeCore.process_message(core, finished)

    assert {:ok, client_state} =
             KeySchedule.traffic_state(result.suite, result.client_application_secret)

    assert {:ok, server_state} =
             KeySchedule.traffic_state(result.suite, result.server_application_secret)

    assert client_state.key == @capture.client_app_key
    assert server_state.key == @capture.server_app_key
    assert Transcript.digest(result.transcript) == @capture.transcript_digest

    assert {:ok, write} =
             KeySchedule.traffic_state(result.suite, core.secrets.client_handshake_secret)

    assert {:ok, record, _} = Record.encrypt(write, :handshake, client_finished)
    assert record == @capture.client_finished_record
    refute inspect(result) =~ inspect(result.client_application_secret)
  end

  test "record-free core rejects altered signatures and Finished before returning secrets" do
    attrs = input() |> Map.from_struct() |> Map.delete(:records)
    assert {:ok, initial} = SSL.Protocol.HandshakeCore.start_client(attrs, [])
    [ee, cert, cv, finished] = captured_messages()
    assert {:ok, core} = SSL.Protocol.HandshakeCore.process_message(initial, ee)
    assert {:ok, core} = SSL.Protocol.HandshakeCore.process_message(core, cert)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_certificate_verify}} =
             SSL.Protocol.HandshakeCore.process_message(core, flip_last_bit(cv))

    assert {:ok, core} = SSL.Protocol.HandshakeCore.process_message(core, cv)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} =
             SSL.Protocol.HandshakeCore.process_message(core, flip_last_bit(finished))

    refute inspect(core) =~ inspect(core.secrets.master_secret)
    assert core.input.client_key_pair == nil
    refute inspect(core) =~ inspect(attrs.client_key_pair.private_key)
  end

  test "record-free core still requires trust and independent reference identity" do
    [ee, cert | _] = captured_messages()

    for {overrides, expected} <- [
          {[identity: {:dns_id, "wrong.example.test"}],
           {:fatal_alert, :certificate_unknown, :hostname_mismatch}},
          {[trust_source: @wrong_root_pem], :unknown_ca}
        ] do
      attrs = input(overrides) |> Map.from_struct() |> Map.delete(:records)
      assert {:ok, core} = SSL.Protocol.HandshakeCore.start_client(attrs, [])
      assert {:ok, core} = SSL.Protocol.HandshakeCore.process_message(core, ee)
      result = SSL.Protocol.HandshakeCore.process_message(core, cert)

      case expected do
        :unknown_ca ->
          assert {:error, {:fatal_alert, :unknown_ca, {:path_validation_failed, _}}} = result

        reason ->
          assert {:error, ^reason} = result
      end
    end
  end

  test "verifies a full SHA-384 transcript with RSA-PSS-RSAE-SHA256" do
    flight =
      SSL.TestServerFlightBuilder.build(
        signature_scheme: 0x0804,
        leaf_pem: @rsa_leaf_path,
        leaf_key_pem: @rsa_leaf_key_path
      )

    assert {:ok, %Result{transcript: %{hash: :sha384}}} =
             ServerFlightVerifier.verify(input_from_flight(flight))
  end

  test "maps tampered AEAD authentication to bad_record_mac" do
    [first | rest] = capture_records()

    assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
             ServerFlightVerifier.verify(input(records: [flip_last_bit(first) | rest]))
  end

  test "classifies unexpected outer record content types before authentication" do
    for outer_type <- [22, 25] do
      <<_original_type, remainder::binary>> = authenticate_raw(<<1, 22>>)
      record = <<outer_type, remainder::binary>>

      assert {:error,
              {:fatal_alert, :unexpected_message, {:unexpected_outer_content_type, ^outer_type}}} =
               ServerFlightVerifier.verify(input(records: [record]))
    end
  end

  test "classifies authenticated inner overflow precisely" do
    oversized = :binary.copy(<<1>>, 16_384) <> <<22, 0>>

    assert {:error,
            {:fatal_alert, :record_overflow, {:inner_plaintext_length_exceeded, 16_386, 16_385}}} =
             ServerFlightVerifier.verify(input(records: [authenticate_raw(oversized)]))

    assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
             ServerFlightVerifier.verify(
               input(records: [authenticate_raw(oversized) |> flip_last_bit()])
             )
  end

  test "classifies authenticated empty and missing inner content precisely" do
    invalid_plaintexts = [
      {<<>>, :empty_inner_plaintext},
      {<<0>>, :missing_inner_content_type},
      {<<0, 0>>, :missing_inner_content_type},
      {<<21>>, {:empty_content, :alert}},
      {<<21, 0>>, {:empty_content, :alert}},
      {<<22>>, {:empty_content, :handshake}},
      {<<22, 0>>, {:empty_content, :handshake}}
    ]

    for {plaintext, reason} <- invalid_plaintexts do
      record = authenticate_raw(plaintext)

      assert {:error, {:fatal_alert, :unexpected_message, ^reason}} =
               ServerFlightVerifier.verify(input(records: [record]))

      assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
               ServerFlightVerifier.verify(input(records: [flip_last_bit(record)]))
    end
  end

  test "classifies authenticated unsupported inner content types precisely" do
    for type <- [20, 25], padding <- [<<>>, <<0>>, <<0, 0>>] do
      record = authenticate_raw(<<1, type, padding::binary>>)

      assert {:error,
              {:fatal_alert, :unexpected_message, {:unsupported_inner_content_type, ^type}}} =
               ServerFlightVerifier.verify(input(records: [record]))

      assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
               ServerFlightVerifier.verify(input(records: [flip_last_bit(record)]))
    end
  end

  test "classifies an oversized outer record before authentication" do
    oversized = <<23, 3, 3, 16_641::16, 0::size(16_641 * 8)>>

    assert {:error, {:fatal_alert, :record_overflow, {:record_length_exceeded, 16_641, 16_640}}} =
             ServerFlightVerifier.verify(input(records: [oversized]))

    generic_limit = <<23, 3, 3, 16_640::16, 0::size(16_640 * 8)>>

    assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
             ServerFlightVerifier.verify(input(records: [generic_limit]))
  end

  test "maps untrusted chains and wrong identities to certificate alerts" do
    assert {:error, {:fatal_alert, :unknown_ca, {:path_validation_failed, _reason}}} =
             ServerFlightVerifier.verify(input(trust_source: @wrong_root_pem))

    assert {:error, {:fatal_alert, :certificate_unknown, :hostname_mismatch}} =
             ServerFlightVerifier.verify(input(identity: {:dns_id, "wrong.example.test"}))
  end

  test "passes depth through to PKIX path validation" do
    assert {:ok, %Result{}} = ServerFlightVerifier.verify(input(), depth: 0)

    assert {:error, {:fatal_alert, :decode_error, {:invalid_options, :depth}}} =
             ServerFlightVerifier.verify(input(), depth: -1)
  end

  test "maps an invalid caller DNS identity to illegal_parameter" do
    identity = {:dns_id, ".example.test"}

    assert {:error, {:fatal_alert, :illegal_parameter, {:invalid_identity, ^identity}}} =
             ServerFlightVerifier.verify(input(identity: identity))
  end

  test "rejects a correctly authenticated unoffered ALPN selection" do
    flight =
      constructed_flight(
        encrypted_extensions: [{16, <<9::16, 8, "http/1.1">>}],
        client_options: [alpn_protocols: ["h2"]]
      )

    assert {:error, {:fatal_alert, :illegal_parameter, {:alpn_not_offered, "http/1.1"}}} =
             ServerFlightVerifier.verify(input_from_flight(flight))
  end

  test "validates ALPN as exact opaque values and permits an absent response" do
    for protocol <- ["h2", "http/1.1"] do
      flight = constructed_flight(encrypted_extensions: [{16, alpn_payload([protocol])}])

      assert {:ok, %Result{negotiated_protocol: ^protocol}} =
               ServerFlightVerifier.verify(input_from_flight(flight))
    end

    absent = constructed_flight(encrypted_extensions: [])

    assert {:ok, %Result{negotiated_protocol: nil}} =
             ServerFlightVerifier.verify(input_from_flight(absent))

    case_mismatch =
      constructed_flight(
        encrypted_extensions: [{16, alpn_payload(["H2"])}],
        client_options: [alpn_protocols: ["h2"]]
      )

    assert {:error, {:fatal_alert, :illegal_parameter, {:alpn_not_offered, "H2"}}} =
             ServerFlightVerifier.verify(input_from_flight(case_mismatch))
  end

  test "rejects unsolicited and malformed ALPN with precise reasons" do
    unsolicited =
      constructed_flight(
        encrypted_extensions: [{16, alpn_payload(["h2"])}],
        client_options: [alpn_protocols: []]
      )

    assert {:error, {:fatal_alert, :unsupported_extension, {:unsolicited_extension, 16}}} =
             ServerFlightVerifier.verify(input_from_flight(unsolicited))

    for payload <- [<<0::16>>, alpn_payload(["h2", "http/1.1"])] do
      malformed = constructed_flight(encrypted_extensions: [{16, payload}])

      assert {:error, {:fatal_alert, :decode_error, {:malformed_extension, 16, :alpn}}} =
               ServerFlightVerifier.verify(input_from_flight(malformed))
    end
  end

  test "classifies a forbidden EncryptedExtensions extension as illegal_parameter" do
    valid_flight = constructed_flight(encrypted_extensions: [])
    flight = constructed_flight(encrypted_extensions: [{43, <<0x0304::16>>}])
    unsupported_flight = constructed_flight(encrypted_extensions: [{0xFAFA, <<>>}])

    assert {:ok, %Result{}} = ServerFlightVerifier.verify(input_from_flight(valid_flight))

    assert {:error,
            {:fatal_alert, :illegal_parameter, {:forbidden_extension, :encrypted_extensions, 43}}} =
             ServerFlightVerifier.verify(input_from_flight(flight))

    assert {:error,
            {:fatal_alert, :unsupported_extension,
             {:unsupported_extension, :encrypted_extensions, 0xFAFA}}} =
             ServerFlightVerifier.verify(input_from_flight(unsupported_flight))
  end

  test "rejects early_data in the certificate-authenticated non-PSK flow" do
    unsolicited = constructed_flight(encrypted_extensions: [{42, <<>>}])

    assert {:error, {:fatal_alert, :unsupported_extension, {:unsolicited_extension, 42}}} =
             ServerFlightVerifier.verify(input_from_flight(unsolicited))

    impossible =
      constructed_flight(
        encrypted_extensions: [{42, <<>>}],
        client_options: [early_data: true]
      )

    assert {:error, {:fatal_alert, :illegal_parameter, {:early_data_not_permitted, :non_psk}}} =
             ServerFlightVerifier.verify(input_from_flight(impossible))
  end

  test "rejects unsolicited CertificateEntry OCSP and SCT responses on every entry" do
    status_request = {5, <<1, 4::24, "ocsp">>}
    sct = {18, <<3::16, "sct">>}

    for {id, extension} <- [{5, status_request}, {18, sct}] do
      offered = constructed_flight(certificate_extensions: [extension])
      assert {:ok, %Result{}} = ServerFlightVerifier.verify(input_from_flight(offered))

      leaf_response =
        constructed_flight(
          certificate_extensions: [extension],
          client_options: [{extension_option(id), false}]
        )

      assert {:error,
              {:fatal_alert, :unsupported_extension, {:unsolicited_certificate_extension, ^id, 0}}} =
               ServerFlightVerifier.verify(input_from_flight(leaf_response))

      later_response =
        constructed_flight(
          additional_certificate_entries: [{@root_pem, [extension]}],
          client_options: [{extension_option(id), false}]
        )

      assert {:error,
              {:fatal_alert, :unsupported_extension, {:unsolicited_certificate_extension, ^id, 1}}} =
               ServerFlightVerifier.verify(input_from_flight(later_response))
    end
  end

  test "rejects invalid CertificateVerify and Finished with decrypt_error" do
    messages = captured_messages()
    invalid_signature = List.update_at(messages, 2, &flip_last_bit/1)
    invalid_finished = List.update_at(messages, 3, &flip_last_bit/1)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_certificate_verify}} =
             ServerFlightVerifier.verify(input(records: encrypt_messages(invalid_signature)))

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} =
             ServerFlightVerifier.verify(input(records: encrypt_messages(invalid_finished)))
  end

  test "rejects empty, excessive, malformed, and incomplete record flights" do
    assert {:error, {:fatal_alert, :unexpected_message, :empty_server_flight}} =
             ServerFlightVerifier.verify(input(records: []))

    assert {:error, {:fatal_alert, :decode_error, {:record_count_limit_exceeded, 3, 2}}} =
             ServerFlightVerifier.verify(input(), max_records: 2)

    records_with_unchecked_tail = [<<>>, <<>>, <<>> | :not_a_list]

    assert {:error, {:fatal_alert, :decode_error, {:record_count_limit_exceeded, 3, 2}}} =
             ServerFlightVerifier.verify(input(records: records_with_unchecked_tail),
               max_records: 2
             )

    first_record = hd(capture_records())
    <<_header::binary-size(3), declared_length::16, body::binary>> = first_record
    invalid_declared_length = declared_length + 1
    actual_length = byte_size(body)

    assert {:error,
            {:fatal_alert, :decode_error,
             {:record_length_mismatch, ^invalid_declared_length, ^actual_length}}} =
             ServerFlightVerifier.verify(
               input(records: [set_record_length(first_record, declared_length + 1)])
             )

    stream = IO.iodata_to_binary(captured_messages())
    incomplete = binary_part(stream, 0, byte_size(stream) - 1)

    assert {:error, {:fatal_alert, :decode_error, {:incomplete_handshake, _bytes}}} =
             ServerFlightVerifier.verify(input(records: encrypt_stream(incomplete)))
  end

  test "rejects out-of-order, duplicate, trailing, alert, and application data messages" do
    [encrypted_extensions, certificate, certificate_verify, finished] = captured_messages()

    out_of_order = [certificate, encrypted_extensions, certificate_verify, finished]
    duplicate = [encrypted_extensions, encrypted_extensions, certificate_verify, finished]
    trailing = [encrypted_extensions, certificate, certificate_verify, finished, finished]

    for messages <- [out_of_order, duplicate, trailing] do
      assert {:error, {:fatal_alert, :unexpected_message, _reason}} =
               ServerFlightVerifier.verify(input(records: encrypt_messages(messages)))
    end

    for type <- [:alert, :application_data] do
      assert {:error,
              {:fatal_alert, :unexpected_message, {:unexpected_inner_content_type, ^type}}} =
               ServerFlightVerifier.verify(
                 input(records: encrypt_stream(encrypted_extensions, type))
               )
    end
  end

  test "rejects HelloRetryRequest and key-share mismatches explicitly" do
    server_hello = server_hello()

    assert {:error, {:fatal_alert, :illegal_parameter, {:server_hello_semantics_mismatch, :kind}}} =
             ServerFlightVerifier.verify(
               input(server_hello: %{server_hello | kind: :hello_retry_request})
             )

    assert {:ok, wrong_pair} = KeyExchange.generate(:secp256r1)

    assert {:error, {:fatal_alert, :illegal_parameter, {:key_share_group_mismatch, _, _}}} =
             ServerFlightVerifier.verify(input(client_key_pair: wrong_pair))
  end

  test "rejects supplied ServerHello semantics that diverge from its exact bytes" do
    original = server_hello()
    {:key_share, key_share} = Enum.find(original.extensions, &match?({:key_share, _}, &1))

    mutations = [
      {:cipher_suite, %{original | cipher_suite: 0x1301}},
      {:random, %{original | random: :binary.copy(<<0>>, 32)}},
      {:legacy_session_id_echo, %{original | legacy_session_id_echo: <<1>>}},
      {:legacy_version, %{original | legacy_version: 0x0304}},
      {:compression_method, %{original | compression_method: 1}},
      {:kind, %{original | kind: :hello_retry_request}},
      {:version,
       %{
         original
         | extensions:
             List.keyreplace(
               original.extensions,
               :supported_versions,
               0,
               {:supported_versions, 0x0303}
             )
       }},
      {:key_share,
       %{
         original
         | extensions:
             List.keyreplace(
               original.extensions,
               :key_share,
               0,
               {:key_share, %{key_share | key_exchange: flip_last_bit(key_share.key_exchange)}}
             )
       }}
    ]

    for {field, supplied} <- mutations do
      assert {:error,
              {:fatal_alert, :illegal_parameter, {:server_hello_semantics_mismatch, ^field}}} =
               ServerFlightVerifier.verify(input(server_hello: supplied))
    end
  end

  test "rejects encoded ServerHello selections outside the exact offer" do
    original = server_hello()
    encoded = replace_server_hello_cipher(original.encoded, 0x1301)

    assert {:error, {:fatal_alert, :illegal_parameter, {:cipher_not_offered, 0x1301}}} =
             ServerFlightVerifier.verify(
               input(server_hello: %{original | cipher_suite: 0x1301, encoded: encoded})
             )

    encoded =
      :binary.replace(
        original.encoded,
        <<0, 51, 0, 36, 0, 29>>,
        <<0, 51, 0, 36, 0, 23>>
      )

    assert {:error,
            {:fatal_alert, :illegal_parameter, {:selected_group_not_offered, :key_share, 0x0017}}} =
             ServerFlightVerifier.verify(input(server_hello: %{original | encoded: encoded}))
  end

  test "rejects a client key pair not coherent with the offered public share" do
    pair = client_key_pair()
    mismatched = %{pair | public_key: flip_last_bit(pair.public_key)}

    assert {:error, {:fatal_alert, :illegal_parameter, {:key_pair_mismatch, :x25519}}} =
             ServerFlightVerifier.verify(input(client_key_pair: mismatched))
  end

  test "rejects verifier options that widen the exact client offer" do
    assert {:error,
            {:fatal_alert, :illegal_parameter, {:offer_override_conflict, :offered_extension_ids}}} =
             ServerFlightVerifier.verify(input(), offered_extension_ids: [10, 13, 43, 51])

    assert {:error,
            {:fatal_alert, :illegal_parameter,
             {:offer_override_conflict, :allowed_signature_schemes}}} =
             ServerFlightVerifier.verify(input(), allowed_signature_schemes: [0x0804])
  end

  test "rejects malformed inputs and options with explicit fatal alerts" do
    assert {:error, {:fatal_alert, :decode_error, {:invalid_input, :verifier}}} =
             ServerFlightVerifier.verify(nil)

    assert {:error, {:fatal_alert, :decode_error, {:invalid_options, :verifier}}} =
             ServerFlightVerifier.verify(input(), nil)

    assert {:error, {:fatal_alert, :decode_error, {:invalid_options, :verifier}}} =
             ServerFlightVerifier.verify(input(), unknown: true)
  end

  test "rejects malformed allowed signature schemes with a precise option error" do
    for policy <- [
          nil,
          false,
          :all,
          0x0403,
          <<4, 3>>,
          %{},
          {:invalid, 0x0403},
          [nil],
          [-1],
          [65_536],
          [0x0403, 0x0403],
          [0x0403 | :bad],
          [0x0403 | "bad"]
        ] do
      assert {:error,
              {:fatal_alert, :decode_error, {:invalid_options, :allowed_signature_schemes}}} =
               ServerFlightVerifier.verify(input(), allowed_signature_schemes: policy)
    end
  end

  test "validates an improper signature policy before parsing verifier input" do
    improper_policy = [0x0403 | :bad]

    assert {:error, {:fatal_alert, :decode_error, {:invalid_options, :allowed_signature_schemes}}} =
             ServerFlightVerifier.verify(input(client_hello: <<>>),
               allowed_signature_schemes: improper_policy
             )
  end

  test "preserves default, narrowing, empty, and widening signature policy behavior" do
    assert {:ok, %Result{}} = ServerFlightVerifier.verify(input())

    assert {:ok, %Result{}} =
             ServerFlightVerifier.verify(input(), allowed_signature_schemes: [0x0403])

    assert {:error, {:fatal_alert, :illegal_parameter, {:signature_scheme_not_offered, 0x0403}}} =
             ServerFlightVerifier.verify(input(), allowed_signature_schemes: [])

    assert {:error,
            {:fatal_alert, :illegal_parameter,
             {:offer_override_conflict, :allowed_signature_schemes}}} =
             ServerFlightVerifier.verify(input(), allowed_signature_schemes: [0x0804])
  end

  property "bounded malformed signature policies return the precise option error" do
    check all(policy <- malformed_signature_policy(), max_runs: 100) do
      result = ServerFlightVerifier.verify(input(), allowed_signature_schemes: policy)

      assert {:error,
              {:fatal_alert, :decode_error, {:invalid_options, :allowed_signature_schemes}}} =
               result
    end
  end

  test "rejects an improper ServerHello extension list without raising" do
    server_hello = %{server_hello() | extensions: [{:unknown, nil} | :not_a_list]}

    assert {:error, {:fatal_alert, :illegal_parameter, :malformed_server_hello_extensions}} =
             ServerFlightVerifier.verify(input(server_hello: server_hello))
  end

  test "rejects missing, duplicate, and PSK ServerHello key establishment" do
    server_hello = server_hello()
    key_share = Enum.find(server_hello.extensions, &match?({:key_share, _}, &1))

    assert {:error,
            {:fatal_alert, :illegal_parameter, {:server_hello_semantics_mismatch, :key_share}}} =
             ServerFlightVerifier.verify(
               input(
                 server_hello: %{
                   server_hello
                   | extensions: [{:supported_versions, 0x0304}]
                 }
               )
             )

    duplicate_key_share = %{server_hello | extensions: server_hello.extensions ++ [key_share]}

    assert {:error,
            {:fatal_alert, :illegal_parameter, {:server_hello_semantics_mismatch, :extensions}}} =
             ServerFlightVerifier.verify(input(server_hello: duplicate_key_share))

    psk = %{server_hello | extensions: server_hello.extensions ++ [{:pre_shared_key, 0}]}

    assert {:error,
            {:fatal_alert, :illegal_parameter, {:server_hello_semantics_mismatch, :extensions}}} =
             ServerFlightVerifier.verify(input(server_hello: psk))
  end

  property "bounded malformed ServerHello extension entries return structured errors" do
    check all(
            extension <-
              member_of([nil, false, {:key_share}, {:key_share, nil}, {:unknown, nil}]),
            max_runs: 25
          ) do
      server_hello = %{server_hello() | extensions: [extension]}

      assert {:error, {:fatal_alert, :illegal_parameter, _reason}} =
               ServerFlightVerifier.verify(input(server_hello: server_hello))
    end
  end

  property "bounded malformed record flights return structured errors without raising" do
    check all(
            records <- list_of(binary(max_length: 64), max_length: 6),
            max_runs: 100
          ) do
      assert match?({:ok, %Result{}}, ServerFlightVerifier.verify(input(records: records))) or
               match?(
                 {:error, {:fatal_alert, _alert, _reason}},
                 ServerFlightVerifier.verify(input(records: records))
               )
    end
  end

  defp input(overrides \\ []) when is_list(overrides) do
    struct!(
      Input,
      Keyword.merge(
        [
          client_hello: @capture.client_hello,
          server_hello: server_hello(),
          client_key_pair: client_key_pair(),
          records: capture_records(),
          trust_source: @root_pem,
          identity: {:dns_id, "example.test"}
        ],
        overrides
      )
    )
  end

  defp malformed_signature_policy do
    invalid_identifier =
      one_of([
        constant(nil),
        integer(-65_536..-1),
        integer(65_536..131_072),
        binary(max_length: 8),
        constant(%{}),
        constant({:invalid, 0x0403})
      ])

    one_of([
      constant(nil),
      constant(false),
      atom(:alphanumeric),
      integer(),
      binary(max_length: 8),
      constant(%{}),
      constant({:invalid, 0x0403}),
      list_of(invalid_identifier, min_length: 1, max_length: 8),
      constant([0x0403, 0x0403]),
      map(
        one_of([atom(:alphanumeric), binary(min_length: 1, max_length: 8)]),
        fn tail -> [0x0403 | tail] end
      )
    ])
  end

  defp constructed_flight(options) do
    SSL.TestServerFlightBuilder.build(
      Keyword.merge(
        [signature_scheme: 0x0403, leaf_pem: @leaf_path, leaf_key_pem: @leaf_key_path],
        options
      )
    )
  end

  defp input_from_flight(flight, overrides \\ []) do
    struct!(
      Input,
      Keyword.merge(
        [
          client_hello: flight.client_hello,
          server_hello: server_hello(flight),
          client_key_pair: %KeyPair{
            group: :x25519,
            public_key: flight.client_public,
            private_key: flight.client_private
          },
          records: [flight.record_1, flight.record_2, flight.record_3],
          trust_source: @root_pem,
          identity: {:dns_id, "example.test"}
        ],
        overrides
      )
    )
  end

  defp server_hello do
    expectations = %{
      legacy_session_id: <<>>,
      offered_ciphers: [0x1302],
      offered_groups: [0x001D],
      offered_key_share_groups: [0x001D],
      offered_extension_ids: [5, 10, 13, 16, 18, 43, 51],
      offered_psk_key_exchange_modes: []
    }

    assert {:ok, server_hello, <<>>} = ServerHello.decode(@capture.server_hello, expectations)
    server_hello
  end

  defp server_hello(flight) do
    assert {:ok, offer} = SSL.Protocol.ClientOffer.from_client_hello(flight.client_hello)

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

    assert {:ok, server_hello, <<>>} = ServerHello.decode(flight.server_hello, expectations)
    server_hello
  end

  # RFC 7748 section 6.1 deterministic scalar, used only as test-vector input.
  defp client_key_pair do
    %KeyPair{
      group: :x25519,
      public_key: @capture.client_public,
      private_key: @capture.client_private
    }
  end

  defp capture_records,
    do: [@capture.record_1, @capture.record_2, @capture.record_3]

  defp captured_messages do
    {messages, framer, _state} =
      Enum.reduce(capture_records(), {[], HandshakeFramer.new(), server_handshake_state()}, fn
        record, {messages, framer, state} ->
          assert {:ok, :handshake, plaintext, state} = Record.decrypt(state, record)
          assert {:ok, decoded, framer} = HandshakeFramer.feed(framer, plaintext)
          {messages ++ decoded, framer, state}
      end)

    assert HandshakeFramer.buffered_bytes(framer) == <<>>
    messages
  end

  defp encrypt_messages(messages), do: encrypt_stream(IO.iodata_to_binary(messages))

  defp encrypt_stream(stream, type \\ :handshake) do
    assert {:ok, record, _state} = Record.encrypt(server_handshake_state(), type, stream)
    [record]
  end

  defp server_handshake_state do
    server_hello = server_hello()

    {:key_share, %{key_exchange: peer_public}} =
      Enum.find(server_hello.extensions, &match?({:key_share, _}, &1))

    assert {:ok, shared_secret} = KeyExchange.shared_secret(client_key_pair(), peer_public)
    assert {:ok, early_secret} = KeySchedule.early_secret(:sha384, nil)

    assert {:ok, handshake_secret} =
             KeySchedule.handshake_secret(:sha384, early_secret, shared_secret)

    transcript =
      Transcript.new(:sha384)
      |> Transcript.append(@capture.client_hello)
      |> Transcript.append(server_hello.encoded)

    assert {:ok, traffic_secret} =
             KeySchedule.server_handshake_traffic_secret(
               :sha384,
               handshake_secret,
               Transcript.digest(transcript)
             )

    assert {:ok, state} =
             KeySchedule.traffic_state(:tls_aes_256_gcm_sha384, traffic_secret)

    state
  end

  defp pem_der(path) do
    [entry] = path |> File.read!() |> :public_key.pem_decode()
    elem(entry, 1)
  end

  defp set_record_length(<<type, version::16, _length::16, body::binary>>, length),
    do: <<type, version::16, length::16, body::binary>>

  defp alpn_payload(protocols) do
    entries = IO.iodata_to_binary(Enum.map(protocols, &<<byte_size(&1), &1::binary>>))
    <<byte_size(entries)::16, entries::binary>>
  end

  defp extension_option(5), do: :status_request
  defp extension_option(18), do: :signed_certificate_timestamps

  defp replace_server_hello_cipher(
         <<2, _length::24, legacy::16, random::binary-size(32), session_length, rest::binary>>,
         cipher
       ) do
    <<session::binary-size(^session_length), _old_cipher::16, tail::binary>> = rest

    body =
      <<legacy::16, random::binary, session_length, session::binary, cipher::16, tail::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end

  defp flip_last_bit(binary) do
    prefix_size = byte_size(binary) - 1
    <<prefix::binary-size(^prefix_size), last>> = binary
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end

  defp authenticate_raw(inner_plaintext) do
    length = byte_size(inner_plaintext) + 16
    header = <<23, 3, 3, length::16>>

    assert {:ok, ciphertext, tag} =
             AEAD.encrypt(server_handshake_state(), header, inner_plaintext)

    <<header::binary, ciphertext::binary, tag::binary>>
  end
end
