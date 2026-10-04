defmodule SSL.Protocol.ServerHelloTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.{HandshakeFramer, ServerHello}

  @server_random :binary.copy(<<0>>, 32)
  @x25519_key :binary.copy(<<0xAA>>, 32)
  @session_id <<1, 2>>
  @hrr_random Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

  @server_hello Base.decode16!(
                  "020000580303" <>
                    String.duplicate("00", 32) <>
                    "020102130100002E" <>
                    "002B00020304" <>
                    "00330024001D0020" <>
                    String.duplicate("AA", 32)
                )

  @expectations %{
    legacy_session_id: @session_id,
    offered_ciphers: [0x1301],
    offered_groups: [0x001D, 0x0017],
    offered_key_share_groups: [0x001D],
    offered_extension_ids: [43, 51],
    offered_psk_key_exchange_modes: []
  }

  test "extension budgets count encoded entries and reject at the declared length" do
    hrr =
      hello(
        random: @hrr_random,
        extensions: [
          extension(43, <<0x0304::16>>),
          extension(51, <<23::16>>),
          extension(44, <<3::16, 1, 2, 3>>)
        ]
      )

    for {encoded, kind, size} <- [
          {@server_hello, :server_hello, 46},
          {hrr, :hello_retry_request, 21}
        ] do
      assert {:ok, %{encoded: ^encoded}, <<>>} = ServerHello.decode(encoded, @expectations)

      assert {:ok, _, <<>>} =
               ServerHello.decode(encoded, @expectations, max_extension_bytes: size)

      limit = size - 1
      expected = {:error, {:extension_length_exceeded, kind, size, limit}}
      assert ServerHello.decode(encoded, @expectations, max_extension_bytes: limit) == expected
      # Fixture has a two-byte session ID; its extension payload starts at 46.
      for split <- 0..byte_size(encoded) do
        prefix = binary_part(encoded, 0, split)
        result = ServerHello.decode(prefix, @expectations, max_extension_bytes: limit)
        if split < 46, do: assert(match?({:more, _}, result)), else: assert(result == expected)
      end
    end

    for limit <- [-1, nil, 65_536] do
      assert {:error, {:invalid_limit, :max_extension_bytes}} =
               ServerHello.decode(@server_hello, @expectations, max_extension_bytes: limit)
    end
  end

  test "decodes and preserves an exact ServerHello fixture" do
    assert {:ok, server_hello, <<>>} = ServerHello.decode(@server_hello, @expectations)

    assert %ServerHello{
             kind: :server_hello,
             legacy_version: 0x0303,
             random: @server_random,
             legacy_session_id_echo: @session_id,
             cipher_suite: 0x1301,
             compression_method: 0,
             extensions: [
               {:supported_versions, 0x0304},
               {:key_share, %{group: 0x001D, key_exchange: @x25519_key}}
             ],
             encoded: @server_hello
           } = server_hello
  end

  test "decodes and preserves an exact HelloRetryRequest fixture" do
    encoded =
      hello(
        random: @hrr_random,
        extensions: [
          extension(43, <<0x0304::16>>),
          extension(44, <<3::16, 1, 2, 3>>),
          extension(51, <<0x0017::16>>)
        ]
      )

    assert {:ok,
            %ServerHello{
              kind: :hello_retry_request,
              extensions: [
                {:supported_versions, 0x0304},
                {:cookie, <<1, 2, 3>>},
                {:selected_group, 0x0017}
              ],
              encoded: ^encoded
            }, <<>>} = ServerHello.decode(encoded, @expectations)
  end

  test "accepts a bounded PSK-only ServerHello selection" do
    encoded =
      hello(extensions: [extension(43, <<0x0304::16>>), extension(41, <<1::16>>)])

    expectations = %{
      @expectations
      | offered_extension_ids: [43, 41]
    }

    expectations =
      expectations
      |> Map.put(:offered_psk_count, 2)
      |> Map.put(:offered_psk_key_exchange_modes, [0])

    assert {:ok,
            %ServerHello{
              extensions: [{:supported_versions, 0x0304}, {:pre_shared_key, 1}]
            }, <<>>} = ServerHello.decode(encoded, expectations)
  end

  test "requires ServerHello key_share presence to match an offered PSK mode" do
    version = extension(43, <<0x0304::16>>)
    psk = extension(41, <<0::16>>)
    key_share = extension(51, <<0x001D::16, 32::16, @x25519_key::binary>>)

    base = %{
      @expectations
      | offered_extension_ids: [43, 41, 51],
        offered_psk_key_exchange_modes: [0]
    }

    psk_expectations = Map.put(base, :offered_psk_count, 1)

    assert {:ok, %ServerHello{}, <<>>} =
             ServerHello.decode(hello(extensions: [version, psk]), psk_expectations)

    assert {:error, {:psk_key_exchange_mode_not_offered, 1}} =
             ServerHello.decode(
               hello(extensions: [version, psk, key_share]),
               psk_expectations
             )

    dhe_expectations = %{psk_expectations | offered_psk_key_exchange_modes: [1]}

    assert {:ok, %ServerHello{}, <<>>} =
             ServerHello.decode(
               hello(extensions: [version, psk, key_share]),
               dhe_expectations
             )

    assert {:error, {:psk_key_exchange_mode_not_offered, 0}} =
             ServerHello.decode(hello(extensions: [version, psk]), dhe_expectations)
  end

  test "rejects a HelloRetryRequest that would not change ClientHello" do
    version = extension(43, <<0x0304::16>>)

    assert {:error, :hello_retry_request_would_not_change_client_hello} =
             ServerHello.decode(hello(random: @hrr_random, extensions: [version]), @expectations)

    assert {:ok, %ServerHello{kind: :hello_retry_request}, <<>>} =
             ServerHello.decode(
               hello(
                 random: @hrr_random,
                 extensions: [version, extension(44, <<1::16, 1>>)]
               ),
               @expectations
             )
  end

  test "returns concatenated remainder and retains only consumed exact bytes" do
    trailing = <<8, 0, 0, 0>>

    assert {:ok, %ServerHello{encoded: @server_hello}, ^trailing} =
             ServerHello.decode(@server_hello <> trailing, @expectations)
  end

  test "integrates with HandshakeFramer at every split point" do
    for split <- 0..byte_size(@server_hello) do
      <<first::binary-size(^split), second::binary>> = @server_hello
      buffer = HandshakeFramer.new()
      assert {:ok, first_messages, buffer} = HandshakeFramer.feed(buffer, first)
      assert {:ok, second_messages, buffer} = HandshakeFramer.feed(buffer, second)
      assert first_messages ++ second_messages == [@server_hello]
      assert HandshakeFramer.buffered_bytes(buffer) == <<>>

      assert {:ok, %ServerHello{encoded: @server_hello}, <<>>} =
               ServerHello.decode(@server_hello, @expectations)
    end
  end

  test "reports exact bytes still needed and rejects oversized declarations" do
    assert {:more, 4} = ServerHello.decode(<<>>, @expectations)
    assert {:more, 1} = ServerHello.decode(<<2, 0, 0>>, @expectations)

    expected = byte_size(@server_hello) - 5

    assert {:more, ^expected} =
             ServerHello.decode(binary_part(@server_hello, 0, 5), @expectations)

    assert {:error, {:unexpected_handshake_type, 1}} =
             ServerHello.decode(<<1, 0, 0, 0>>, @expectations)

    assert {:error, {:handshake_length_exceeded, 65_608, 65_607}} =
             ServerHello.decode(<<2, 65_608::24>>, @expectations)
  end

  test "validates expectation shape before consuming wire input" do
    for {expectations, field} <- [
          {nil, :structure},
          {Map.delete(@expectations, :legacy_session_id), :legacy_session_id},
          {%{@expectations | offered_ciphers: :all}, :offered_ciphers},
          {%{@expectations | offered_groups: [0x1_0000]}, :offered_groups},
          {%{@expectations | offered_key_share_groups: [0x001D, 0x001D]},
           :offered_key_share_groups},
          {%{@expectations | offered_extension_ids: [nil]}, :offered_extension_ids},
          {%{@expectations | offered_psk_key_exchange_modes: :all},
           :offered_psk_key_exchange_modes},
          {%{@expectations | offered_psk_key_exchange_modes: [2]},
           :offered_psk_key_exchange_modes},
          {Map.put(@expectations, :offered_psk_count, -1), :offered_psk_count}
        ] do
      assert {:error, {:invalid_expectations, ^field}} =
               ServerHello.decode(@server_hello, expectations)
    end

    assert {:error, {:invalid_input, :not_binary}} = ServerHello.decode(nil, @expectations)
  end

  test "rejects invalid fixed ServerHello fields" do
    assert {:error, {:invalid_legacy_version, 0x0304}} =
             ServerHello.decode(hello(legacy_version: 0x0304), @expectations)

    assert {:error, {:invalid_session_id_length, 33}} =
             ServerHello.decode(
               hello(session_id: :binary.copy(<<0>>, 33)),
               @expectations
             )

    assert {:error, {:session_id_mismatch, <<9>>}} =
             ServerHello.decode(hello(session_id: <<9>>), @expectations)

    assert {:error, {:cipher_not_offered, 0x1302}} =
             ServerHello.decode(hello(cipher_suite: 0x1302), @expectations)

    offered_legacy_cipher = %{@expectations | offered_ciphers: [0xC02F]}

    assert {:error, {:unsupported_selected_cipher, 0xC02F}} =
             ServerHello.decode(hello(cipher_suite: 0xC02F), offered_legacy_cipher)

    grease_expectations = %{@expectations | offered_ciphers: [0x0A0A]}

    assert {:error, {:grease_selected, :cipher_suite, 0x0A0A}} =
             ServerHello.decode(hello(cipher_suite: 0x0A0A), grease_expectations)

    assert {:error, {:invalid_compression_method, 1}} =
             ServerHello.decode(hello(compression_method: 1), @expectations)
  end

  test "requires offered key-share groups to be a subset of offered groups" do
    expectations = %{
      @expectations
      | offered_groups: [0x0017],
        offered_key_share_groups: [0x001D]
    }

    assert {:error, {:invalid_expectations, :offered_key_share_groups}} =
             ServerHello.decode(@server_hello, expectations)
  end

  property "bounded arbitrary input always returns the documented result shape" do
    check all(input <- binary(max_length: 512), max_runs: 100) do
      case ServerHello.decode(input, @expectations) do
        {:ok, %ServerHello{}, remainder} when is_binary(remainder) -> assert true
        {:more, needed} when is_integer(needed) and needed >= 0 -> assert true
        {:error, _reason} -> assert true
        other -> flunk("unexpected decode result: #{inspect(other)}")
      end
    end
  end

  test "rejects malformed, duplicate, forbidden, GREASE, and unoffered extensions" do
    malformed_vector = hello(extension_bytes: <<43, 0, 2>>)
    malformed_payload = hello(extension_bytes: <<43::16, 3::16, 3, 4>>)

    assert {:error, {:malformed_extension, :header}} =
             ServerHello.decode(malformed_vector, @expectations)

    assert {:error, {:malformed_extension, 43, :length}} =
             ServerHello.decode(malformed_payload, @expectations)

    duplicate =
      hello(extensions: [extension(43, <<0x0304::16>>), extension(43, <<0x0304::16>>)])

    assert {:error, {:duplicate_extension, 43}} =
             ServerHello.decode(duplicate, @expectations)

    assert {:error, {:forbidden_extension, :server_hello, 44}} =
             ServerHello.decode(hello(extensions: [extension(44, <<1::16, 1>>)]), @expectations)

    grease_expectations = %{@expectations | offered_extension_ids: [0x0A0A]}

    assert {:error, {:grease_selected, :extension, 0x0A0A}} =
             ServerHello.decode(
               hello(extensions: [extension(0x0A0A, <<>>)]),
               grease_expectations
             )

    assert {:error, {:forbidden_extension, :server_hello, 16}} =
             ServerHello.decode(hello(extensions: [extension(16, <<>>)]), @expectations)

    unoffered_expectations = %{@expectations | offered_extension_ids: [51]}

    assert {:error, {:extension_not_offered, 43}} =
             ServerHello.decode(@server_hello, unoffered_expectations)
  end

  test "requires exact TLS 1.3 version and ServerHello key establishment" do
    key_share = extension(51, <<0x001D::16, 32::16, @x25519_key::binary>>)

    assert {:error, :missing_supported_versions} =
             ServerHello.decode(hello(extensions: [key_share]), @expectations)

    assert {:error, {:invalid_supported_versions, <<3, 3>>}} =
             ServerHello.decode(
               hello(extensions: [extension(43, <<0x0303::16>>), key_share]),
               @expectations
             )

    assert {:error, :missing_key_establishment} =
             ServerHello.decode(
               hello(extensions: [extension(43, <<0x0304::16>>)]),
               @expectations
             )
  end

  test "rejects malformed, unoffered, unsupported, GREASE, and wrong-size key shares" do
    version = extension(43, <<0x0304::16>>)

    invalid_cases = [
      {extension(51, <<0x001D::16, 31::16, 0::size(31 * 8)>>),
       {:invalid_key_exchange, 0x001D, 31}},
      {extension(51, <<0x0017::16, 65::16, 3, 0::size(64 * 8)>>),
       {:invalid_key_exchange, 0x0017, 65}},
      {extension(51, <<0x0017::16, 64::16, 4, 0::size(63 * 8)>>),
       {:invalid_key_exchange, 0x0017, 64}},
      {extension(51, <<0x001D::16, 33::16, 0::size(32 * 8)>>),
       {:malformed_extension, 51, :key_exchange_length}}
    ]

    key_share_expectations = %{@expectations | offered_key_share_groups: [0x001D, 0x0017]}

    for {key_share, reason} <- invalid_cases do
      assert {:error, ^reason} =
               ServerHello.decode(
                 hello(extensions: [version, key_share]),
                 key_share_expectations
               )
    end

    not_offered = %{@expectations | offered_key_share_groups: [0x0017]}

    assert {:error, {:selected_group_not_offered, :key_share, 0x001D}} =
             ServerHello.decode(@server_hello, not_offered)

    for group <- [0x0019, 0x0A0A] do
      expectations = %{
        @expectations
        | offered_groups: [group],
          offered_key_share_groups: [group]
      }

      encoded =
        hello(extensions: [version, extension(51, <<group::16, 1::16, 0>>)])

      expected =
        if group == 0x0A0A,
          do: {:grease_selected, :group, group},
          else: {:unsupported_selected_group, group}

      assert {:error, ^expected} = ServerHello.decode(encoded, expectations)
    end
  end

  test "validates PSK selection and HelloRetryRequest cookie/group semantics" do
    version = extension(43, <<0x0304::16>>)

    psk_expectations =
      @expectations
      |> Map.merge(%{offered_extension_ids: [43, 41], offered_psk_key_exchange_modes: [0]})
      |> Map.put(:offered_psk_count, 1)

    assert {:error, {:invalid_selected_identity, 1, 1}} =
             ServerHello.decode(
               hello(extensions: [version, extension(41, <<1::16>>)]),
               psk_expectations
             )

    assert {:error, {:malformed_extension, 41, {:expected_length, 2, 1}}} =
             ServerHello.decode(
               hello(extensions: [version, extension(41, <<0>>)]),
               psk_expectations
             )

    assert {:error, {:invalid_cookie, :malformed}} =
             ServerHello.decode(
               hello(random: @hrr_random, extensions: [version, extension(44, <<0::16>>)]),
               @expectations
             )

    assert {:error, {:hello_retry_request_group_already_offered, 0x001D}} =
             ServerHello.decode(
               hello(random: @hrr_random, extensions: [version, extension(51, <<0x001D::16>>)]),
               @expectations
             )

    assert {:error, {:selected_group_not_offered, :supported_groups, 0x0017}} =
             ServerHello.decode(
               hello(random: @hrr_random, extensions: [version, extension(51, <<0x0017::16>>)]),
               %{@expectations | offered_groups: [0x001D]}
             )

    assert {:error, {:unsupported_selected_group, 0x0019}} =
             ServerHello.decode(
               hello(random: @hrr_random, extensions: [version, extension(51, <<0x0019::16>>)]),
               %{@expectations | offered_groups: [0x0019], offered_key_share_groups: []}
             )
  end

  defp hello(opts) do
    legacy_version = Keyword.get(opts, :legacy_version, 0x0303)
    random = Keyword.get(opts, :random, @server_random)
    session_id = Keyword.get(opts, :session_id, @session_id)
    cipher_suite = Keyword.get(opts, :cipher_suite, 0x1301)
    compression_method = Keyword.get(opts, :compression_method, 0)

    extension_bytes =
      Keyword.get_lazy(opts, :extension_bytes, fn ->
        opts
        |> Keyword.get(:extensions, [
          extension(43, <<0x0304::16>>),
          extension(51, <<0x001D::16, 32::16, @x25519_key::binary>>)
        ])
        |> IO.iodata_to_binary()
      end)

    body =
      <<legacy_version::16, random::binary, byte_size(session_id), session_id::binary,
        cipher_suite::16, compression_method, byte_size(extension_bytes)::16,
        extension_bytes::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end

  defp extension(id, payload), do: <<id::16, byte_size(payload)::16, payload::binary>>
end
