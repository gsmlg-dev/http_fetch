defmodule SSL.Protocol.ServerHello do
  @moduledoc """
  Pure, bounded decoder for TLS 1.3 ServerHello and HelloRetryRequest messages.

  The input starts at a handshake header. A successful decode retains the exact
  consumed bytes and returns any concatenated handshake bytes as the remainder.
  """

  @hello_retry_request_random Base.decode16!(
                                "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
                              )
  @grease_values Enum.map(0..15, &(0x0A0A + &1 * 0x1010))
  @maximum_body_length 65_607
  @server_hello_type 2

  @type kind :: :server_hello | :hello_retry_request
  @type extension ::
          {:supported_versions, 0x0304}
          | {:key_share, %{group: 0..0xFFFF, key_exchange: binary()}}
          | {:selected_group, 0..0xFFFF}
          | {:pre_shared_key, non_neg_integer()}
          | {:cookie, binary()}

  @type t :: %__MODULE__{
          kind: kind(),
          legacy_version: 0x0303,
          random: binary(),
          legacy_session_id_echo: binary(),
          cipher_suite: 0..0xFFFF,
          compression_method: 0,
          extensions: [extension()],
          encoded: binary()
        }

  @enforce_keys [
    :kind,
    :legacy_version,
    :random,
    :legacy_session_id_echo,
    :cipher_suite,
    :compression_method,
    :extensions,
    :encoded
  ]
  defstruct @enforce_keys

  @type expectations :: %{
          required(:legacy_session_id) => binary(),
          optional(:offered_versions) => [0..0xFFFF],
          required(:offered_ciphers) => [0..0xFFFF],
          required(:offered_groups) => [0..0xFFFF],
          required(:offered_key_share_groups) => [0..0xFFFF],
          required(:offered_extension_ids) => [0..0xFFFF],
          required(:offered_psk_key_exchange_modes) => [0 | 1],
          optional(:offered_psk_count) => non_neg_integer()
        }

  @spec decode(term(), term()) ::
          {:ok, t(), binary()} | {:more, non_neg_integer()} | {:error, term()}
  @spec decode(term(), term(), keyword()) ::
          {:ok, t(), binary()} | {:more, non_neg_integer()} | {:error, term()}
  def decode(input, expectations, opts \\ []) do
    with {:ok, expectations} <- validate_expectations(expectations),
         true <- is_binary(input),
         :ok <- check_extension_limit(input, Keyword.get(opts, :max_extension_bytes, 65_535)) do
      decode_handshake(input, expectations)
    else
      false -> {:error, {:invalid_input, :not_binary}}
      {:error, _reason} = error -> error
    end
  end

  @doc false
  @spec check_extension_limit(binary(), non_neg_integer()) :: :ok | {:error, term()}
  def check_extension_limit(_input, limit)
      when not is_integer(limit) or limit < 0 or limit > 65_535,
      do: {:error, {:invalid_limit, :max_extension_bytes}}

  def check_extension_limit(
        <<2, _body_length::24, _version::16, random::binary-size(32), sid_length, rest::binary>>,
        limit
      )
      when sid_length <= 32 and byte_size(rest) >= sid_length + 5 do
    <<_sid::binary-size(^sid_length), _cipher::16, _compression, length::16, _::binary>> = rest

    if length > limit,
      do: {:error, {:extension_length_exceeded, message_kind(random), length, limit}},
      else: :ok
  end

  def check_extension_limit(_input, _limit), do: :ok

  defp decode_handshake(input, _expectations) when byte_size(input) < 4,
    do: {:more, 4 - byte_size(input)}

  defp decode_handshake(
         <<type, body_length::24, rest::binary>> = input,
         expectations
       ) do
    cond do
      type != @server_hello_type ->
        {:error, {:unexpected_handshake_type, type}}

      body_length > @maximum_body_length ->
        {:error, {:handshake_length_exceeded, body_length, @maximum_body_length}}

      byte_size(rest) < body_length ->
        {:more, body_length - byte_size(rest)}

      true ->
        total_length = body_length + 4
        <<body::binary-size(^body_length), remainder::binary>> = rest
        <<encoded::binary-size(^total_length), _::binary>> = input

        case parse_body(body, expectations, encoded) do
          {:ok, server_hello} -> {:ok, server_hello, remainder}
          {:error, _reason} = error -> error
        end
    end
  end

  defp parse_body(
         <<legacy_version::16, random::binary-size(32), session_id_length, rest::binary>>,
         expectations,
         encoded
       ) do
    with :ok <- require_legacy_version(legacy_version),
         :ok <- require_session_id_length(session_id_length),
         {:ok, session_id, rest} <- take(rest, session_id_length, :legacy_session_id),
         :ok <- require_session_id_echo(session_id, expectations.legacy_session_id),
         {:ok, cipher_suite, compression_method, extension_bytes} <- parse_tail(rest),
         :ok <- require_cipher(cipher_suite, expectations.offered_ciphers),
         :ok <- require_compression(compression_method),
         {:ok, raw_extensions} <- parse_extension_vector(extension_bytes),
         kind = message_kind(random),
         {:ok, extensions} <- validate_extensions(kind, raw_extensions, expectations) do
      {:ok,
       %__MODULE__{
         kind: kind,
         legacy_version: legacy_version,
         random: random,
         legacy_session_id_echo: session_id,
         cipher_suite: cipher_suite,
         compression_method: compression_method,
         extensions: extensions,
         encoded: encoded
       }}
    end
  end

  defp parse_body(_body, _expectations, _encoded),
    do: {:error, {:malformed_server_hello, :fixed_fields}}

  defp parse_tail(<<cipher_suite::16, compression_method, extension_length::16, rest::binary>>) do
    if byte_size(rest) == extension_length do
      {:ok, cipher_suite, compression_method, rest}
    else
      {:error, {:malformed_server_hello, :extensions_length}}
    end
  end

  defp parse_tail(_rest), do: {:error, {:malformed_server_hello, :fixed_fields}}

  defp parse_extension_vector(bytes), do: parse_extensions(bytes, [], %{})

  defp parse_extensions(<<>>, extensions, _seen), do: {:ok, Enum.reverse(extensions)}

  defp parse_extensions(bytes, _extensions, _seen) when byte_size(bytes) < 4,
    do: {:error, {:malformed_extension, :header}}

  defp parse_extensions(<<extension_id::16, length::16, rest::binary>>, extensions, seen) do
    cond do
      Map.has_key?(seen, extension_id) ->
        {:error, {:duplicate_extension, extension_id}}

      byte_size(rest) < length ->
        {:error, {:malformed_extension, extension_id, :length}}

      true ->
        <<payload::binary-size(^length), remainder::binary>> = rest

        parse_extensions(
          remainder,
          [{extension_id, payload} | extensions],
          Map.put(seen, extension_id, true)
        )
    end
  end

  defp validate_extensions(kind, raw_extensions, expectations) do
    raw_extensions
    |> Enum.reduce_while({:ok, []}, fn extension, {:ok, parsed} ->
      case validate_extension(kind, extension, expectations) do
        {:ok, semantic} -> {:cont, {:ok, [semantic | parsed]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, parsed} ->
        validate_required_extensions(kind, Enum.reverse(parsed), expectations)

      error ->
        error
    end
  end

  defp validate_extension(kind, {extension_id, _payload}, _expectations)
       when extension_id not in [41, 43, 44, 51],
       do: reject_unknown_extension(kind, extension_id)

  defp validate_extension(kind, {extension_id, _payload}, _expectations)
       when kind == :server_hello and extension_id == 44,
       do: {:error, {:forbidden_extension, kind, extension_id}}

  defp validate_extension(kind, {extension_id, _payload}, _expectations)
       when kind == :hello_retry_request and extension_id == 41,
       do: {:error, {:forbidden_extension, kind, extension_id}}

  defp validate_extension(kind, {extension_id, payload}, expectations)
       when extension_id != 44 do
    cond do
      grease?(extension_id) ->
        {:error, {:grease_selected, :extension, extension_id}}

      extension_id not in expectations.offered_extension_ids ->
        {:error, {:extension_not_offered, extension_id}}

      true ->
        :continue
    end
    |> case do
      :continue -> :continue
      {:error, _reason} = error -> error
    end
    |> continue_extension(kind, extension_id, payload, expectations)
  end

  defp validate_extension(kind, {44, payload}, expectations),
    do: parse_extension(kind, 44, payload, expectations)

  defp continue_extension(:continue, kind, extension_id, payload, expectations),
    do: parse_extension(kind, extension_id, payload, expectations)

  defp continue_extension(
         {:error, _reason} = error,
         _kind,
         _extension_id,
         _payload,
         _expectations
       ),
       do: error

  defp parse_extension(_kind, 43, <<0x0304::16>>, expectations) do
    if 0x0304 in Map.get(expectations, :offered_versions, [0x0304]) do
      {:ok, {:supported_versions, 0x0304}}
    else
      {:error, {:selected_version_not_offered, 0x0304}}
    end
  end

  defp parse_extension(_kind, 43, payload, _expectations),
    do: {:error, {:invalid_supported_versions, payload}}

  defp parse_extension(:server_hello, 51, payload, expectations),
    do: parse_server_key_share(payload, expectations)

  defp parse_extension(:hello_retry_request, 51, payload, expectations),
    do: parse_selected_group(payload, expectations)

  defp parse_extension(:server_hello, 41, <<selected_identity::16>>, expectations) do
    if selected_identity < expectations.offered_psk_count do
      {:ok, {:pre_shared_key, selected_identity}}
    else
      {:error, {:invalid_selected_identity, selected_identity, expectations.offered_psk_count}}
    end
  end

  defp parse_extension(:server_hello, 41, payload, _expectations),
    do: {:error, {:malformed_extension, 41, {:expected_length, 2, byte_size(payload)}}}

  defp parse_extension(:hello_retry_request, 44, <<length::16, cookie::binary>>, _expectations)
       when length > 0 and byte_size(cookie) == length,
       do: {:ok, {:cookie, cookie}}

  defp parse_extension(:hello_retry_request, 44, _payload, _expectations),
    do: {:error, {:invalid_cookie, :malformed}}

  defp parse_server_key_share(
         <<group::16, key_length::16, key_exchange::binary>>,
         expectations
       ) do
    with true <- key_length > 0 and byte_size(key_exchange) == key_length,
         :ok <- require_implemented_group(group),
         :ok <- require_offered_group(group, expectations.offered_key_share_groups, :key_share),
         :ok <- validate_key_exchange(group, key_exchange) do
      {:ok, {:key_share, %{group: group, key_exchange: key_exchange}}}
    else
      false -> {:error, {:malformed_extension, 51, :key_exchange_length}}
      {:error, _reason} = error -> error
    end
  end

  defp parse_server_key_share(_payload, _expectations),
    do: {:error, {:malformed_extension, 51, :key_share}}

  defp parse_selected_group(<<group::16>>, expectations) do
    with :ok <- require_implemented_group(group),
         :ok <- require_offered_group(group, expectations.offered_groups, :supported_groups),
         false <- group in expectations.offered_key_share_groups do
      {:ok, {:selected_group, group}}
    else
      true -> {:error, {:hello_retry_request_group_already_offered, group}}
      {:error, _reason} = error -> error
    end
  end

  defp parse_selected_group(payload, _expectations),
    do: {:error, {:malformed_extension, 51, {:expected_length, 2, byte_size(payload)}}}

  defp validate_required_extensions(kind, extensions, expectations) do
    has_version = Enum.any?(extensions, &match?({:supported_versions, 0x0304}, &1))
    has_key_share = Enum.any?(extensions, &match?({:key_share, _}, &1))
    has_psk = Enum.any?(extensions, &match?({:pre_shared_key, _}, &1))

    changes_client_hello =
      Enum.any?(extensions, fn extension ->
        match?({:cookie, _}, extension) or match?({:selected_group, _}, extension)
      end)

    cond do
      not has_version ->
        {:error, :missing_supported_versions}

      kind == :hello_retry_request and not changes_client_hello ->
        {:error, :hello_retry_request_would_not_change_client_hello}

      kind == :server_hello and not has_key_share and not has_psk ->
        {:error, :missing_key_establishment}

      kind == :server_hello and has_psk ->
        negotiated_mode = if has_key_share, do: 1, else: 0

        if negotiated_mode in expectations.offered_psk_key_exchange_modes do
          {:ok, extensions}
        else
          {:error, {:psk_key_exchange_mode_not_offered, negotiated_mode}}
        end

      true ->
        {:ok, extensions}
    end
  end

  defp reject_unknown_extension(kind, extension_id) do
    if grease?(extension_id) do
      {:error, {:grease_selected, :extension, extension_id}}
    else
      {:error, {:forbidden_extension, kind, extension_id}}
    end
  end

  defp require_legacy_version(0x0303), do: :ok
  defp require_legacy_version(version), do: {:error, {:invalid_legacy_version, version}}

  defp require_session_id_length(length) when length <= 32, do: :ok
  defp require_session_id_length(length), do: {:error, {:invalid_session_id_length, length}}

  defp require_session_id_echo(session_id, session_id), do: :ok
  defp require_session_id_echo(actual, _expected), do: {:error, {:session_id_mismatch, actual}}

  defp require_cipher(cipher_suite, offered_ciphers) do
    cond do
      grease?(cipher_suite) ->
        {:error, {:grease_selected, :cipher_suite, cipher_suite}}

      cipher_suite not in offered_ciphers ->
        {:error, {:cipher_not_offered, cipher_suite}}

      cipher_suite not in SSL.Capabilities.cipher_ids(0x0304) ->
        {:error, {:unsupported_selected_cipher, cipher_suite}}

      true ->
        :ok
    end
  end

  defp require_compression(0), do: :ok
  defp require_compression(method), do: {:error, {:invalid_compression_method, method}}

  defp require_implemented_group(group) do
    cond do
      group in SSL.Capabilities.identifiers(:group) -> :ok
      grease?(group) -> {:error, {:grease_selected, :group, group}}
      true -> {:error, {:unsupported_selected_group, group}}
    end
  end

  defp require_offered_group(group, offered, source) do
    if group in offered do
      :ok
    else
      {:error, {:selected_group_not_offered, source, group}}
    end
  end

  defp validate_key_exchange(group, key_exchange) do
    capability = SSL.Capabilities.resolve(:group, group)
    valid_encoding = capability.share_encoding == :raw or match?(<<4, _::binary>>, key_exchange)

    if byte_size(key_exchange) == capability.share_size and valid_encoding do
      :ok
    else
      {:error, {:invalid_key_exchange, group, byte_size(key_exchange)}}
    end
  end

  defp message_kind(@hello_retry_request_random), do: :hello_retry_request
  defp message_kind(_random), do: :server_hello

  defp take(bytes, length, _field) when byte_size(bytes) >= length do
    <<value::binary-size(^length), remainder::binary>> = bytes
    {:ok, value, remainder}
  end

  defp take(_bytes, _length, field), do: {:error, {:malformed_server_hello, field}}

  defp grease?(value), do: value in @grease_values

  defp validate_expectations(expectations) when is_map(expectations) do
    with :ok <- validate_session_expectation(expectations),
         :ok <- validate_list_expectation(expectations, :offered_ciphers),
         :ok <- validate_list_expectation(expectations, :offered_groups),
         :ok <- validate_list_expectation(expectations, :offered_key_share_groups),
         :ok <- validate_list_expectation(expectations, :offered_extension_ids),
         :ok <- validate_optional_list_expectation(expectations, :offered_versions),
         :ok <- validate_psk_mode_expectation(expectations),
         :ok <- validate_key_share_expectation(expectations),
         :ok <- validate_psk_expectation(expectations) do
      {:ok, Map.put_new(expectations, :offered_psk_count, 0)}
    end
  end

  defp validate_expectations(_expectations), do: {:error, {:invalid_expectations, :structure}}

  defp validate_session_expectation(expectations) do
    case Map.fetch(expectations, :legacy_session_id) do
      {:ok, session_id} when is_binary(session_id) and byte_size(session_id) <= 32 -> :ok
      _other -> {:error, {:invalid_expectations, :legacy_session_id}}
    end
  end

  defp validate_list_expectation(expectations, field) do
    case Map.fetch(expectations, field) do
      {:ok, values} when is_list(values) ->
        if Enum.all?(values, &valid_uint16?/1) and Enum.uniq(values) == values do
          :ok
        else
          {:error, {:invalid_expectations, field}}
        end

      _other ->
        {:error, {:invalid_expectations, field}}
    end
  end

  defp validate_optional_list_expectation(expectations, field) do
    case Map.fetch(expectations, field) do
      :error -> :ok
      {:ok, _values} -> validate_list_expectation(expectations, field)
    end
  end

  defp validate_psk_expectation(expectations) do
    case Map.get(expectations, :offered_psk_count, 0) do
      count when is_integer(count) and count in 0..65_536 -> :ok
      _count -> {:error, {:invalid_expectations, :offered_psk_count}}
    end
  end

  defp validate_psk_mode_expectation(expectations) do
    case Map.fetch(expectations, :offered_psk_key_exchange_modes) do
      {:ok, modes} when is_list(modes) ->
        if Enum.all?(modes, &(&1 in [0, 1])) and Enum.uniq(modes) == modes do
          :ok
        else
          {:error, {:invalid_expectations, :offered_psk_key_exchange_modes}}
        end

      _other ->
        {:error, {:invalid_expectations, :offered_psk_key_exchange_modes}}
    end
  end

  defp validate_key_share_expectation(expectations) do
    if ordered_subset?(
         expectations.offered_key_share_groups,
         expectations.offered_groups
       ) do
      :ok
    else
      {:error, {:invalid_expectations, :offered_key_share_groups}}
    end
  end

  defp ordered_subset?([], _offered_groups), do: true

  defp ordered_subset?([group | groups], offered_groups) do
    case Enum.split_while(offered_groups, &(&1 != group)) do
      {_before, []} -> false
      {_before, [_group | remaining]} -> ordered_subset?(groups, remaining)
    end
  end

  defp valid_uint16?(value), do: is_integer(value) and value in 0..0xFFFF
end
