defmodule SSL.Protocol.ClientOffer do
  @moduledoc """
  Bounded extraction of negotiation inputs from one exact ClientHello message.

  The original bytes remain authoritative for transcript hashing. Unknown
  extensions are retained as opaque payloads and do not affect parsing.
  """

  @maximum_body_length 65_535

  @enforce_keys [
    :encoded,
    :legacy_session_id,
    :cipher_suites,
    :extension_ids,
    :extensions,
    :offered_versions,
    :supported_groups,
    :key_shares,
    :signature_schemes,
    :certificate_signature_schemes,
    :alpn_protocols,
    :psk_key_exchange_modes,
    :psk_count
  ]
  defstruct @enforce_keys

  @type key_share :: %{group: 0..0xFFFF, key_exchange: binary()}
  @type t :: %__MODULE__{
          encoded: binary(),
          legacy_session_id: binary(),
          cipher_suites: [0..0xFFFF],
          extension_ids: [0..0xFFFF],
          extensions: [{0..0xFFFF, binary()}],
          offered_versions: [0..0xFFFF],
          supported_groups: [0..0xFFFF],
          key_shares: [key_share()],
          signature_schemes: [0..0xFFFF],
          certificate_signature_schemes: [0..0xFFFF] | nil,
          alpn_protocols: [binary()],
          psk_key_exchange_modes: [byte()],
          psk_count: non_neg_integer()
        }

  @spec from_client_hello(term()) :: {:ok, t()} | {:error, term()}
  def from_client_hello(<<1, body_length::24, body::binary-size(body_length)>> = encoded)
      when body_length <= @maximum_body_length do
    parse_body(body, encoded)
  end

  def from_client_hello(<<1, body_length::24, _body::binary>>)
      when body_length > @maximum_body_length,
      do: {:error, {:client_hello_length_exceeded, body_length, @maximum_body_length}}

  def from_client_hello(input) when is_binary(input),
    do: {:error, {:malformed_client_hello, :handshake_length}}

  def from_client_hello(_input), do: {:error, {:invalid_input, :client_hello}}

  @doc false
  @spec observe(term()) ::
          {:error,
           {:duplicate_client_hello_extension, char()}
           | {:malformed_client_hello,
              :cipher_suites
              | :compression_methods
              | :extensions
              | :fixed_fields
              | :handshake_length
              | :session_id
              | :signature_algorithms
              | :signature_algorithms_cert
              | :supported_groups
              | :supported_versions}
           | {:malformed_client_hello_extension, :header}
           | {:malformed_client_hello_extension, char(), :length}}
          | {:ok,
             %{
               cipher_suites: [any()],
               compression_methods: binary(),
               encoded: <<_::32, _::_*8>>,
               extension_ids: [any()],
               extensions: [any()],
               legacy_session_id: binary(),
               legacy_version: char()
             }}
  def observe(<<1, length::24, body::binary-size(length)>> = encoded)
      when length <= @maximum_body_length do
    observe_body(body, encoded)
  end

  def observe(_), do: {:error, {:malformed_client_hello, :handshake_length}}

  defp parse_body(body, encoded) do
    with {:ok, observed} <- observe_body(body, encoded),
         :ok <- validate_legacy_version(observed.legacy_version),
         :ok <- validate_compression_methods(observed.compression_methods),
         {:ok, fields} <- extract_fields(observed.extensions) do
      {:ok,
       struct!(
         __MODULE__,
         Map.merge(fields, Map.drop(observed, [:legacy_version, :compression_methods]))
       )}
    end
  end

  defp validate_legacy_version(0x0303), do: :ok

  defp validate_legacy_version(version),
    do: {:error, {:invalid_client_hello_legacy_version, version}}

  defp observe_body(
         <<version::16, _random::binary-size(32), session_id_length, rest::binary>>,
         encoded
       )
       when session_id_length <= 32 do
    with {:ok, session_id, rest} <- take(rest, session_id_length, :session_id),
         {:ok, cipher_bytes, rest} <- take_vector16(rest, :cipher_suites),
         {:ok, cipher_suites} <- parse_uint16_list(cipher_bytes, :cipher_suites, false),
         {:ok, compression_methods, rest} <- take_vector8(rest, :compression_methods),
         {:ok, extension_bytes} <- observation_extensions(rest),
         {:ok, extensions} <- parse_extensions(extension_bytes) do
      {:ok,
       %{
         encoded: encoded,
         legacy_version: version,
         compression_methods: compression_methods,
         legacy_session_id: session_id,
         cipher_suites: cipher_suites,
         extension_ids: Enum.map(extensions, &elem(&1, 0)),
         extensions: extensions
       }}
    end
  end

  defp observe_body(_, _), do: {:error, {:malformed_client_hello, :fixed_fields}}
  defp observation_extensions(<<>>), do: {:ok, <<>>}
  defp observation_extensions(<<length::16, bytes::binary-size(length)>>), do: {:ok, bytes}
  defp observation_extensions(_), do: {:error, {:malformed_client_hello, :extensions}}

  defp parse_extensions(bytes), do: parse_extensions(bytes, %{}, [])
  defp parse_extensions(<<>>, _seen, extensions), do: {:ok, Enum.reverse(extensions)}

  defp parse_extensions(bytes, _seen, _extensions) when byte_size(bytes) < 4,
    do: {:error, {:malformed_client_hello_extension, :header}}

  defp parse_extensions(<<id::16, length::16, rest::binary>>, seen, extensions) do
    cond do
      Map.has_key?(seen, id) ->
        {:error, {:duplicate_client_hello_extension, id}}

      byte_size(rest) < length ->
        {:error, {:malformed_client_hello_extension, id, :length}}

      true ->
        <<payload::binary-size(^length), remainder::binary>> = rest
        parse_extensions(remainder, Map.put(seen, id, true), [{id, payload} | extensions])
    end
  end

  defp extract_fields(extensions) do
    defaults = %{
      offered_versions: [],
      supported_groups: [],
      key_shares: [],
      signature_schemes: [],
      certificate_signature_schemes: nil,
      alpn_protocols: [],
      psk_key_exchange_modes: [],
      psk_count: 0
    }

    Enum.reduce_while(extensions, {:ok, defaults}, fn extension, {:ok, fields} ->
      case extract_field(extension, fields) do
        {:ok, fields} -> {:cont, {:ok, fields}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp extract_field({0, <<length::16, names::binary-size(length)>>}, fields)
       when length > 0 do
    with :ok <- server_names(names, %{}) do
      {:ok, fields}
    end
  end

  defp extract_field({0, _}, _),
    do: {:error, {:malformed_client_hello_extension, 0, :server_name}}

  defp extract_field({49, <<>>}, fields), do: {:ok, fields}

  defp extract_field({49, _}, _),
    do: {:error, {:malformed_client_hello_extension, 49, :post_handshake_auth}}

  defp extract_field({21, bytes}, fields) do
    if bytes == :binary.copy(<<0>>, byte_size(bytes)),
      do: {:ok, fields},
      else: {:error, {:malformed_client_hello_extension, 21, :padding}}
  end

  defp extract_field({43, <<length, versions::binary>>}, fields)
       when length == byte_size(versions) do
    with {:ok, values} <- parse_uint16_list(versions, :supported_versions, false) do
      {:ok, %{fields | offered_versions: values}}
    end
  end

  defp extract_field({43, _payload}, _fields),
    do: {:error, {:malformed_client_hello_extension, 43, :supported_versions}}

  defp extract_field({10, payload}, fields) do
    with {:ok, bytes} <- exact_vector16(payload, 10),
         {:ok, values} <- parse_uint16_list(bytes, :supported_groups, false) do
      {:ok, %{fields | supported_groups: values}}
    end
  end

  defp extract_field({51, payload}, fields) do
    with {:ok, bytes} <- exact_vector16(payload, 51),
         {:ok, key_shares} <- parse_key_shares(bytes, []) do
      {:ok, %{fields | key_shares: key_shares}}
    end
  end

  defp extract_field({13, payload}, fields) do
    with {:ok, bytes} <- exact_vector16(payload, 13),
         {:ok, values} <- parse_uint16_list(bytes, :signature_algorithms, false) do
      {:ok, %{fields | signature_schemes: values}}
    end
  end

  defp extract_field({50, payload}, fields) do
    with {:ok, bytes} <- exact_vector16(payload, 50),
         {:ok, values} <- parse_uint16_list(bytes, :signature_algorithms_cert, false) do
      {:ok, %{fields | certificate_signature_schemes: values}}
    end
  end

  defp extract_field({16, payload}, fields) do
    with {:ok, bytes} <- exact_vector16(payload, 16),
         {:ok, protocols} <- parse_alpn(bytes, []) do
      {:ok, %{fields | alpn_protocols: protocols}}
    end
  end

  defp extract_field({45, <<length, modes::binary>>}, fields)
       when length == byte_size(modes) and length > 0 do
    values = :binary.bin_to_list(modes)

    # Unknown modes are legal offers to ignore (including GREASE). Selection
    # validation is a separate concern owned by the handshake engine.
    {:ok, %{fields | psk_key_exchange_modes: values}}
  end

  defp extract_field({45, _payload}, _fields),
    do: {:error, {:malformed_client_hello_extension, 45, :psk_key_exchange_modes}}

  defp extract_field({41, payload}, fields) do
    with {:ok, identities, binders} <- split_psk(payload),
         {:ok, count} <- count_psk_identities(identities, 0),
         {:ok, ^count} <- count_psk_binders(binders, 0) do
      {:ok, %{fields | psk_count: count}}
    else
      {:ok, _different_count} ->
        {:error, {:malformed_client_hello_extension, 41, :binder_count}}

      {:error, _reason} = error ->
        error
    end
  end

  defp extract_field({_unknown, _payload}, fields), do: {:ok, fields}

  defp server_names(<<>>, _seen), do: :ok

  defp server_names(<<0, length::16, name::binary-size(length), rest::binary>>, seen)
       when length > 0 do
    if Map.has_key?(seen, 0) or :binary.match(name, <<0>>) != :nomatch,
      do: {:error, {:malformed_client_hello_extension, 0, :server_name}},
      else: server_names(rest, Map.put(seen, 0, true))
  end

  defp server_names(_, _), do: {:error, {:malformed_client_hello_extension, 0, :server_name}}

  defp parse_key_shares(<<>>, shares), do: {:ok, Enum.reverse(shares)}

  defp parse_key_shares(<<group::16, length::16, rest::binary>>, shares)
       when length > 0 and byte_size(rest) >= length do
    <<key_exchange::binary-size(^length), remainder::binary>> = rest
    parse_key_shares(remainder, [%{group: group, key_exchange: key_exchange} | shares])
  end

  defp parse_key_shares(_bytes, _shares),
    do: {:error, {:malformed_client_hello_extension, 51, :key_share}}

  defp parse_alpn(<<>>, protocols) when protocols != [], do: {:ok, Enum.reverse(protocols)}

  defp parse_alpn(<<length, rest::binary>>, protocols)
       when length > 0 and byte_size(rest) >= length do
    <<protocol::binary-size(^length), remainder::binary>> = rest
    parse_alpn(remainder, [protocol | protocols])
  end

  defp parse_alpn(_bytes, _protocols),
    do: {:error, {:malformed_client_hello_extension, 16, :alpn}}

  defp split_psk(
         <<identities_length::16, identities::binary-size(identities_length), binders_length::16,
           binders::binary-size(binders_length)>>
       ) do
    {:ok, identities, binders}
  end

  defp split_psk(_payload),
    do: {:error, {:malformed_client_hello_extension, 41, :pre_shared_key}}

  defp count_psk_identities(<<>>, count) when count > 0, do: {:ok, count}

  defp count_psk_identities(<<length::16, rest::binary>>, count)
       when length > 0 and byte_size(rest) >= length + 4 do
    <<_identity::binary-size(^length), _age::32, remainder::binary>> = rest
    count_psk_identities(remainder, count + 1)
  end

  defp count_psk_identities(_identities, _count),
    do: {:error, {:malformed_client_hello_extension, 41, :identities}}

  defp count_psk_binders(<<>>, count) when count > 0, do: {:ok, count}

  defp count_psk_binders(<<length, rest::binary>>, count)
       when length > 0 and byte_size(rest) >= length do
    <<_binder::binary-size(^length), remainder::binary>> = rest
    count_psk_binders(remainder, count + 1)
  end

  defp count_psk_binders(_binders, _count),
    do: {:error, {:malformed_client_hello_extension, 41, :binders}}

  defp exact_vector16(<<length::16, bytes::binary>>, _id) when length == byte_size(bytes),
    do: {:ok, bytes}

  defp exact_vector16(_payload, id),
    do: {:error, {:malformed_client_hello_extension, id, :vector_length}}

  defp take_vector16(<<length::16, rest::binary>>, _field) when byte_size(rest) >= length do
    <<value::binary-size(^length), remainder::binary>> = rest
    {:ok, value, remainder}
  end

  defp take_vector16(_bytes, field), do: {:error, {:malformed_client_hello, field}}

  defp take_vector8(<<length, rest::binary>>, _field) when byte_size(rest) >= length do
    <<value::binary-size(^length), remainder::binary>> = rest
    {:ok, value, remainder}
  end

  defp take_vector8(_bytes, field), do: {:error, {:malformed_client_hello, field}}

  defp take(bytes, length, _field) when byte_size(bytes) >= length do
    <<value::binary-size(^length), remainder::binary>> = bytes
    {:ok, value, remainder}
  end

  defp take(_bytes, _length, field), do: {:error, {:malformed_client_hello, field}}

  defp parse_uint16_list(bytes, _field, allow_empty)
       when rem(byte_size(bytes), 2) == 0 and (allow_empty or byte_size(bytes) > 0),
       do: {:ok, for(<<value::16 <- bytes>>, do: value)}

  defp parse_uint16_list(_bytes, field, _allow_empty),
    do: {:error, {:malformed_client_hello, field}}

  defp validate_compression_methods(<<0>>), do: :ok

  defp validate_compression_methods(_methods),
    do: {:error, {:malformed_client_hello, :compression_methods}}
end
