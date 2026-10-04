defmodule SSL.Protocol.ServerFlight do
  alias SSL.Capabilities

  @moduledoc """
  Bounded codecs for the encrypted TLS 1.3 server handshake flight.

  Decoding accepts one complete handshake message and preserves its exact
  encoded bytes. Stream fragmentation remains the responsibility of
  `SSL.Protocol.HandshakeFramer`. Bounded NewSessionTicket and KeyUpdate codecs
  let the connection runtime apply post-handshake epoch transitions explicitly.
  """

  defmodule EncryptedExtensions do
    @moduledoc false
    @type t :: %__MODULE__{extensions: list(), encoded: binary()}
    @enforce_keys [:extensions, :encoded]
    defstruct [:extensions, :encoded]
  end

  defmodule CertificateEntry do
    @moduledoc false
    @type t :: %__MODULE__{der: binary(), extensions: list()}
    @enforce_keys [:der, :extensions]
    defstruct [:der, :extensions]
  end

  defmodule Certificate do
    @moduledoc false
    @type t :: %__MODULE__{
            request_context: binary(),
            entries: [CertificateEntry.t()],
            encoded: binary()
          }
    @enforce_keys [:request_context, :entries, :encoded]
    defstruct [:request_context, :entries, :encoded]
  end

  defmodule CertificateVerify do
    @moduledoc false
    @type t :: %__MODULE__{
            signature_scheme: non_neg_integer(),
            signature: binary(),
            encoded: binary()
          }
    @enforce_keys [:signature_scheme, :signature, :encoded]
    defstruct [:signature_scheme, :signature, :encoded]
  end

  defmodule Finished do
    @moduledoc false
    @type t :: %__MODULE__{verify_data: binary(), encoded: binary()}
    @enforce_keys [:verify_data, :encoded]
    defstruct [:verify_data, :encoded]
  end

  defmodule CertificateRequest do
    @moduledoc false
    @type t :: %__MODULE__{request_context: binary(), extensions: list(), encoded: binary()}
    @enforce_keys [:request_context, :extensions, :encoded]
    defstruct @enforce_keys
  end

  defmodule NewSessionTicket do
    @moduledoc false
    @type t :: %__MODULE__{
            ticket_lifetime: non_neg_integer(),
            ticket_age_add: non_neg_integer(),
            ticket_nonce: binary(),
            ticket: binary(),
            extensions: list(),
            encoded: binary()
          }
    @enforce_keys [
      :ticket_lifetime,
      :ticket_age_add,
      :ticket_nonce,
      :ticket,
      :extensions,
      :encoded
    ]
    defstruct @enforce_keys
  end

  defmodule KeyUpdate do
    @moduledoc false
    @type t :: %__MODULE__{request_update: boolean(), encoded: binary()}
    @enforce_keys [:request_update, :encoded]
    defstruct @enforce_keys
  end

  @default_max_handshake_length 1_048_576
  @default_max_certificate_count 16
  @default_max_total_certificate_bytes 1_048_576
  @default_max_certificate_bytes 262_144
  @default_max_extension_bytes 65_535
  @default_max_signature_bytes 16_384

  @encrypted_extension_ids [0, 1, 10, 16, 19, 20, 28, 42, 57]
  @certificate_extension_ids [5, 18]
  # RFC 9846 permits these extensions in CertificateRequest. Unknown extensions
  # remain opaque, while the known selection constraints are decoded and bounded.
  @certificate_request_extension_ids [0, 5, 13, 47, 48, 50]
  @recognized_extension_ids Enum.uniq(
                              @encrypted_extension_ids ++
                                @certificate_extension_ids ++
                                @certificate_request_extension_ids ++ [41, 43, 51]
                            )

  @type decoded ::
          EncryptedExtensions.t()
          | Certificate.t()
          | CertificateVerify.t()
          | Finished.t()
          | CertificateRequest.t()
          | NewSessionTicket.t()
          | KeyUpdate.t()

  @spec decode(term(), keyword()) ::
          {:ok, decoded(), binary()} | {:more, pos_integer()} | {:error, term()}
  def decode(input, opts \\ []) do
    with {:ok, config} <- validate_options(opts),
         :ok <- validate_input(input) do
      decode_message(input, config)
    end
  end

  @spec encode_finished(term(), keyword()) :: {:ok, binary()} | {:error, term()}
  def encode_finished(verify_data, opts \\ []) do
    with {:ok, config} <- validate_options(opts),
         :ok <- validate_verify_data_input(verify_data),
         :ok <- validate_finished_length(verify_data, config.hash_length) do
      {:ok, <<20, byte_size(verify_data)::24, verify_data::binary>>}
    end
  end

  @spec encode_empty_certificate(binary()) :: {:ok, binary()} | {:error, term()}
  def encode_empty_certificate(context) when is_binary(context) and byte_size(context) <= 255,
    do: {:ok, <<11, byte_size(context) + 4::24, byte_size(context), context::binary, 0::24>>}

  def encode_empty_certificate(_context), do: {:error, {:invalid_input, :request_context}}

  @spec encode_client_certificate(binary(), [binary()]) :: {:ok, binary()} | {:error, term()}
  def encode_client_certificate(context, chain)
      when is_binary(context) and byte_size(context) <= 255 and is_list(chain) do
    if length(chain) <= @default_max_certificate_count and
         Enum.all?(
           chain,
           &(is_binary(&1) and byte_size(&1) >= 1 and
               byte_size(&1) <= @default_max_certificate_bytes)
         ) and
         Enum.reduce(chain, 0, &(byte_size(&1) + &2)) <= 524_288 do
      entries = for der <- chain, do: <<byte_size(der)::24, der::binary, 0::16>>
      list = IO.iodata_to_binary(entries)
      body = <<byte_size(context), context::binary, byte_size(list)::24, list::binary>>
      {:ok, <<11, byte_size(body)::24, body::binary>>}
    else
      {:error, :invalid_client_certificate_chain}
    end
  end

  def encode_client_certificate(_context, _chain),
    do: {:error, :invalid_client_certificate_chain}

  @spec encode_client_certificate_verify(non_neg_integer(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def encode_client_certificate_verify(scheme, signature)
      when is_integer(scheme) and scheme in 0..0xFFFF and is_binary(signature) and
             byte_size(signature) in 1..@default_max_signature_bytes do
    {:ok,
     <<15, 4 + byte_size(signature)::24, scheme::16, byte_size(signature)::16, signature::binary>>}
  end

  def encode_client_certificate_verify(_scheme, _signature),
    do: {:error, :invalid_client_certificate_verify}

  @spec encode_key_update(boolean()) :: {:ok, <<_::40>>}
  def encode_key_update(request_update) when is_boolean(request_update),
    do: {:ok, <<24, 1::24, if(request_update, do: 1, else: 0)>>}

  defp decode_message(input, _config) when byte_size(input) < 4,
    do: {:more, 4 - byte_size(input)}

  defp decode_message(<<type, length::24, _rest::binary>> = input, config) do
    total_length = 4 + length

    cond do
      length > config.max_handshake_length ->
        {:error, {:handshake_length_exceeded, length, config.max_handshake_length}}

      byte_size(input) < total_length ->
        {:more, total_length - byte_size(input)}

      true ->
        <<encoded::binary-size(^total_length), remainder::binary>> = input
        <<_header::binary-size(4), body::binary>> = encoded
        decode_body(type, body, encoded, remainder, config)
    end
  end

  defp decode_body(8, body, encoded, remainder, config) do
    with {:ok, extension_bytes} <- decode_vector16(body, {:malformed_extensions, :length}),
         {:ok, extensions} <-
           parse_extensions(extension_bytes, :encrypted_extensions, config) do
      {:ok, %EncryptedExtensions{extensions: extensions, encoded: encoded}, remainder}
    end
  end

  defp decode_body(11, body, encoded, remainder, config) do
    with {:ok, request_context, certificate_list} <- parse_certificate_header(body),
         :ok <- require_empty_certificate_context(request_context),
         {:ok, entries} <- parse_certificate_entries(certificate_list, config) do
      {:ok,
       %Certificate{
         request_context: request_context,
         entries: entries,
         encoded: encoded
       }, remainder}
    end
  end

  defp decode_body(13, body, encoded, remainder, config) do
    with {:ok, context, extension_bytes} <- parse_certificate_request(body),
         :ok <- require_empty_certificate_request_context(context),
         {:ok, extensions} <- parse_extensions(extension_bytes, :certificate_request, config),
         :ok <- require_certificate_request_signature_algorithms(extensions) do
      {:ok,
       %CertificateRequest{
         request_context: context,
         extensions: extensions,
         encoded: encoded
       }, remainder}
    end
  end

  defp decode_body(15, body, encoded, remainder, config) do
    with {:ok, signature_scheme, signature} <- parse_certificate_verify(body),
         :ok <- validate_signature_scheme(signature_scheme, config.allowed_signature_schemes),
         :ok <- validate_signature(signature, config.max_signature_bytes) do
      {:ok,
       %CertificateVerify{
         signature_scheme: signature_scheme,
         signature: signature,
         encoded: encoded
       }, remainder}
    end
  end

  defp decode_body(20, verify_data, encoded, remainder, config) do
    with :ok <- validate_finished_length(verify_data, config.hash_length) do
      {:ok, %Finished{verify_data: verify_data, encoded: encoded}, remainder}
    end
  end

  defp decode_body(4, body, encoded, remainder, config) do
    with {:ok, lifetime, age_add, nonce, ticket, extension_bytes} <-
           parse_new_session_ticket(body),
         {:ok, extensions} <- parse_extensions(extension_bytes, :new_session_ticket, config) do
      {:ok,
       %NewSessionTicket{
         ticket_lifetime: lifetime,
         ticket_age_add: age_add,
         ticket_nonce: nonce,
         ticket: ticket,
         extensions: extensions,
         encoded: encoded
       }, remainder}
    end
  end

  defp decode_body(24, <<request>>, encoded, remainder, _config) when request in [0, 1],
    do: {:ok, %KeyUpdate{request_update: request == 1, encoded: encoded}, remainder}

  defp decode_body(24, <<request>>, _encoded, _remainder, _config),
    do: {:error, {:malformed_key_update, request}}

  defp decode_body(24, _body, _encoded, _remainder, _config),
    do: {:error, {:malformed_key_update, :length}}

  defp decode_body(type, _body, _encoded, _remainder, _config),
    do: {:error, {:unexpected_handshake_type, type}}

  defp parse_certificate_header(<<context_length, rest::binary>>) do
    if byte_size(rest) < context_length + 3 do
      {:error, {:malformed_certificate, :request_context}}
    else
      <<request_context::binary-size(^context_length), list_length::24, certificate_list::binary>> =
        rest

      if byte_size(certificate_list) == list_length do
        {:ok, request_context, certificate_list}
      else
        {:error, {:malformed_certificate, :certificate_list_length}}
      end
    end
  end

  defp parse_certificate_header(_body),
    do: {:error, {:malformed_certificate, :request_context}}

  defp require_empty_certificate_context(<<>>), do: :ok

  defp require_empty_certificate_context(context),
    do: {:error, {:unsupported_certificate_request_context, context}}

  defp parse_certificate_entries(<<>>, _config), do: {:error, :empty_certificate_chain}

  defp parse_certificate_entries(bytes, config) do
    parse_certificate_entries(bytes, config, [], 0, 0, 0)
  end

  defp parse_certificate_entries(<<>>, _config, entries, _count, _der_bytes, _extension_bytes),
    do: {:ok, Enum.reverse(entries)}

  defp parse_certificate_entries(bytes, _config, _entries, _count, _der_bytes, _extension_bytes)
       when byte_size(bytes) < 3,
       do: {:error, {:malformed_certificate, :certificate_entry_header}}

  defp parse_certificate_entries(
         <<certificate_length::24, rest::binary>>,
         config,
         entries,
         count,
         der_bytes,
         extension_bytes
       ) do
    new_count = count + 1
    new_der_bytes = der_bytes + certificate_length

    cond do
      certificate_length == 0 ->
        {:error, {:malformed_certificate, :empty_certificate_entry}}

      new_count > config.max_certificate_count ->
        certificate_limit(:count, new_count, config.max_certificate_count)

      certificate_length > config.max_certificate_bytes ->
        certificate_limit(
          :individual_der_bytes,
          certificate_length,
          config.max_certificate_bytes
        )

      new_der_bytes > config.max_total_certificate_bytes ->
        certificate_limit(
          :total_der_bytes,
          new_der_bytes,
          config.max_total_certificate_bytes
        )

      byte_size(rest) < certificate_length + 2 ->
        {:error, {:malformed_certificate, :certificate_entry_length}}

      true ->
        parse_certificate_entry_body(
          rest,
          certificate_length,
          config,
          entries,
          new_count,
          new_der_bytes,
          extension_bytes
        )
    end
  end

  defp parse_certificate_entry_body(
         rest,
         certificate_length,
         config,
         entries,
         count,
         der_bytes,
         extension_bytes
       ) do
    <<der::binary-size(^certificate_length), entry_extension_length::16, tail::binary>> = rest
    new_extension_bytes = extension_bytes + entry_extension_length

    cond do
      new_extension_bytes > config.max_extension_bytes ->
        certificate_limit(
          :extension_bytes,
          new_extension_bytes,
          config.max_extension_bytes
        )

      byte_size(tail) < entry_extension_length ->
        {:error, {:malformed_certificate, :entry_extensions_length}}

      true ->
        <<entry_extension_bytes::binary-size(^entry_extension_length), remainder::binary>> = tail

        with {:ok, entry_extensions} <-
               parse_extensions(entry_extension_bytes, :certificate_entry, config) do
          entry = %CertificateEntry{der: der, extensions: entry_extensions}

          parse_certificate_entries(
            remainder,
            config,
            [entry | entries],
            count,
            der_bytes,
            new_extension_bytes
          )
        end
    end
  end

  defp certificate_limit(kind, actual, limit),
    do: {:error, {:certificate_limit_exceeded, kind, actual, limit}}

  defp parse_certificate_verify(<<signature_scheme::16, signature_length::16, rest::binary>>) do
    cond do
      byte_size(rest) < signature_length ->
        {:error, {:malformed_certificate_verify, :signature_length}}

      byte_size(rest) > signature_length ->
        {:error, {:malformed_certificate_verify, :trailing_data}}

      true ->
        {:ok, signature_scheme, rest}
    end
  end

  defp parse_certificate_verify(_body),
    do: {:error, {:malformed_certificate_verify, :header}}

  defp validate_signature_scheme(signature_scheme, allowed_signature_schemes) do
    cond do
      not Capabilities.tls13_signature_scheme?(signature_scheme) ->
        {:error, {:unsupported_signature_scheme, signature_scheme}}

      signature_scheme not in allowed_signature_schemes ->
        {:error, {:signature_scheme_not_allowed, signature_scheme}}

      true ->
        :ok
    end
  end

  defp validate_signature(<<>>, _maximum), do: {:error, :empty_certificate_verify_signature}

  defp validate_signature(signature, maximum) when byte_size(signature) > maximum,
    do: {:error, {:signature_length_exceeded, byte_size(signature), maximum}}

  defp validate_signature(_signature, _maximum), do: :ok

  defp parse_certificate_request(<<context_length, rest::binary>>) do
    if byte_size(rest) < context_length + 2 do
      {:error, {:malformed_certificate_request, :request_context}}
    else
      <<context::binary-size(^context_length), extension_length::16, extension_bytes::binary>> =
        rest

      if byte_size(extension_bytes) == extension_length do
        {:ok, context, extension_bytes}
      else
        {:error, {:malformed_certificate_request, :extensions_length}}
      end
    end
  end

  defp parse_certificate_request(_body),
    do: {:error, {:malformed_certificate_request, :request_context}}

  defp require_empty_certificate_request_context(<<>>), do: :ok

  defp require_empty_certificate_request_context(context),
    do: {:error, {:unsupported_certificate_request_context, context}}

  defp require_certificate_request_signature_algorithms(extensions) do
    if Enum.any?(extensions, &match?({:signature_algorithms, [_ | _]}, &1)),
      do: :ok,
      else: {:error, :missing_certificate_request_signature_algorithms}
  end

  defp parse_new_session_ticket(<<lifetime::32, age_add::32, nonce_length, rest::binary>>)
       when byte_size(rest) >= nonce_length + 4 do
    <<nonce::binary-size(^nonce_length), ticket_length::16, tail::binary>> = rest

    cond do
      lifetime > 604_800 ->
        {:error, {:invalid_new_session_ticket_lifetime, lifetime}}

      ticket_length > 0 and byte_size(tail) >= ticket_length + 2 ->
        <<ticket::binary-size(^ticket_length), extensions_length::16, extensions::binary>> = tail

        if byte_size(extensions) == extensions_length do
          {:ok, lifetime, age_add, nonce, ticket, extensions}
        else
          {:error, {:malformed_new_session_ticket, :extensions_length}}
        end

      true ->
        {:error, {:malformed_new_session_ticket, :ticket}}
    end
  end

  defp parse_new_session_ticket(_body),
    do: {:error, {:malformed_new_session_ticket, :header}}

  defp decode_vector16(<<length::16, bytes::binary>>, _error) when byte_size(bytes) == length,
    do: {:ok, bytes}

  defp decode_vector16(_bytes, error), do: {:error, error}

  defp parse_extensions(bytes, context, config) do
    if byte_size(bytes) > config.max_extension_bytes do
      {:error,
       {:extension_length_exceeded, context, byte_size(bytes), config.max_extension_bytes}}
    else
      parse_extensions(bytes, context, config, %{}, [])
    end
  end

  defp parse_extensions(<<>>, _context, _config, _seen, extensions),
    do: {:ok, Enum.reverse(extensions)}

  defp parse_extensions(bytes, context, _config, _seen, _extensions)
       when byte_size(bytes) < 4,
       do: {:error, {:malformed_extension, context, :header}}

  defp parse_extensions(
         <<extension_id::16, length::16, rest::binary>>,
         context,
         config,
         seen,
         extensions
       ) do
    cond do
      Map.has_key?(seen, extension_id) ->
        {:error, {:duplicate_extension, context, extension_id}}

      byte_size(rest) < length ->
        {:error, {:malformed_extension, extension_id, :length}}

      true ->
        <<payload::binary-size(^length), remainder::binary>> = rest

        with {:ok, extension} <- decode_extension(context, extension_id, payload, config) do
          parse_extensions(
            remainder,
            context,
            config,
            Map.put(seen, extension_id, true),
            [extension | extensions]
          )
        end
    end
  end

  defp decode_extension(:encrypted_extensions, extension_id, payload, config) do
    with :ok <- require_known_extension(extension_id, :encrypted_extensions),
         :ok <- require_offered_extension(extension_id, config.offered_extension_ids) do
      decode_encrypted_extension(extension_id, payload)
    end
  end

  defp decode_extension(:certificate_entry, extension_id, payload, _config) do
    with :ok <- require_known_extension(extension_id, :certificate_entry) do
      decode_certificate_extension(extension_id, payload)
    end
  end

  defp decode_extension(:certificate_request, 13, payload, _config),
    do: decode_signature_algorithms(payload)

  defp decode_extension(:certificate_request, 47, payload, _config),
    do: decode_certificate_authorities(payload)

  defp decode_extension(:certificate_request, 50, payload, _config),
    do: decode_signature_algorithms_cert(payload)

  defp decode_extension(:certificate_request, 48, payload, _config),
    do: decode_oid_filters(payload)

  defp decode_extension(:certificate_request, extension_id, payload, _config)
       when extension_id in @certificate_request_extension_ids,
       do: {:ok, {:raw, extension_id, payload}}

  defp decode_extension(:certificate_request, extension_id, _payload, _config)
       when extension_id in @recognized_extension_ids,
       do: {:error, {:forbidden_extension, :certificate_request, extension_id}}

  # RFC 9846 requires clients to ignore unrecognized CertificateRequest
  # extensions. Preserve their framing for diagnostics while leaving their
  # semantics unused by this no-client-authentication implementation.
  defp decode_extension(:certificate_request, extension_id, payload, _config),
    do: {:ok, {:raw, extension_id, payload}}

  defp decode_extension(:new_session_ticket, 42, <<maximum::32>>, _config),
    do: {:ok, {:early_data, maximum}}

  defp decode_extension(:new_session_ticket, 42, _payload, _config),
    do: {:error, {:malformed_extension, 42, :early_data}}

  defp decode_extension(:new_session_ticket, extension_id, _payload, _config)
       when extension_id in @recognized_extension_ids,
       do: {:error, {:forbidden_extension, :new_session_ticket, extension_id}}

  # RFC 9846 requires clients to ignore unrecognized NewSessionTicket
  # extensions. Keep known, forbidden extensions distinct from that case.
  defp decode_extension(:new_session_ticket, extension_id, payload, _config),
    do: {:ok, {:raw, extension_id, payload}}

  defp require_known_extension(extension_id, :encrypted_extensions)
       when extension_id in @encrypted_extension_ids,
       do: :ok

  defp require_known_extension(extension_id, :certificate_entry)
       when extension_id in @certificate_extension_ids,
       do: :ok

  defp require_known_extension(extension_id, context)
       when extension_id in @recognized_extension_ids,
       do: {:error, {:forbidden_extension, context, extension_id}}

  defp require_known_extension(extension_id, context),
    do: {:error, {:unsupported_extension, context, extension_id}}

  defp require_offered_extension(extension_id, offered_extension_ids) do
    if extension_id in offered_extension_ids,
      do: :ok,
      else: {:error, {:extension_not_offered, extension_id}}
  end

  defp decode_encrypted_extension(57, payload), do: {:ok, {:quic_transport_parameters, payload}}

  defp decode_encrypted_extension(0, <<>>), do: {:ok, {:server_name_ack}}

  defp decode_encrypted_extension(1, <<value>>) when value in 1..4,
    do: {:ok, {:max_fragment_length, value}}

  defp decode_encrypted_extension(10, payload), do: decode_supported_groups(payload)
  defp decode_encrypted_extension(16, payload), do: decode_alpn(payload)

  defp decode_encrypted_extension(19, <<value>>) when value in [0, 2],
    do: {:ok, {:client_certificate_type, value}}

  defp decode_encrypted_extension(20, <<value>>) when value in [0, 2],
    do: {:ok, {:server_certificate_type, value}}

  defp decode_encrypted_extension(28, <<limit::16>>) when limit in 64..16_385,
    do: {:ok, {:record_size_limit, limit}}

  defp decode_encrypted_extension(42, <<>>), do: {:ok, {:early_data}}

  defp decode_encrypted_extension(extension_id, _payload),
    do: {:error, {:malformed_extension, extension_id, extension_name(extension_id)}}

  defp decode_supported_groups(<<length::16, groups::binary>>)
       when length > 0 and rem(length, 2) == 0 and byte_size(groups) == length do
    {:ok, {:supported_groups, for(<<group::16 <- groups>>, do: group)}}
  end

  defp decode_supported_groups(_payload),
    do: {:error, {:malformed_extension, 10, :supported_groups}}

  defp decode_signature_algorithms(<<length::16, values::binary>>)
       when length > 0 and rem(length, 2) == 0 and byte_size(values) == length do
    algorithms = for <<algorithm::16 <- values>>, do: algorithm

    if length(algorithms) != length(Enum.uniq(algorithms)) do
      {:error, {:duplicate_signature_algorithm, :certificate_request}}
    else
      {:ok, {:signature_algorithms, algorithms}}
    end
  end

  defp decode_signature_algorithms(_payload),
    do: {:error, {:malformed_extension, 13, :signature_algorithms}}

  defp decode_signature_algorithms_cert(<<length::16, values::binary>>)
       when length > 0 and rem(length, 2) == 0 and byte_size(values) == length do
    algorithms = for <<algorithm::16 <- values>>, do: algorithm

    if length(algorithms) == length(Enum.uniq(algorithms)),
      do: {:ok, {:signature_algorithms_cert, algorithms}},
      else: {:error, {:duplicate_signature_algorithm, :certificate_request}}
  end

  defp decode_signature_algorithms_cert(_payload),
    do: {:error, {:malformed_extension, 50, :signature_algorithms_cert}}

  defp decode_certificate_authorities(<<length::16, names::binary>>)
       when length >= 3 and byte_size(names) == length,
       do: decode_authority_names(names, [])

  defp decode_certificate_authorities(_payload),
    do: {:error, {:malformed_extension, 47, :certificate_authorities}}

  defp decode_authority_names(<<>>, names),
    do: {:ok, {:certificate_authorities, Enum.reverse(names)}}

  defp decode_authority_names(<<length::16, name::binary-size(length), rest::binary>>, names)
       when length > 0 and length(names) < 64 do
    case valid_der_name?(name) do
      true -> decode_authority_names(rest, [name | names])
      false -> {:error, {:malformed_extension, 47, :distinguished_name}}
    end
  end

  defp decode_authority_names(_bytes, _names),
    do: {:error, {:malformed_extension, 47, :certificate_authorities}}

  defp valid_der_name?(bytes) do
    case :public_key.der_decode(:Name, bytes) do
      {:rdnSequence, _} = name -> :public_key.der_encode(:Name, name) == bytes
      _ -> false
    end
  catch
    _, _ -> false
  end

  defp decode_oid_filters(<<length::16, filters::binary>>) when byte_size(filters) == length,
    do: decode_oid_filter_entries(filters, [])

  defp decode_oid_filters(_payload), do: {:error, {:malformed_extension, 48, :oid_filters}}

  defp decode_oid_filter_entries(<<>>, filters),
    do: {:ok, {:oid_filters, Enum.reverse(filters)}}

  defp decode_oid_filter_entries(
         <<oid_length, oid::binary-size(oid_length), values_length::16,
           values::binary-size(values_length), rest::binary>>,
         filters
       )
       when oid_length > 0 and length(filters) < 64 do
    cond do
      not valid_der_oid?(oid) ->
        {:error, {:malformed_extension, 48, :oid}}

      Enum.any?(filters, fn {seen_oid, _} -> seen_oid == oid end) ->
        {:error, {:duplicate_oid_filter, oid}}

      true ->
        decode_oid_filter_entries(rest, [{oid, values} | filters])
    end
  end

  defp decode_oid_filter_entries(_bytes, _filters),
    do: {:error, {:malformed_extension, 48, :oid_filters}}

  # A DER OBJECT IDENTIFIER has a canonical definite length and complete
  # base-128 subidentifiers. The OID values are left opaque until supported.
  defp valid_der_oid?(<<6, length, body::binary>>)
       when length > 0 and length < 128 and byte_size(body) == length,
       do: valid_oid_components(body, true)

  defp valid_der_oid?(<<6, 0x81, length, body::binary>>)
       when length >= 128 and byte_size(body) == length,
       do: valid_oid_components(body, true)

  defp valid_der_oid?(_), do: false

  defp valid_oid_components(<<>>, true), do: true
  defp valid_oid_components(<<>>, false), do: false
  defp valid_oid_components(<<128, _::binary>>, true), do: false

  defp valid_oid_components(<<byte, rest::binary>>, _start?),
    do: valid_oid_components(rest, byte < 128)

  defp decode_alpn(<<list_length::16, protocol_length, protocol::binary>>)
       when list_length == protocol_length + 1 and protocol_length > 0 and
              byte_size(protocol) == protocol_length,
       do: {:ok, {:alpn, protocol}}

  defp decode_alpn(_payload), do: {:error, {:malformed_extension, 16, :alpn}}

  defp decode_certificate_extension(5, <<1, response_length::24, response::binary>>)
       when response_length > 0 and byte_size(response) == response_length,
       do: {:ok, {:status_request, response}}

  defp decode_certificate_extension(5, _payload),
    do: {:error, {:malformed_extension, 5, :status_request}}

  defp decode_certificate_extension(18, <<length::16, timestamps::binary>>)
       when length > 0 and byte_size(timestamps) == length,
       do: {:ok, {:signed_certificate_timestamps, timestamps}}

  defp decode_certificate_extension(18, _payload),
    do: {:error, {:malformed_extension, 18, :signed_certificate_timestamps}}

  defp extension_name(0), do: :server_name
  defp extension_name(1), do: :max_fragment_length
  defp extension_name(10), do: :supported_groups
  defp extension_name(16), do: :alpn
  defp extension_name(19), do: :client_certificate_type
  defp extension_name(20), do: :server_certificate_type
  defp extension_name(28), do: :record_size_limit
  defp extension_name(42), do: :early_data

  defp validate_options(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      build_config(opts)
    else
      {:error, {:invalid_options, :structure}}
    end
  end

  defp validate_options(_opts), do: {:error, {:invalid_options, :structure}}

  defp build_config(opts) do
    config = %{
      max_handshake_length:
        Keyword.get(opts, :max_handshake_length, @default_max_handshake_length),
      max_certificate_count:
        Keyword.get(opts, :max_certificate_count, @default_max_certificate_count),
      max_total_certificate_bytes:
        Keyword.get(
          opts,
          :max_total_certificate_bytes,
          @default_max_total_certificate_bytes
        ),
      max_certificate_bytes:
        Keyword.get(opts, :max_certificate_bytes, @default_max_certificate_bytes),
      max_extension_bytes: Keyword.get(opts, :max_extension_bytes, @default_max_extension_bytes),
      max_signature_bytes: Keyword.get(opts, :max_signature_bytes, @default_max_signature_bytes),
      offered_extension_ids: Keyword.get(opts, :offered_extension_ids, []),
      allowed_signature_schemes:
        Keyword.get(opts, :allowed_signature_schemes, Capabilities.tls13_signature_ids()),
      hash: Keyword.get(opts, :hash, :sha256)
    }

    with :ok <- validate_limit(config.max_handshake_length, :max_handshake_length),
         :ok <- validate_limit(config.max_certificate_count, :max_certificate_count),
         :ok <-
           validate_limit(config.max_total_certificate_bytes, :max_total_certificate_bytes),
         :ok <- validate_limit(config.max_certificate_bytes, :max_certificate_bytes),
         :ok <- validate_limit(config.max_extension_bytes, :max_extension_bytes),
         :ok <- validate_limit(config.max_signature_bytes, :max_signature_bytes),
         :ok <- validate_id_list(config.offered_extension_ids, :offered_extension_ids),
         :ok <-
           validate_id_list(config.allowed_signature_schemes, :allowed_signature_schemes),
         {:ok, hash_length} <- validate_hash(config.hash) do
      {:ok, Map.put(config, :hash_length, hash_length)}
    end
  end

  defp validate_limit(limit, _name) when is_integer(limit) and limit >= 0, do: :ok
  defp validate_limit(_limit, name), do: {:error, {:invalid_limit, name}}

  defp validate_id_list(values, name) when is_list(values) do
    if Enum.all?(values, &(is_integer(&1) and &1 in 0..0xFFFF)) and
         length(values) == length(Enum.uniq(values)) do
      :ok
    else
      {:error, {:invalid_options, name}}
    end
  end

  defp validate_id_list(_values, name), do: {:error, {:invalid_options, name}}

  defp validate_hash(:sha256), do: {:ok, 32}
  defp validate_hash(:sha384), do: {:ok, 48}
  defp validate_hash(_hash), do: {:error, {:invalid_options, :hash}}

  defp validate_input(input) when is_binary(input), do: :ok
  defp validate_input(_input), do: {:error, {:invalid_input, :not_binary}}

  defp validate_verify_data_input(verify_data) when is_binary(verify_data), do: :ok
  defp validate_verify_data_input(_verify_data), do: {:error, {:invalid_input, :verify_data}}

  defp validate_finished_length(verify_data, expected) when byte_size(verify_data) == expected,
    do: :ok

  defp validate_finished_length(verify_data, expected),
    do: {:error, {:invalid_finished_length, byte_size(verify_data), expected}}
end
