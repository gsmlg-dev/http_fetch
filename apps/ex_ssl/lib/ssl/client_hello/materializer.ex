defmodule SSL.ClientHello.Materializer do
  @moduledoc """
  Resolves a reusable wire profile into per-connection ClientHello material.
  """

  alias SSL.ClientHello.{
    AST,
    Extension,
    GreasePolicy,
    Identifiers,
    Profile,
    Serializer,
    WireProfile
  }

  alias SSL.Crypto.KeyExchange
  alias SSL.Crypto.KeyExchange.KeyPair

  @grease_values Enum.map(0..15, &(0x0A0A + &1 * 0x1010))
  @grease_psk_modes [0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4]

  defmodule Materialized do
    @moduledoc """
    A public ClientHello AST and its separately retained ephemeral key pairs.
    """

    alias SSL.ClientHello.AST
    alias SSL.Crypto.KeyExchange.KeyPair

    @type t :: %__MODULE__{client_hello: AST.t(), key_pairs: [KeyPair.t()]}

    @derive {Inspect, except: [:key_pairs]}
    @enforce_keys [:client_hello, :key_pairs]
    defstruct [:client_hello, :key_pairs]
  end

  @type context :: %{optional(:server_name) => binary(), optional(:pre_shared_key) => binary()}

  @spec materialize(WireProfile.t(), Profile.capabilities(), context(), keyword()) ::
          {:ok, Materialized.t()} | {:error, term()}
  def materialize(profile, capabilities, context, opts \\ [])

  def materialize(%WireProfile{} = profile, capabilities, context, opts)
      when is_map(context) and is_list(opts) do
    with {:ok, _profile} <- Profile.validate(profile, capabilities),
         :ok <- validate_options(opts),
         {:ok, grease} <- grease_values(profile),
         {:ok, random} <- connection_random(opts),
         {:ok, session_id} <- session_id(profile.session_id, opts),
         {:ok, cipher_suites} <-
           resolve_uint16_list(profile.cipher_suites, :cipher_suite, grease),
         :ok <- reject_duplicates(cipher_suites, :cipher_suites),
         {:ok, extensions, key_pairs} <-
           materialize_extensions(profile.extensions, context, opts, grease),
         :ok <- reject_extension_duplicates(extensions) do
      client_hello = %AST{
        legacy_version: profile.legacy_version,
        random: random,
        session_id: session_id,
        cipher_suites: cipher_suites,
        compression_methods: profile.compression_methods,
        extensions: extensions
      }

      case Serializer.validate(client_hello) do
        :ok -> {:ok, %Materialized{client_hello: client_hello, key_pairs: key_pairs}}
        {:error, _reason} = error -> error
      end
    end
  end

  def materialize(_profile, _capabilities, _context, _opts),
    do: {:error, {:invalid_materialization, :arguments}}

  defp validate_options(opts) do
    allowed = [:test_random, :test_session_id, :test_key_share_generator]

    cond do
      not Keyword.keyword?(opts) ->
        {:error, {:invalid_materialization, :options}}

      unknown = Enum.find(Keyword.keys(opts), &(&1 not in allowed)) ->
        {:error, {:unknown_materialization_option, unknown}}

      true ->
        :ok
    end
  end

  defp connection_random(opts) do
    case Keyword.fetch(opts, :test_random) do
      :error -> {:ok, :crypto.strong_rand_bytes(32)}
      {:ok, random} when is_binary(random) and byte_size(random) == 32 -> {:ok, random}
      {:ok, _random} -> {:error, {:invalid_test_option, :test_random}}
    end
  end

  defp session_id(:empty, _opts), do: {:ok, <<>>}
  defp session_id({:fixed, session_id}, _opts), do: {:ok, session_id}

  defp session_id(:random_32, opts) do
    case Keyword.fetch(opts, :test_session_id) do
      :error ->
        {:ok, :crypto.strong_rand_bytes(32)}

      {:ok, session_id} when is_binary(session_id) and byte_size(session_id) == 32 ->
        {:ok, session_id}

      {:ok, _session_id} ->
        {:error, {:invalid_test_option, :test_session_id}}
    end
  end

  defp grease_values(%WireProfile{} = profile) do
    slots =
      (Enum.flat_map(profile.cipher_suites, &grease_slot/1) ++
         Enum.flat_map(profile.extensions, &extension_grease_slots/1))
      |> Enum.uniq()

    case {profile.grease, slots} do
      {%GreasePolicy{mode: :disabled}, []} ->
        {:ok, %{}}

      {%GreasePolicy{mode: {:deterministic, seed}}, slots} ->
        {:ok, assign_grease(slots, rem(seed, 16))}

      {%GreasePolicy{mode: :random}, slots} ->
        <<offset>> = :crypto.strong_rand_bytes(1)
        {:ok, assign_grease(slots, rem(offset, 16))}

      {%GreasePolicy{mode: :disabled}, _slots} ->
        {:error, :grease_not_supported}
    end
  end

  defp assign_grease(slots, offset) do
    slots
    |> Enum.with_index()
    |> Map.new(fn {slot, index} -> {slot, Enum.at(@grease_values, rem(offset + index, 16))} end)
  end

  defp grease_slot({:grease, slot}), do: [slot]
  defp grease_slot(_identifier), do: []

  defp extension_grease_slots({:grease, slot}), do: [slot]

  defp extension_grease_slots({tag, values})
       when tag in [
              :supported_groups,
              :signature_algorithms,
              :signature_algorithms_cert,
              :alpn,
              :supported_versions,
              :psk_key_exchange_modes,
              :key_share
            ] and is_list(values),
       do: Enum.flat_map(values, &grease_slot/1)

  defp extension_grease_slots(_extension), do: []

  defp resolve_uint16_list(values, kind, grease) do
    reduce_values(values, fn value -> resolve_uint16(value, kind, grease) end)
  end

  defp resolve_uint8_list(values, kind, grease) do
    reduce_values(values, fn
      {:grease, slot} -> grease_uint8(grease, slot)
      value -> Identifiers.uint8(kind, value)
    end)
  end

  defp resolve_uint16({:grease, slot}, _kind, grease), do: Map.fetch(grease, slot)
  defp resolve_uint16(value, kind, _grease), do: Identifiers.uint16(kind, value)

  defp grease_uint8(grease, slot) do
    with {:ok, value} <- Map.fetch(grease, slot),
         index when is_integer(index) <- Enum.find_index(@grease_values, &(&1 == value)) do
      {:ok, Enum.at(@grease_psk_modes, rem(index, length(@grease_psk_modes)))}
    else
      :error -> {:error, {:unknown_grease_slot, slot}}
    end
  end

  defp reduce_values(values, resolver) do
    values
    |> Enum.reduce_while({:ok, []}, fn value, {:ok, resolved} ->
      case resolver.(value) do
        {:ok, concrete} -> {:cont, {:ok, [concrete | resolved]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, resolved} -> {:ok, Enum.reverse(resolved)}
      error -> error
    end
  end

  defp materialize_extensions(extensions, context, opts, grease) do
    extensions
    |> Enum.reduce_while({:ok, [], []}, fn extension, {:ok, encoded, key_pairs} ->
      case materialize_extension(extension, context, opts, grease) do
        {:ok, encoded_extension, new_key_pairs} ->
          {:cont, {:ok, [encoded_extension | encoded], Enum.reverse(new_key_pairs, key_pairs)}}

        {:error, _reason} = error ->
          {:halt, error}
      end
    end)
    |> case do
      {:ok, encoded, key_pairs} -> {:ok, Enum.reverse(encoded), Enum.reverse(key_pairs)}
      error -> error
    end
  end

  defp materialize_extension({:server_name, :from_connection}, context, _opts, _grease) do
    with {:ok, server_name} <- fetch_material(context, :server_name),
         true <- is_binary(server_name) and byte_size(server_name) > 0 do
      Extension.encode({:server_name, server_name})
      |> with_no_key_pairs()
    else
      false -> {:error, {:invalid_material, :server_name}}
      {:error, _reason} = error -> error
    end
  end

  defp materialize_extension({:pre_shared_key, :deferred}, context, _opts, _grease) do
    with {:ok, payload} <- fetch_material(context, :pre_shared_key),
         true <- is_binary(payload) do
      Extension.encode({:pre_shared_key, payload})
      |> with_no_key_pairs()
    else
      false -> {:error, {:invalid_material, :pre_shared_key}}
      {:error, _reason} = error -> error
    end
  end

  defp materialize_extension({:grease, slot}, _context, _opts, grease) do
    case Map.fetch(grease, slot) do
      {:ok, extension_id} ->
        {:ok, {extension_id, <<>>}, []}

      :error ->
        {:error, {:unknown_grease_slot, slot}}
    end
  end

  defp materialize_extension({:supported_groups, groups}, _context, _opts, grease),
    do: materialize_uint16_extension(:supported_groups, groups, :group, grease)

  defp materialize_extension({:signature_algorithms, algorithms}, _context, _opts, grease),
    do:
      materialize_uint16_extension(
        :signature_algorithms,
        algorithms,
        :signature_algorithm,
        grease
      )

  defp materialize_extension({:signature_algorithms_cert, algorithms}, _context, _opts, grease),
    do:
      materialize_uint16_extension(
        :signature_algorithms_cert,
        algorithms,
        :signature_algorithm,
        grease
      )

  defp materialize_extension({:supported_versions, versions}, _context, _opts, grease),
    do: materialize_uint16_extension(:supported_versions, versions, :version, grease)

  defp materialize_extension({:psk_key_exchange_modes, modes}, _context, _opts, grease) do
    with {:ok, resolved} <- resolve_uint8_list(modes, :psk_mode, grease),
         :ok <- reject_duplicates(resolved, :psk_key_exchange_modes),
         {:ok, encoded} <- Extension.encode({:psk_key_exchange_modes, resolved}) do
      {:ok, encoded, []}
    end
  end

  defp materialize_extension({:alpn, protocols}, _context, _opts, grease) do
    with {:ok, resolved} <- materialize_alpn(protocols, grease),
         :ok <- reject_duplicates(resolved, :alpn),
         {:ok, encoded} <- Extension.encode({:alpn, resolved}) do
      {:ok, encoded, []}
    end
  end

  defp materialize_extension({:key_share, groups}, _context, opts, grease) do
    with {:ok, generator} <- key_share_generator(opts),
         {:ok, entries, key_pairs} <- materialize_key_shares(groups, grease, generator),
         :ok <- reject_duplicates(Enum.map(entries, &elem(&1, 0)), :key_share),
         {:ok, encoded} <- Extension.encode({:key_share, entries}) do
      {:ok, encoded, key_pairs}
    end
  end

  defp materialize_extension({:ec_point_formats, formats}, _context, _opts, _grease),
    do: Extension.encode({:ec_point_formats, formats}) |> with_no_key_pairs()

  defp materialize_extension({:extended_master_secret, <<>>}, _context, _opts, _grease),
    do: Extension.encode({:extended_master_secret, <<>>}) |> with_no_key_pairs()

  defp materialize_extension({:renegotiation_info, <<0>>}, _context, _opts, _grease),
    do: Extension.encode({:renegotiation_info, <<0>>}) |> with_no_key_pairs()

  defp materialize_extension({:padding, {:fixed, size}}, _context, _opts, _grease),
    do: Extension.encode({:padding, size}) |> with_no_key_pairs()

  defp materialize_extension({:padding, size}, _context, _opts, _grease),
    do: Extension.encode({:padding, size}) |> with_no_key_pairs()

  defp materialize_extension({:raw, extension_id, payload}, _context, _opts, _grease),
    do: Extension.encode({:raw, extension_id, payload}) |> with_no_key_pairs()

  defp materialize_uint16_extension(tag, values, kind, grease) do
    with {:ok, resolved} <- resolve_uint16_list(values, kind, grease),
         :ok <- reject_duplicates(resolved, tag),
         {:ok, encoded} <- Extension.encode({tag, resolved}) do
      {:ok, encoded, []}
    end
  end

  defp materialize_alpn(protocols, grease) do
    reduce_values(protocols, fn
      {:grease, slot} ->
        with {:ok, value} <- Map.fetch(grease, slot), do: {:ok, <<value::16>>}

      protocol when is_binary(protocol) ->
        {:ok, protocol}
    end)
  end

  defp materialize_key_shares(groups, grease, generator) do
    groups
    |> Enum.reduce_while({:ok, [], []}, fn group, {:ok, entries, key_pairs} ->
      case materialize_key_share(group, grease, generator) do
        {:ok, entry, nil} -> {:cont, {:ok, [entry | entries], key_pairs}}
        {:ok, entry, key_pair} -> {:cont, {:ok, [entry | entries], [key_pair | key_pairs]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, entries, key_pairs} -> {:ok, Enum.reverse(entries), Enum.reverse(key_pairs)}
      error -> error
    end
  end

  defp materialize_key_share({:grease, slot}, grease, _generator) do
    case Map.fetch(grease, slot) do
      {:ok, value} ->
        {:ok, {value, <<value::16>>}, nil}

      :error ->
        {:error, {:unknown_grease_slot, slot}}
    end
  end

  defp materialize_key_share(group, grease, generator) do
    with {:ok, group_id} <- resolve_uint16(group, :group, grease),
         {:ok, key_exchange_group} <- Identifiers.key_exchange_group(group),
         {:ok, %KeyPair{} = key_pair} <- generator.(key_exchange_group),
         :ok <- validate_generated_key_pair(key_pair, key_exchange_group) do
      {:ok, {group_id, key_pair.public_key}, key_pair}
    else
      {:ok, other} -> {:error, {:invalid_key_share_generator_result, other}}
      {:error, _reason} = error -> error
      other -> {:error, {:invalid_key_share_generator_result, other}}
    end
  end

  defp key_share_generator(opts) do
    case Keyword.fetch(opts, :test_key_share_generator) do
      :error -> {:ok, &KeyExchange.generate/1}
      {:ok, generator} when is_function(generator, 1) -> {:ok, generator}
      {:ok, _generator} -> {:error, {:invalid_test_option, :test_key_share_generator}}
    end
  end

  defp validate_generated_key_pair(%KeyPair{group: group, public_key: public_key}, group)
       when is_binary(public_key) do
    case SSL.Capabilities.resolve(:group, group) do
      %{share_size: size, share_encoding: encoding} when byte_size(public_key) == size ->
        if encoding == :raw or match?(<<4, _::binary>>, public_key),
          do: :ok,
          else: {:error, {:invalid_generated_key_share, group}}

      _ ->
        {:error, {:invalid_generated_key_share, group}}
    end
  end

  defp validate_generated_key_pair(_key_pair, group),
    do: {:error, {:invalid_generated_key_share, group}}

  defp fetch_material(context, field) do
    case Map.fetch(context, field) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:missing_material, field}}
    end
  end

  defp reject_extension_duplicates(extensions) do
    reject_duplicates(Enum.map(extensions, &elem(&1, 0)), :extension)
  end

  defp reject_duplicates(values, field) do
    case Enum.reduce_while(values, MapSet.new(), fn value, seen ->
           if MapSet.member?(seen, value) do
             {:halt, {:duplicate, value}}
           else
             {:cont, MapSet.put(seen, value)}
           end
         end) do
      %MapSet{} -> :ok
      {:duplicate, value} when field == :extension -> {:error, {:duplicate_extension, value}}
      {:duplicate, value} -> {:error, {:duplicate_materialized_identifier, field, value}}
    end
  end

  defp with_no_key_pairs({:ok, encoded}), do: {:ok, encoded, []}
  defp with_no_key_pairs({:error, _reason} = error), do: error
end
