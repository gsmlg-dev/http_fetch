defmodule SSL.Protocol.ClientHandshake do
  @moduledoc "Shared record-free ClientHello and HelloRetryRequest orchestration."
  alias SSL.ClientHello.{Extension, Serializer}
  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.KeyExchange
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.Protocol.{ClientOffer, Resumption, ServerHello, Transcript}

  @spec prepare(Materialized.t(), term(), SSL.PKIX.identity(), keyword()) ::
          {:ok, map(), binary()} | {:error, term()}
  def prepare(%Materialized{} = materialized, trust_source, identity, opts) when is_list(opts) do
    {client_identity, verifier_opts} = Keyword.pop(opts, :client_identity)
    {ticket, verifier_opts} = Keyword.pop(verifier_opts, :ticket)
    {enable_tickets, verifier_opts} = Keyword.pop(verifier_opts, :enable_tickets, false)

    with {:ok, unsigned} <- encoded_client_hello(materialized, verifier_opts),
         {:ok, client_hello} <- bind_hello(unsigned, ticket, <<>>),
         {:ok, offer} <- ClientOffer.from_client_hello(client_hello),
         {:ok, key_pairs} <- matching_key_pairs(materialized.key_pairs, offer),
         :ok <- validate_identity(identity) do
      state = %{
        client_hello: client_hello,
        client_ast: materialized.client_hello,
        key_pair: List.first(key_pairs),
        key_pairs: key_pairs,
        trust_source: trust_source,
        identity: identity,
        client_identity: client_identity,
        ticket: ticket,
        enable_tickets: enable_tickets,
        offer: offer,
        phase: :await_server_hello,
        hrr: nil,
        hrr_transcript: nil,
        options: verifier_opts
      }

      {:ok, state, client_hello}
    end
  end

  def prepare(_, _, _, _), do: {:error, {:invalid_input, :handshake_machine}}

  def retry(state, %ServerHello{kind: :hello_retry_request} = hrr) do
    if state.phase == :await_server_hello_after_retry do
      fatal(:unexpected_message, :second_hello_retry_request)
    else
      with {:ok, ast, key_pair} <- retry_client_hello(state.client_ast, state.key_pair, hrr),
           {:ok, _suite, hash} <- suite(hrr.cipher_suite),
           {ast, ticket} = retry_ticket(ast, state.ticket, hash),
           prefix =
             Transcript.new(hash)
             |> Transcript.append(state.client_hello)
             |> Transcript.apply_hello_retry_request_rewrite()
             |> Transcript.append(hrr.encoded),
           {:ok, unsigned} <- Serializer.encode(ast),
           {:ok, encoded} <-
             bind_hello(
               unsigned,
               ticket,
               prefix.messages |> Enum.reverse() |> IO.iodata_to_binary()
             ),
           {:ok, offer} <- ClientOffer.from_client_hello(encoded) do
        transcript = Transcript.append(prefix, encoded)

        {:ok,
         %{
           state
           | client_ast: ast,
             client_hello: encoded,
             ticket: ticket,
             key_pair: key_pair,
             key_pairs: retry_key_pairs(state.key_pairs, hrr, key_pair),
             offer: offer,
             phase: :await_server_hello_after_retry,
             hrr: hrr,
             hrr_transcript: transcript
         }, encoded}
      else
        {:error, reason} -> fatal(:illegal_parameter, reason)
      end
    end
  end

  defp retry_client_hello(ast, current_pair, hrr) do
    selected =
      Enum.find_value(hrr.extensions, fn
        {:selected_group, group} -> group
        _ -> nil
      end)

    cookie =
      Enum.find_value(hrr.extensions, fn
        {:cookie, value} -> value
        _ -> nil
      end)

    with {:ok, pair} <- retry_key_pair(selected, current_pair),
         {:ok, extensions} <- retry_extensions(ast.extensions, selected, pair, cookie) do
      {:ok, %{ast | extensions: extensions}, pair}
    end
  end

  defp retry_key_pair(nil, pair), do: {:ok, pair}

  defp retry_key_pair(group, _pair) do
    case SSL.Capabilities.resolve(:group, group) do
      %{name: name} -> KeyExchange.generate(name)
      nil -> {:error, {:unsupported_selected_group, group}}
    end
  end

  defp retry_key_pairs(key_pairs, hrr, pair) do
    if Enum.any?(hrr.extensions, &match?({:selected_group, _}, &1)),
      do: [pair],
      else: key_pairs
  end

  defp retry_extensions(extensions, selected, pair, cookie) do
    with {:ok, key_share} <- retry_key_share_extension(selected, pair),
         {:ok, cookie_extension} <- retry_cookie_extension(cookie) do
      replaced =
        extensions
        |> Enum.map(fn
          {51, _} when not is_nil(key_share) -> key_share
          {42, _} -> nil
          extension -> extension
        end)
        |> Enum.reject(&is_nil/1)

      {:ok, insert_cookie(replaced, cookie_extension)}
    end
  end

  defp retry_key_share_extension(nil, _pair), do: {:ok, nil}

  defp retry_key_share_extension(_selected, pair),
    do: Extension.encode({:key_share, [{group_id(pair.group), pair.public_key}]})

  defp retry_cookie_extension(nil), do: {:ok, nil}

  defp retry_cookie_extension(cookie) when byte_size(cookie) <= 65_533,
    do: {:ok, {44, <<byte_size(cookie)::16, cookie::binary>>}}

  defp insert_cookie(extensions, nil), do: extensions

  defp insert_cookie(extensions, cookie) do
    {before_psk, psk} = Enum.split_while(extensions, &(elem(&1, 0) != 41))
    before_psk ++ [cookie] ++ psk
  end

  defp encoded_client_hello(%Materialized{client_hello: ast}, opts) do
    case Keyword.fetch(opts, :encoded_client_hello) do
      {:ok, encoded} when is_binary(encoded) -> {:ok, encoded}
      :error -> Serializer.encode(ast)
      {:ok, _} -> {:error, :invalid_encoded_client_hello}
    end
  end

  defp matching_key_pairs(key_pairs, offer) when is_list(key_pairs) do
    matching =
      Enum.filter(key_pairs, fn
        %KeyPair{group: group, public_key: public} ->
          Enum.any?(
            offer.key_shares,
            &(&1.group == group_id(group) and :crypto.hash_equals(&1.key_exchange, public))
          )

        _ ->
          false
      end)

    cond do
      matching == [] and offer.key_shares == [] and 0x0303 in offer.offered_versions and
        0x0304 not in offer.offered_versions and key_pairs == [] ->
        {:ok, []}

      matching == [] ->
        {:error, :no_matching_client_key_share}

      true ->
        Enum.reduce_while(matching, {:ok, []}, fn pair, {:ok, valid} ->
          case KeyExchange.validate_key_pair(pair) do
            :ok -> {:cont, {:ok, [pair | valid]}}
            {:error, _} = error -> {:halt, error}
          end
        end)
        |> case do
          {:ok, valid} -> {:ok, Enum.reverse(valid)}
          error -> error
        end
    end
  end

  defp matching_key_pairs(_, _), do: {:error, :invalid_key_pairs}

  def selected_key_pair(key_pairs, fallback, hello) do
    selected_group =
      Enum.find_value(hello.extensions, fn
        {:key_share, %{group: group}} -> group
        _ -> nil
      end)

    case Enum.find(key_pairs || [], &(group_id(&1.group) == selected_group)) do
      %KeyPair{} = pair ->
        {:ok, pair}

      nil ->
        if group_id(fallback.group) == selected_group,
          do: {:ok, fallback},
          else: {:error, {:missing_key_pair_for_selected_group, selected_group}}
    end
  end

  def validate_hrr_selection(nil, _hello), do: :ok

  def validate_hrr_selection(hrr, hello) do
    selected_group =
      Enum.find_value(hrr.extensions, fn
        {:selected_group, group} -> group
        _ -> nil
      end)

    final_group =
      Enum.find_value(hello.extensions, fn
        {:key_share, %{group: group}} -> group
        _ -> nil
      end)

    cond do
      hello.cipher_suite != hrr.cipher_suite ->
        {:error, :hello_retry_request_cipher_changed}

      not is_nil(selected_group) and final_group != selected_group ->
        {:error, :hello_retry_request_group_changed}

      true ->
        :ok
    end
  end

  defp bind_hello(encoded, nil, _prefix), do: {:ok, encoded}
  defp bind_hello(encoded, ticket, prefix), do: Resumption.bind(encoded, ticket, prefix)
  defp retry_ticket(ast, nil, _hash), do: {ast, nil}
  defp retry_ticket(ast, %{hash: hash} = ticket, hash), do: {ast, ticket}

  defp retry_ticket(ast, _ticket, _hash),
    do: {%{ast | extensions: Enum.reject(ast.extensions, &(elem(&1, 0) == 41))}, nil}

  def decode_server_hello(encoded, offer, previous_hrr \\ nil, opts \\ []) do
    if repeated_retry?(encoded, previous_hrr),
      do: fatal(:unexpected_message, :second_hello_retry_request),
      else: do_decode_server_hello(encoded, offer, opts)
  end

  defp repeated_retry?(
         <<2, size::24, 0x0303::16, random::binary-size(32), _::binary>> = encoded,
         %ServerHello{random: random}
       )
       when byte_size(encoded) == size + 4 do
    true
  end

  defp repeated_retry?(_, _), do: false

  defp do_decode_server_hello(encoded, offer, opts) do
    expectations = %{
      legacy_session_id: offer.legacy_session_id,
      offered_ciphers: offer.cipher_suites,
      offered_versions: offer.offered_versions,
      offered_groups: offer.supported_groups,
      offered_key_share_groups: Enum.map(offer.key_shares, & &1.group),
      offered_extension_ids: offer.extension_ids,
      offered_psk_key_exchange_modes: offer.psk_key_exchange_modes,
      offered_psk_count: offer.psk_count
    }

    case ServerHello.decode(encoded, expectations, opts) do
      {:ok, %ServerHello{} = hello, <<>>} -> {:ok, hello}
      {:ok, _, remainder} -> {:error, {:trailing_server_hello, byte_size(remainder)}}
      {:error, {:extension_length_exceeded, _, _, _} = reason} -> fatal(:decode_error, reason)
      {:error, reason} -> {:error, {:fatal_alert, :illegal_parameter, reason}}
      other -> {:error, {:fatal_alert, :decode_error, other}}
    end
  end

  defp suite(value) do
    case SSL.Capabilities.resolve(:cipher_suite, value) do
      %{version: 0x0304, name: name, hash: hash} -> {:ok, name, hash}
      _ -> {:error, {:unsupported_cipher_suite, value}}
    end
  end

  defp group_id(group), do: SSL.Capabilities.resolve(:group, group).id

  defp validate_identity({:dns_id, name}) when is_binary(name), do: :ok
  defp validate_identity({:ip, _}), do: :ok
  defp validate_identity(_), do: {:error, :invalid_identity}

  defp fatal(alert, reason), do: {:error, {:fatal_alert, alert, reason}}
end
