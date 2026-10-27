defmodule SSL.ResumptionContext do
  @moduledoc false
  alias SSL.{Options, SessionTicket, TicketCache}
  alias SSL.Protocol.Resumption

  @spec prepare(Options.t(), term()) ::
          {:ok, Options.t(), SessionTicket.t() | nil,
           binary() | {:manual, binary(), charlist() | :undefined} | nil}
  def prepare(%{policy: policy} = options, _endpoint) when policy != nil do
    {:ok, prepared, nil} = material(nil, options)
    {:ok, prepared, nil, nil}
  end

  def prepare(%{verify_fun: policy} = options, _endpoint) when policy != :undefined do
    {:ok, prepared, nil} = material(nil, options)
    {:ok, %{prepared | session_tickets: :disabled}, nil, nil}
  end

  def prepare(%{session_tickets: :disabled} = options, _endpoint), do: {:ok, options, nil, nil}

  def prepare(%{session_tickets: :auto} = options, endpoint) do
    key = partition(options, endpoint)

    ticket =
      case TicketCache.checkout(key) do
        {:ok, candidate} -> validate_peer(candidate, options)
        :miss -> nil
      end

    case material(ticket, options) do
      {:ok, prepared, selected} -> {:ok, prepared, selected, key}
    end
  end

  def prepare(%{session_tickets: :manual} = options, endpoint) do
    key = partition(options, endpoint)

    ticket =
      Enum.find_value(options.use_ticket, fn
        %SessionTicket{context: ^key} = candidate -> validate_peer(candidate, options)
        _ -> nil
      end)

    sni =
      case Map.get(options.context, :server_name) do
        name when is_binary(name) -> String.to_charlist(name)
        _ -> :undefined
      end

    {:ok, prepared, selected} = material(ticket, options)
    {:ok, prepared, selected, {:manual, key, sni}}
  end

  @doc false
  def partition(options, endpoint) do
    :crypto.hash(
      :sha256,
      :erlang.term_to_binary(
        {:ex_ssl_ticket_policy, 3, options.verify, options.endpoint, endpoint, options.identity,
         Map.get(options.context, :server_name), options.trust_source, options.profile,
         options.depth, options.hostname_check, options.client_identity,
         if(options.session_tickets == :manual,
           do: {:manual, Process.whereis(:init)},
           else: :auto
         )}
      )
    )
  end

  defp validate_peer(candidate, options) do
    policy =
      case List.keyfind(options.profile.extensions, :signature_algorithms_cert, 0) do
        {_, ids} ->
          Enum.map(ids, &SSL.Capabilities.resolve(:certificate_signature_algorithm, &1).id)

        nil ->
          nil
      end

    with :ok <- SessionTicket.validate(candidate),
         true <- candidate.expires_at > System.monotonic_time(:millisecond),
         true <-
           candidate.alpn == nil or candidate.alpn in (options.alpn_advertised_protocols || []),
         true <-
           Enum.any?(options.profile.cipher_suites, fn id ->
             match?(
               %{version: 0x0304, hash: hash} when hash == candidate.hash,
               SSL.Capabilities.resolve(:cipher_suite, id)
             )
           end),
         {:ok, peer} <-
           SSL.PKIX.peer(
             candidate.peer.chain,
             options.trust_source,
             options.identity,
             options.verify,
             depth: options.depth,
             customize_hostname_check: options.hostname_check,
             certificate_signature_schemes: policy
           ) do
      %{candidate | peer: peer}
    else
      _ -> nil
    end
  end

  defp material(nil, options) do
    profile = %{
      options.profile
      | extensions: Enum.reject(options.profile.extensions, &match?({:pre_shared_key, _}, &1))
    }

    {:ok, %{options | profile: profile}, nil}
  end

  defp material(ticket, options) do
    case Resumption.psk_extension(ticket, System.monotonic_time(:millisecond)) do
      {:ok, payload} ->
        {:ok, %{options | context: Map.put(options.context, :pre_shared_key, payload)}, ticket}

      {:error, _} ->
        material(nil, options)
    end
  end

  @spec store(binary(), map()) :: :ok
  def store(key, material) do
    _ = TicketCache.put(key, new_ticket(material))
    :ok
  end

  @doc false
  def store({:manual, key, sni}, material, owner) do
    ticket = %{new_ticket(material) | context: key, sni: sni}

    if SessionTicket.validate(ticket) == :ok do
      send(owner, {:ssl, :session_ticket, ticket})
    end

    :ok
  end

  def store(key, material, _owner), do: store(key, material)

  defp new_ticket(material) do
    now = System.monotonic_time(:millisecond)

    %SessionTicket{
      ticket: material.ticket,
      psk: material.psk,
      hash: material.hash,
      age_add: material.age_add,
      issued_at: now,
      expires_at: now + material.lifetime * 1_000,
      peer: material.peer,
      alpn: material.alpn
    }
  end
end
