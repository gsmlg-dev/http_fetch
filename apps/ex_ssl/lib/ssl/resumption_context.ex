defmodule SSL.ResumptionContext do
  @moduledoc false
  alias SSL.{Options, SessionTicket, TicketCache}
  alias SSL.Protocol.Resumption

  @spec prepare(Options.t(), term()) ::
          {:ok, Options.t(), SessionTicket.t() | nil, binary() | nil}
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

  @doc false
  def partition(options, endpoint) do
    :crypto.hash(
      :sha256,
      :erlang.term_to_binary(
        {:ex_ssl_ticket_policy, 1, options.endpoint, endpoint, options.identity,
         options.trust_source, options.profile, options.depth, options.hostname_check}
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
           SSL.PKIX.verify(candidate.peer.chain, options.trust_source, options.identity,
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
    now = System.monotonic_time(:millisecond)

    ticket = %SessionTicket{
      ticket: material.ticket,
      psk: material.psk,
      hash: material.hash,
      age_add: material.age_add,
      issued_at: now,
      expires_at: now + material.lifetime * 1_000,
      peer: material.peer,
      alpn: material.alpn
    }

    _ = TicketCache.put(key, ticket)
    :ok
  end
end
