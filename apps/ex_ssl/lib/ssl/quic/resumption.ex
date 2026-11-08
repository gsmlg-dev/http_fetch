defmodule SSL.QUIC.Resumption do
  @moduledoc false
  alias SSL.QUIC.Session
  alias SSL.Protocol.{Resumption, Transcript}
  alias SSL.Crypto.KeySchedule

  def policy(nil), do: {:ok, nil}

  def policy(opts) when is_list(opts) do
    with true <- Keyword.keyword?(opts),
         true <- Keyword.keys(opts) == Enum.uniq(Keyword.keys(opts)),
         true <-
           Enum.all?(
             Keyword.keys(opts),
             &(&1 in [:enabled, :context, :now, :session, :ticket_lifetime, :early_data])
           ),
         true <- opts[:enabled] == true,
         context when is_binary(context) and byte_size(context) in 1..256 <- opts[:context],
         now when is_integer(now) <- opts[:now],
         lifetime when is_integer(lifetime) and lifetime in 1..600 <-
           Keyword.get(opts, :ticket_lifetime, 600),
         early when is_boolean(early) <- Keyword.get(opts, :early_data, false),
         session = opts[:session],
         true <- is_nil(session) or Session.validate(session) == :ok do
      {:ok,
       %{
         context: context,
         now: now,
         session: session,
         ticket_lifetime: lifetime,
         early_data: early
       }}
    else
      _ -> {:error, :invalid_resumption_policy}
    end
  end

  def policy(_), do: {:error, :invalid_resumption_policy}

  def client_session(%{resumption: nil}), do: nil
  def client_session(%{resumption: %{session: nil}}), do: nil

  def client_session(config) do
    s = config.resumption.session

    with true <- eligible?(s, config, config.resumption.now),
         true <- is_map(s.peer) and is_list(Map.get(s.peer, :chain)),
         {:ok, peer} <-
           SSL.PKIX.peer(s.peer.chain, config.trust, config.reference_identity, :verify_peer,
             depth: config.verifier_options[:depth],
             customize_hostname_check: config.verifier_options[:customize_hostname_check],
             max_certificates: config.limits[:max_certificate_count],
             max_der_bytes: config.limits[:max_certificate_bytes],
             max_total_der_bytes: config.limits[:max_total_certificate_bytes],
             certificate_signature_schemes: certificate_policy(config)
           ) do
      %{s | peer: peer}
    else
      _ -> nil
    end
  end

  defp certificate_policy(%{profile: nil}),
    do: Enum.filter(SSL.Capabilities.identifiers(:certificate_signature_algorithm), &is_integer/1)

  defp certificate_policy(
         %{profile: %SSL.ClientHello.WireProfile{extensions: extensions}} = config
       )
       when is_list(extensions) do
    case List.keyfind(extensions, :signature_algorithms_cert, 0) ||
           List.keyfind(extensions, :signature_algorithms, 0) do
      nil ->
        config.signature_algorithms

      {_, ids} ->
        Enum.map(ids, &SSL.Capabilities.resolve(:certificate_signature_algorithm, &1).id)
    end
  end

  defp certificate_policy(_), do: nil

  def eligible?(%Session{} = s, config, now) when is_integer(now) do
    Session.validate(s) == :ok and now >= s.issued_at and now < s.expires_at and
      config.resumption != nil and s.context == config.resumption.context and
      s.alpn in config.alpn and (config.role == :server or s.server_name == config.server_name) and
      Enum.any?(config.ciphers, &(SSL.Capabilities.resolve(:cipher_suite, &1).hash == s.hash))
  end

  def eligible?(_, _, _), do: false

  # Adapt only the shared cryptographic client's existing input, never its cache/policy.
  def ticket(%Session{} = s) do
    %SSL.SessionTicket{
      ticket: s.identity,
      psk: s.psk,
      hash: s.hash,
      age_add: s.age_add,
      issued_at: s.issued_at,
      expires_at: s.expires_at,
      peer: s.peer,
      alpn: s.alpn
    }
  end

  def offer(config, material, nil) do
    extensions =
      material.client_hello.extensions ++ if(config.resumption, do: [{45, <<1, 1>>}], else: [])

    {:ok, %{material | client_hello: %{material.client_hello | extensions: extensions}}}
  end

  def offer(config, material, session) do
    with {:ok, payload} <- Resumption.psk_extension(ticket(session), config.resumption.now) do
      extensions =
        material.client_hello.extensions ++
          [{45, <<1, 1>>}] ++
          if(early?(config, session), do: [{42, <<>>}], else: []) ++ [{41, payload}]

      {:ok, %{material | client_hello: %{material.client_hello | extensions: extensions}}}
    end
  end

  def early?(%{resumption: %{early_data: true}}, %Session{max_early_data: 0xFFFFFFFF}), do: true
  def early?(_, _), do: false

  def early_secret(session, hello) do
    with {:ok, secret} <- KeySchedule.early_secret(session.hash, session.psk),
         {:ok, traffic} <-
           KeySchedule.client_early_traffic_secret(
             session.hash,
             secret,
             :crypto.hash(session.hash, hello)
           ) do
      {:ok, traffic}
    end
  end

  def server_name(offer) do
    case List.keyfind(offer.extensions, 0, 0) do
      {0, <<_size::16, 0, length::16, name::binary-size(length), _::binary>>} -> name
      _ -> nil
    end
  end

  def early_age_valid?(session, offer, now) do
    {:ok, _, age} = first_identity(offer)
    reported = Integer.mod(age - session.age_add, 0x1_0000_0000)
    abs(reported - (now - session.issued_at)) <= 10_000
  end

  def first_identity(offer) do
    case List.keyfind(offer.extensions, 41, 0) do
      {41, <<size::16, identities::binary-size(size), _::binary>>} ->
        <<length::16, identity::binary-size(length), age::32, _::binary>> = identities
        {:ok, identity, age}

      nil ->
        :none
    end
  end

  def verify(session, offer, previous) do
    prefix =
      if previous,
        do: previous.transcript.messages |> Enum.reverse() |> IO.iodata_to_binary(),
        else: <<>>

    Resumption.verify_binder(offer.encoded, session.psk, session.hash, prefix)
  end

  def new_ticket(config, suite, alpn, master, transcript) do
    spec = SSL.Capabilities.resolve(:cipher_suite, suite)
    nonce = :crypto.strong_rand_bytes(16)
    identity = :crypto.strong_rand_bytes(32)
    <<age::32>> = :crypto.strong_rand_bytes(4)

    {:ok, rms} =
      KeySchedule.resumption_master_secret(spec.hash, master, Transcript.digest(transcript))

    {:ok, psk} = KeySchedule.resumption_secret(spec.hash, rms, nonce)
    lifetime = config.resumption.ticket_lifetime
    early = if config.resumption.early_data, do: 0xFFFFFFFF, else: 0

    session = %Session{
      identity: identity,
      psk: psk,
      hash: spec.hash,
      cipher_suite: suite,
      age_add: age,
      issued_at: config.resumption.now,
      expires_at: config.resumption.now + lifetime * 1000,
      context: config.resumption.context,
      alpn: alpn,
      server_name: nil,
      transport_parameters: config.transport_parameters,
      max_early_data: early
    }

    extensions = if early == 0, do: <<>>, else: <<42::16, 4::16, early::32>>

    body =
      <<lifetime::32, age::32, byte_size(nonce), nonce::binary, byte_size(identity)::16,
        identity::binary, byte_size(extensions)::16, extensions::binary>>

    {session, <<4, byte_size(body)::24, body::binary>>}
  end

  def valid_ticket_early_data?(ticket) do
    case List.keyfind(ticket.extensions, :early_data, 0) do
      nil -> true
      {:early_data, 0xFFFFFFFF} -> true
      _ -> false
    end
  end

  def receive_ticket(ticket, metadata) do
    early =
      case List.keyfind(ticket.extensions, :early_data, 0) do
        nil -> 0
        {:early_data, value} -> value
      end

    cond do
      early not in [0, 0xFFFFFFFF] ->
        {:error, {:illegal_parameter, :invalid_quic_early_data_maximum}}

      ticket.ticket_lifetime == 0 ->
        :skip

      true ->
        {:ok, psk} =
          KeySchedule.resumption_secret(metadata.hash, metadata.master, ticket.ticket_nonce)

        s = %Session{
          identity: ticket.ticket,
          psk: psk,
          hash: metadata.hash,
          cipher_suite: metadata.suite,
          age_add: ticket.ticket_age_add,
          issued_at: metadata.now,
          expires_at: metadata.now + ticket.ticket_lifetime * 1000,
          alpn: metadata.alpn,
          context: metadata.context,
          server_name: metadata.server_name,
          peer: metadata.peer,
          transport_parameters: metadata.parameters,
          max_early_data: early
        }

        if Session.validate(s) == :ok, do: {:ok, s}, else: :skip
    end
  end
end
