defmodule SSL.TLS12ResumptionContext do
  @moduledoc false

  alias SSL.{Options, SessionCache, TLS12Session}

  @spec prepare(Options.t(), term()) ::
          {:ok, Options.t(), TLS12Session.t() | nil, {binary(), boolean() | :save} | nil}
  def prepare(options, endpoint) do
    if enabled?(options) do
      key = partition(options, endpoint)
      reference = options.reuse_session || if(options.reuse_sessions == true, do: :auto)

      candidate =
        case SessionCache.lookup(key, reference) do
          {:ok, session} -> validate_peer(session, options)
          :miss -> nil
        end

      {prepared, selected} = material(options, candidate)
      {:ok, prepared, selected, {key, options.reuse_sessions}}
    else
      {:ok, options, nil, nil}
    end
  end

  defp enabled?(options) do
    options.policy == nil and options.verify_fun == :undefined and
      Enum.any?(options.profile.extensions, fn
        {:supported_versions, versions} -> 0x0303 in versions or :tlsv1_2 in versions
        _ -> false
      end)
  end

  @doc false
  def partition(options, endpoint) do
    :crypto.hash(
      :sha256,
      :erlang.term_to_binary(
        {:ex_ssl_tls12_ems_policy, 1, options.verify, options.endpoint, endpoint,
         options.identity, Map.get(options.context, :server_name), options.trust_source,
         options.profile, options.depth, options.hostname_check, options.client_identity}
      )
    )
  end

  defp validate_peer(session, options) do
    policy =
      Keyword.get(options.profile.extensions, :signature_algorithms_cert) ||
        Keyword.get(options.profile.extensions, :signature_algorithms)

    policy =
      if policy,
        do: Enum.map(policy, &SSL.Capabilities.resolve(:certificate_signature_algorithm, &1).id)

    with :ok <- TLS12Session.validate(session),
         true <- session.expires_at > System.monotonic_time(:millisecond),
         true <-
           session.alpn == nil or session.alpn in (options.alpn_advertised_protocols || []),
         true <-
           Enum.any?(options.profile.cipher_suites, fn id ->
             match?(
               %{id: saved} when saved == session.suite,
               SSL.Capabilities.resolve(:cipher_suite, id)
             )
           end),
         {:ok, peer} <-
           SSL.PKIX.peer(
             session.peer.chain,
             options.trust_source,
             options.identity,
             options.verify,
             [
               depth: options.depth,
               customize_hostname_check: options.hostname_check,
               certificate_signature_schemes: policy
             ],
             :tls12
           ) do
      %{session | peer: peer}
    else
      _ -> nil
    end
  end

  # A fixed profile ID is a caller wire constraint; a different cached ID must
  # not silently replace it. Generated empty/random IDs can carry a saved ID.
  defp material(%{profile: %{session_id: {:fixed, id}}} = options, %{id: saved})
       when id != saved,
       do: {options, nil}

  defp material(options, nil), do: {options, nil}

  defp material(options, session),
    do: {%{options | profile: %{options.profile | session_id: {:fixed, session.id}}}, session}

  @spec retain({binary(), boolean() | :save} | nil, map()) :: TLS12Session.t() | nil
  def retain(nil, _material), do: nil

  def retain({key, mode}, %TLS12Session{} = session) do
    if TLS12Session.validate(session) == :ok and
         session.expires_at > System.monotonic_time(:millisecond) do
      session = %{session | auto: session.auto or mode == true}
      if mode in [true, :save], do: SessionCache.put(key, session)
      session
    end
  end

  def retain({key, mode}, material) do
    now = System.monotonic_time(:millisecond)

    session =
      %TLS12Session{
        id: material.id,
        master_secret: material.master_secret,
        suite: material.suite,
        peer: material.peer,
        alpn: material.alpn,
        issued_at: now,
        expires_at: now + 600_000,
        auto: mode == true
      }

    if TLS12Session.validate(session) == :ok do
      if mode in [true, :save], do: SessionCache.put(key, session)
      session
    end
  end

  @spec export(binary(), TLS12Session.t()) :: {:ok, binary(), TLS12Session.t()} | {:error, atom()}
  def export(key, session) do
    cond do
      session.expires_at <= System.monotonic_time(:millisecond) ->
        {:error, :no_session}

      session.data != nil and
          match?({:ok, _}, SessionCache.lookup(key, {session.id, session.data})) ->
        {:ok, session.data, session}

      true ->
        session = %{session | data: <<"EXSSL12", 1, :crypto.strong_rand_bytes(32)::binary>>}

        case SessionCache.put(key, session) do
          :ok -> {:ok, session.data, session}
          {:error, _} -> {:error, :session_cache_unavailable}
        end
    end
  end
end
