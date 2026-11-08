defmodule QUICTLSResumptionReference do
  @fixtures Path.expand("../../apps/ex_ssl/test/fixtures/server_flight", __DIR__)
  def run do
    for role <- [:client, :server], suite <- [0x1301, 0x1302, 0x1303], early <- [false, true] do
      scenario(role, suite, early)
    end
  end

  defp scenario(role, suite, early) do
    python = System.fetch_env!("QUIC_TLS_PYTHON")

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 3_000_000},
        args: [
          Path.join(__DIR__, "peer.py"),
          if(role == :client, do: "server", else: "client"),
          to_string(suite),
          to_string(early)
        ]
      ])

    try do
      {client_session, server_session} = handshake(port, role, suite, early, nil, nil, false)
      [] = request(port, "reset\t\n")
      handshake(port, role, suite, early, client_session, server_session, true)
      IO.puts("PASS TLS provider role=#{role} suite=#{suite} early=#{early} full+resumed")
    after
      if Port.info(port), do: Port.close(port)
    end
  end

  defp handshake(port, role, suite, early, client_session, server_session, resumed) do
    policy = [
      enabled: true,
      context: "independent-policy-v1",
      now: System.monotonic_time(:millisecond),
      early_data: early
    ]

    policy =
      if role == :client and client_session, do: policy ++ [session: client_session], else: policy

    options = [
      alpn: ["test"],
      transport_parameters: "provider-parameters",
      ciphers: [suite],
      resumption: policy
    ]

    options =
      if role == :client do
        options ++
          [
            cacerts: [cert("root")],
            reference_identity: {:dns_id, "example.test"},
            server_name: "example.test"
          ]
      else
        [{type, key, :not_encrypted}] =
          File.read!(Path.join(@fixtures, "leaf-key.pem")) |> :public_key.pem_decode()

        options ++ [cert: [cert("leaf")], key: {type, key}]
      end

    {:ok, state, out} = SSL.QUIC.new(role, options)
    inbound = if role == :server, do: request(port, "start\t\n"), else: []

    {state, local, remote, info} =
      drive(port, state, out, inbound, [], [], nil, server_session, early, 0)

    true = SSL.QUIC.info(state).handshake_complete
    ^resumed = SSL.QUIC.info(state).resumed
    %{done: true, resumed: ^resumed} = info
    if resumed, do: ^early = info.early

    for level <- [:handshake, :application] ++ if(resumed and early, do: [:early_data], else: []),
        direction <-
          if(level == :early_data,
            do: [if(role == :client, do: :write, else: :read)],
            else: [:read, :write]
          ) do
      opposite = if direction == :read, do: :write, else: :read

      [left] =
        for %SSL.QUIC.Secret{level: ^level, direction: ^direction} = secret <- local, do: secret

      [right] = for {:secret, ^level, ^opposite, ^suite, hash} <- remote, do: hash
      ^right = :crypto.hash(:sha256, left.secret) |> Base.encode16(case: :lower)
    end

    client =
      Enum.find_value(local, fn
        {:session_ticket, s} -> s
        _ -> nil
      end)

    server =
      Enum.find_value(local, fn
        {:session_store, %{session: s}} -> s
        _ -> nil
      end)

    if role == :client, do: true = client != nil, else: true = server != nil
    {client, server}
  end

  defp drive(_, _, _, _, _, _, _, _, _, n) when n > 30, do: raise("bounded TLS progress exceeded")

  defp drive(port, state, out, inbound, local, remote, info, cached, early, n) do
    replies =
      Enum.flat_map(out, fn
        {:emit, _, bytes} -> request(port, "feed\t" <> Base.encode16(bytes, case: :lower) <> "\n")
        _ -> []
      end)

    inbound = inbound ++ replies

    info =
      Enum.reduce(inbound, info, fn
        {:info, current}, _ -> current
        _, previous -> previous
      end)

    {state, next} =
      Enum.reduce(inbound, {state, []}, fn
        {:emit, level, bytes}, {state, all} ->
          {:ok, state, actions} = SSL.QUIC.feed(state, level, bytes)
          {state, extra} = resolve(state, actions, cached, early)
          {state, all ++ actions ++ extra}

        _, acc ->
          acc
      end)

    local = local ++ out
    remote = remote ++ inbound

    if next == [],
      do: {state, local, remote, info},
      else: drive(port, state, next, [], local, remote, info, cached, early, n + 1)
  end

  defp resolve(state, actions, cached, early) do
    Enum.reduce(actions, {state, []}, fn
      {kind, %SSL.QUIC.Request{} = req}, {state, all}
      when kind in [:session_lookup, :session_commit, :session_store] ->
        result =
          case kind do
            :session_lookup ->
              if cached,
                do: {:ok, cached, :independent_lease, System.monotonic_time(:millisecond)},
                else: :miss

            :session_commit ->
              {:ok, if(early and req.early_data, do: :early_data, else: :resumed)}

            :session_store ->
              :ok
          end

        {:ok, state, more} = SSL.QUIC.continue(state, req.id, result)
        {state, extra} = resolve(state, more, cached, early)
        {state, all ++ more ++ extra}

      _, acc ->
        acc
    end)
  end

  defp request(port, command) do
    true = Port.command(port, command)
    receive_lines(port, [])
  end

  defp receive_lines(port, acc) do
    receive do
      {^port, {:data, {:eol, "end"}}} -> Enum.reverse(acc)
      {^port, {:data, {:eol, line}}} -> receive_lines(port, [parse(line) | acc])
      {^port, {:exit_status, code}} -> raise("independent peer exited #{code}")
    after
      10_000 -> raise("independent peer timeout")
    end
  end

  defp parse(line) do
    case String.split(line, "\t") do
      ["emit", level, bytes] ->
        {:emit, String.to_existing_atom(level), Base.decode16!(bytes, case: :mixed)}

      ["secret", level, direction, suite, hash] ->
        {:secret, String.to_existing_atom(level), String.to_existing_atom(direction),
         String.to_integer(suite), hash}

      ["info", done, resumed, early] ->
        {:info, %{done: done == "true", resumed: resumed == "true", early: early == "true"}}
    end
  end

  defp cert(name) do
    [{:Certificate, der, :not_encrypted}] =
      File.read!(Path.join(@fixtures, name <> ".pem")) |> :public_key.pem_decode()

    der
  end
end

QUICTLSResumptionReference.run()
