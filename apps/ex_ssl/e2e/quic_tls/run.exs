defmodule QUICTLSReference do
  @fixtures Path.expand("../../test/fixtures/server_flight", __DIR__)

  def run do
    python = System.fetch_env!("QUIC_TLS_PYTHON")

    for role <- [:client, :server],
        suite <- [0x1301, 0x1302, 0x1303],
        identity <- ["leaf", "leaf-rsa"] do
      scenario(python, role, suite, identity, false)
    end

    scenario(python, :client, 0x1301, "leaf", true)
  end

  defp scenario(python, role, suite, identity, request_identity) do
    opposite = if role == :client, do: "server", else: "client"

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 3_000_000},
        args: [
          Path.join(__DIR__, "peer.py"),
          opposite,
          Integer.to_string(suite),
          identity,
          if(request_identity, do: "yes", else: "no")
        ]
      ])

    options = [alpn: ["test"], transport_parameters: "ex_ssl-parameters", ciphers: [suite]]

    options =
      if role == :client,
        do: options ++ [cacerts: [cert("root")], reference_identity: {:dns_id, "example.test"}],
        else: options

    options =
      if role == :server or request_identity,
        do: options ++ identity_options(identity),
        else: options

    {:ok, state, actions} = SSL.QUIC.new(role, options)
    initial = if role == :server, do: request(port, "start\t\n"), else: []
    {state, local, remote, info} = drive(port, state, actions, initial, [], [], nil, 0)
    true = SSL.QUIC.info(state).handshake_complete
    %{done: true, alpn: "test", parameters: "ex_ssl-parameters"} = info
    "test" = SSL.QUIC.info(state).alpn

    for level <- [:handshake, :application], direction <- [:read, :write] do
      opposite = if direction == :read, do: :write, else: :read
      [left] = for %SSL.QUIC.Secret{level: ^level, direction: ^direction} = s <- local, do: s
      [right] = for {:secret, ^level, ^opposite, ^suite, hash} <- remote, do: hash
      ^right = :crypto.hash(:sha256, left.secret) |> Base.encode16(case: :lower)
    end

    true = {:peer_transport_parameters, "reference-parameters", :authenticated} in local
    Port.close(port)

    IO.puts(
      "PASS ex_ssl #{role} suite=#{suite} identity=#{identity} client_identity=#{request_identity}"
    )
  end

  defp drive(_, _, _, _, _, _, _, count) when count > 20,
    do: raise("handshake made no bounded progress")

  defp drive(port, state, out, inbound, local, remote, info, count) do
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
          {state, all ++ actions}

        _, acc ->
          acc
      end)

    local = local ++ out
    remote = remote ++ inbound

    if next == [] do
      {state, local, remote, info}
    else
      drive(port, state, next, [], local, remote, info, count + 1)
    end
  end

  defp request(port, command) do
    true = Port.command(port, command)
    receive_lines(port, [])
  end

  defp receive_lines(port, acc) do
    receive do
      {^port, {:data, {:eol, "end"}}} -> Enum.reverse(acc)
      {^port, {:data, {:eol, line}}} -> receive_lines(port, [parse(line) | acc])
      {^port, {:exit_status, code}} -> raise("reference peer exited: #{code}")
    after
      10_000 -> raise("reference peer timeout")
    end
  end

  defp parse(line) do
    case String.split(line, "\t") do
      ["emit", level, bytes] ->
        {:emit, level(level), Base.decode16!(bytes, case: :mixed)}

      ["secret", level, direction, suite, hash] ->
        {:secret, level(level), direction(direction), String.to_integer(suite), hash}

      ["info", done, alpn, parameters] ->
        {:info,
         %{done: done == "true", alpn: alpn, parameters: Base.decode16!(parameters, case: :mixed)}}
    end
  end

  defp level("initial"), do: :initial
  defp level("handshake"), do: :handshake
  defp level("application"), do: :application
  defp direction("read"), do: :read
  defp direction("write"), do: :write

  defp cert(name) do
    [{:Certificate, der, :not_encrypted}] =
      File.read!(Path.join(@fixtures, name <> ".pem")) |> :public_key.pem_decode()

    der
  end

  defp identity_options(name) do
    [{type, der, :not_encrypted}] =
      File.read!(Path.join(@fixtures, name <> "-key.pem")) |> :public_key.pem_decode()

    [cert: [cert(name)], key: {type, der}]
  end
end

QUICTLSReference.run()
