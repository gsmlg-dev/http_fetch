# Run with: mix run scripts/interop/run.exs client|server [output-directory]
defmodule Quic.Interop.Run do
  alias Quic.{Endpoint, Connection}

  def run(mode, directory) do
    scenario = System.get_env("INTEROP_SCENARIO", "baseline")
    profile_name = System.get_env("INTEROP_PROFILE")

    profile =
      case profile_name do
        nil ->
          nil

        name when name in ["ordered", "compact"] ->
          {:ok, compiled} = Quic.Profile.compile(String.to_existing_atom(name))
          compiled

        other ->
          raise("unsupported profile: #{other}")
      end

    impairments = [
      "drop_initial",
      "drop_handshake",
      "reorder",
      "duplicate",
      "corrupt",
      "drop_handshake_done"
    ]

    negatives = ["wrong_ca", "wrong_hostname", "wrong_alpn"]

    unless scenario in (["baseline", "retry"] ++ impairments ++ negatives),
      do: raise("unsupported scenario")

    File.mkdir_p!(directory)
    fixture = Path.expand("apps/elixir_quic/test/fixtures/tls")

    der = fn name ->
      [{:Certificate, bytes, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      bytes
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    client_tls = [
      cacerts: [der.("root.pem")],
      reference_identity: {:dns_id, "example.test"},
      alpn: [if(profile, do: "ex-quic", else: "ex-quic-test")]
    ]

    client_tls =
      case scenario do
        "wrong_ca" ->
          Keyword.put(client_tls, :cacerts, [der.("../pkix/wrong_root.pem")])

        "wrong_hostname" ->
          Keyword.put(client_tls, :reference_identity, {:dns_id, "wrong.example.test"})

        "wrong_alpn" ->
          Keyword.put(client_tls, :alpn, ["incompatible"])

        _ ->
          client_tls
      end

    server_tls = [cert: [der.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-test"]]

    endpoint =
      if mode == "server" do
        {:ok, endpoint} =
          Endpoint.start_link(role: :server, retry: scenario == "retry", tls: server_tls)

        endpoint
      end

    port = if endpoint, do: elem(Endpoint.local(endpoint), 1), else: 0
    peer_mode = if mode == "client", do: "server", else: "client"

    args = [
      "run",
      "--python",
      "3.12",
      "--with",
      "aioquic==1.2.0",
      "python",
      "scripts/interop/peer.py",
      "--mode",
      peer_mode,
      "--port",
      Integer.to_string(port),
      "--cert",
      Path.join(fixture, "leaf.pem"),
      "--key",
      Path.join(fixture, "leaf-key.pem"),
      "--ca",
      Path.join(
        fixture,
        if(mode == "server" and scenario == "wrong_ca",
          do: "../pkix/wrong_root.pem",
          else: "root.pem"
        )
      ),
      "--capture",
      Path.join(directory, "udp.jsonl")
    ]

    args = if scenario == "retry" and mode == "client", do: args ++ ["--retry"], else: args

    args = if scenario in impairments, do: args ++ ["--scenario", scenario], else: args

    args =
      if mode == "server" and scenario == "wrong_hostname",
        do: args ++ ["--hostname", "wrong.example.test"],
        else: args

    args =
      if mode == "server" and scenario == "wrong_alpn",
        do: args ++ ["--alpn", "incompatible"],
        else: args

    args = if profile, do: args ++ ["--alpn", "ex-quic"], else: args

    peer =
      Port.open(
        {:spawn_executable, System.find_executable("uv")},
        [:binary, :exit_status, :use_stdio, :stderr_to_stdout, {:line, 65_536}, {:args, args}]
      )

    deadline = System.monotonic_time(:millisecond) + 12_000

    {endpoint, messages} =
      if endpoint,
        do: {endpoint, []},
        else: start_client(peer, client_tls, profile, deadline, [])

    result = await(peer, endpoint, mode, deadline, messages, false, scenario in negatives)
    observed_retry = Enum.any?(result.events, &match?(%{"event" => "retry"}, &1))

    observed_impairment =
      Enum.any?(result.events, &match?(%{"event" => "impairment", "action" => ^scenario}, &1))

    result =
      Map.merge(result, %{
        scenario: scenario,
        passed:
          if(scenario in negatives,
            do: negative_passed?(result, mode, scenario),
            else:
              result.passed and (scenario != "retry" or observed_retry) and
                (scenario not in impairments or observed_impairment)
          )
      })

    File.write!(Path.join(directory, "result.json"), JSON.encode!(result))
    IO.puts(JSON.encode!(result))
    if Port.info(peer), do: Port.command(peer, "stop\n")
    GenServer.stop(endpoint)
    if result.passed, do: :ok, else: System.halt(1)
  end

  defp start_client(peer, tls, profile, deadline, messages) do
    if System.monotonic_time(:millisecond) >= deadline, do: raise("peer startup timed out")

    receive do
      {^peer, {:data, {:eol, line}}} ->
        case JSON.decode(line) do
          {:ok, %{"event" => "listening", "port" => port} = message} ->
            opts = [role: :client, remote: {{127, 0, 0, 1}, port}, tls: tls]
            opts = if profile, do: Keyword.put(opts, :profile, profile), else: opts
            {:ok, endpoint} = Endpoint.start_link(opts)

            {endpoint, messages ++ [message]}

          {:ok, message} ->
            start_client(peer, tls, profile, deadline, messages ++ [message])

          _ ->
            start_client(peer, tls, profile, deadline, messages ++ [line])
        end

      {^peer, {:exit_status, code}} ->
        raise("peer exited: #{code}")
    after
      100 -> start_client(peer, tls, profile, deadline, messages)
    end
  end

  defp await(peer, endpoint, mode, deadline, messages, peer_complete, negative) do
    error = Endpoint.stats(endpoint).last_error
    local_error = %{"local_error" => inspect(error)}

    messages =
      if error != nil and local_error not in messages,
        do: messages ++ [local_error],
        else: messages

    states = Enum.flat_map(Endpoint.connections(endpoint), &connection_status/1)

    local_complete =
      Enum.any?(
        states,
        &(&1.phase == :established and &1.quic_confirmed and
            &1.retired_levels == [:initial, :handshake])
      )

    peer_confirmed = Enum.any?(messages, &match?(%{"event" => "quic_confirmed"}, &1))
    peer_failed = Enum.any?(messages, &match?(%{"event" => "terminated"}, &1))

    if (local_complete and peer_complete and peer_confirmed) or
         (negative and (match?({:tls, _, _, _}, error) or peer_failed)) or
         System.monotonic_time(:millisecond) >= deadline do
      %{
        passed: local_complete and peer_complete and peer_confirmed,
        peer_confirmed: peer_confirmed,
        peer_complete: peer_complete,
        failure:
          case error do
            {:tls, kind, alert, reason} -> %{kind: kind, alert: alert, reason: inspect(reason)}
            _ -> nil
          end,
        role: mode,
        peer: "aioquic 1.2.0",
        runtime: %{elixir: System.version(), otp: to_string(:erlang.system_info(:otp_release))},
        endpoint: sanitize(Endpoint.stats(endpoint)),
        connections: Enum.map(states, &sanitize/1),
        events: messages
      }
    else
      receive do
        {^peer, {:data, {:eol, line}}} ->
          message =
            case JSON.decode(line) do
              {:ok, message} -> message
              _ -> line
            end

          complete = peer_complete or match?(%{"event" => "handshake_complete"}, message)
          await(peer, endpoint, mode, deadline, messages ++ [message], complete, negative)

        {^peer, {:exit_status, code}} ->
          await(
            peer,
            endpoint,
            mode,
            0,
            messages ++ [%{exit_status: code}],
            peer_complete,
            negative
          )
      after
        20 -> await(peer, endpoint, mode, deadline, messages, peer_complete, negative)
      end
    end
  end

  # The connection can finish between listing routes and querying its status.
  # Only a disappeared process is skipped; unexpected status failures remain fatal.
  defp connection_status(entry) do
    [Connection.status(entry.pid)]
  catch
    :exit, {:noproc, _} -> []
    :exit, {:normal, _} -> []
  end

  defp negative_passed?(result, mode, scenario) do
    no_ready =
      not result.peer_complete and Enum.all?(result.connections, &(&1.phase != :established))

    expected =
      case {mode, scenario} do
        {"client", "wrong_ca"} ->
          match?(%{kind: :tls, alert: :unknown_ca}, result.failure)

        {"client", "wrong_hostname"} ->
          match?(
            %{kind: :tls, alert: :certificate_unknown, reason: ":hostname_mismatch"},
            result.failure
          )

        {"server", "wrong_alpn"} ->
          match?(%{kind: :tls, alert: :no_application_protocol}, result.failure)

        {"client", "wrong_alpn"} ->
          peer_alert?(result.events, 0x128, "No common ALPN protocols")

        {"server", "wrong_hostname"} ->
          peer_alert?(result.events, 0x12A, "doesn't match")

        {"server", "wrong_ca"} ->
          peer_alert?(result.events, 0x12A, "issuer") or
            peer_alert?(result.events, 0x12A, "self-signed")
      end

    no_ready and expected
  end

  defp peer_alert?(events, code, reason) do
    Enum.any?(events, fn
      %{"event" => "terminated", "error_code" => ^code, "reason" => text} ->
        String.contains?(text, reason)

      _ ->
        false
    end)
  end

  defp sanitize(map),
    do:
      Map.new(map, fn
        {:generation, _} -> {:generation, "redacted"}
        {key, value} when is_tuple(value) -> {key, inspect(value)}
        entry -> entry
      end)
end

case System.argv() do
  [mode | rest] when mode in ["client", "server"] ->
    Quic.Interop.Run.run(mode, List.first(rest) || "_build/interop/#{mode}")

  _ ->
    raise("usage: mix run scripts/interop/run.exs client|server [output-directory]")
end
