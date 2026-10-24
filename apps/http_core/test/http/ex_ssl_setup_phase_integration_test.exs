defmodule HTTP.ExSSLSetupPhaseIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias HTTP.{ClientCompletion, RequestLifecycle}
  alias HTTP.Transport.ExSSL

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)
  @peer Path.expand("../../../http_fetch/test/support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

  defp ssl_options(version, rejection) do
    [
      verify: :verify_peer,
      versions: [version],
      cacertfile:
        Path.join(
          @fixtures,
          if(rejection == :wrong_ca, do: "pinned-ca.pem", else: "localhost-ca.pem")
        ),
      server_name_indication:
        if(rejection == :wrong_ca, do: ~c"localhost", else: ~c"wrong.invalid")
    ]
  end

  defp wire(:"tlsv1.2"), do: "TLSv1.2"
  defp wire(:"tlsv1.3"), do: "TLSv1.3"
  defp alert(:"tlsv1.2", _), do: :bad_certificate
  defp alert(:"tlsv1.3", :wrong_ca), do: :unknown_ca
  defp alert(:"tlsv1.3", :wrong_identity), do: :certificate_unknown

  for version <- [:"tlsv1.2", :"tlsv1.3"], rejection <- [:wrong_ca, :wrong_identity] do
    test "#{version} #{rejection} correlates public phase with the exact token before provider folding" do
      version = unquote(version)
      rejection = unquote(rejection)
      {peer, port} = peer(wire(version), "http/1.1", "forward")
      token = make_ref()
      expected = alert(version, rejection)
      parent = self()
      reference = make_ref()

      owner =
        Task.async(fn ->
          completion = ClientCompletion.new()
          :ok = RequestLifecycle.enter(completion.tracker, :owner)
          send(parent, {reference, completion})

          result =
            ExSSL.connect(
              "localhost",
              port,
              [
                request_lifecycle: completion.tracker,
                connect_failure_token: token,
                tls_setup_evidence: true,
                connect_address: {127, 0, 0, 1},
                ssl: ssl_options(version, rejection)
              ],
              2_000
            )

          RequestLifecycle.complete(completion.tracker)
          result
        end)

      assert_receive {^reference, completion}, 1_000

      on_exit(fn ->
        RequestLifecycle.abort(completion.tracker)
        if Process.alive?(owner.pid), do: Task.shutdown(owner, :brutal_kill)
      end)

      assert {:error, {:tls_setup_failure, ^token, {:tls_alert, {^expected, _}}}} =
               Task.await(owner, 3_000)

      assert :ok = ClientCompletion.await(completion, 2_000)
      state = stats(peer, &(&1["closed_connections"] == 1))
      assert state["requests"] == []
      assert state["accepted_connections"] == 1
      assert [%{"kind" => "tls", "reason" => reason}] = state["errors"]
      assert reason =~ expected |> Atom.to_string() |> String.upcase()
      stop_peer(peer)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"], route <- [:without_token, :ineligible, :upgrade] do
    test "#{version} #{route} preserves the raw error despite actual fatal setup" do
      version = unquote(version)
      route = unquote(route)
      {peer, port} = peer(wire(version), "http/1.1", "forward")
      expected = alert(version, :wrong_ca)

      {result, completion} =
        tracked_result(fn tracker ->
          options = [
            request_lifecycle: tracker,
            connect_failure_token: make_ref(),
            tls_setup_evidence: true,
            connect_address: {127, 0, 0, 1},
            ssl: ssl_options(version, :wrong_ca)
          ]

          excluded_connect(route, port, options)
        end)

      assert {:error, {:tls_alert, {^expected, _}}} = result
      assert :ok = ClientCompletion.await(completion, 2_000)
      state = stats(peer, &(&1["closed_connections"] == 1))
      assert state["requests"] == []
      assert state["accepted_connections"] == 1
      stop_peer(peer)
    end
  end

  defp excluded_connect(:without_token, port, options),
    do: ExSSL.connect("localhost", port, Keyword.delete(options, :connect_failure_token), 2_000)

  defp excluded_connect(:ineligible, port, options),
    do: ExSSL.connect("localhost", port, Keyword.put(options, :tls_setup_evidence, false), 2_000)

  defp excluded_connect(:upgrade, port, options) do
    {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    ExSSL.upgrade(tcp, "localhost", options, 2_000)
  end

  defp tracked_result(function) do
    parent = self()
    reference = make_ref()

    owner =
      Task.async(fn ->
        completion = ClientCompletion.new()
        :ok = RequestLifecycle.enter(completion.tracker, :owner)
        send(parent, {reference, completion})
        result = function.(completion.tracker)
        RequestLifecycle.complete(completion.tracker)
        result
      end)

    assert_receive {^reference, completion}, 1_000

    on_exit(fn ->
      RequestLifecycle.abort(completion.tracker)
      if Process.alive?(owner.pid), do: Task.shutdown(owner, :brutal_kill)
    end)

    {Task.await(owner, 3_000), completion}
  end

  defp peer(version, protocol, route) do
    port =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          @peer,
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key"),
          "--tls",
          version,
          "--protocol",
          protocol,
          "--route",
          route
        ]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    assert %{"event" => "ready", "port" => number} = event(port)
    {port, number}
  end

  defp event(peer) do
    receive do
      {^peer, {:data, {:eol, line}}} ->
        if System.get_env("P3_PROXY_PEER_EVIDENCE"), do: IO.puts("P3_PROXY_PEER " <> line)
        JSON.decode!(line)

      {^peer, {:exit_status, code}} ->
        flunk("independent proxy peer exit #{code}")
    after
      5_000 -> flunk("independent proxy peer timeout")
    end
  end

  defp stats(peer, predicate),
    do: stats(peer, predicate, System.monotonic_time(:millisecond) + 2_000)

  defp stats(peer, predicate, deadline) do
    assert Port.command(peer, JSON.encode!(%{command: "stats"}) <> "\n")
    result = event(peer)

    if predicate.(result) do
      result
    else
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        2 -> stats(peer, predicate, deadline)
      end
    end
  end

  defp stop_peer(peer) do
    assert Port.command(peer, JSON.encode!(%{command: "stop"}) <> "\n")
    assert event(peer)["event"] == "stop"
    assert_receive {^peer, {:exit_status, 0}}, 5_000
  end
end

defmodule HTTP.ExSSLPolicySetupPhaseIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :policy_setup
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}
  alias HTTP.{ClientCompletion, RequestLifecycle}
  alias HTTP.Transport.ExSSL

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      io <- [:http, :hash],
      material <- [:revoked, :invalid] do
    test "#{version} public adapter maps builtin #{io} #{material} after ServerHello", %{
      directory: directory
    } do
      version = unquote(version)

      alert =
        unquote(
          if version == :"tlsv1.2" or material == :invalid,
            do: :bad_certificate,
            else: :unknown_ca
        )

      source = policy_source(directory, unquote(io), unquote(material))
      peer = RevocationPeer.start(directory, version)
      parent = self()
      reference = make_ref()
      token = make_ref()
      options = policy_options(directory, version, source, parent, reference)

      owner =
        Task.async(fn ->
          completion = ClientCompletion.new()
          :ok = RequestLifecycle.enter(completion.tracker, :owner)
          send(parent, {reference, completion})

          result =
            ExSSL.connect(
              "r49.example",
              peer.port,
              [
                request_lifecycle: completion.tracker,
                connect_failure_token: token,
                tls_setup_evidence: true,
                connect_address: {127, 0, 0, 1},
                ssl: options
              ],
              5_000
            )

          RequestLifecycle.complete(completion.tracker)
          result
        end)

      assert_receive {^reference, completion}, 1_000

      try do
        assert {:error, {:tls_setup_failure, ^token, {:tls_alert, {^alert, _}}}} =
                 Task.await(owner, 6_000)

        assert_policy_event(reference, unquote(material))
        assert :ok = source.join.()
        assert :ok = ClientCompletion.await(completion, 3_000)
      after
        RequestLifecycle.abort(completion.tracker)
        if Process.alive?(owner.pid), do: Task.shutdown(owner, :brutal_kill)
        source.stop.()
        RevocationPeer.stop(peer)
      end
    end
  end

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  defp policy_source(directory, :hash, :revoked) do
    %{
      options: [
        crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: Path.join(directory, "revoked")]}}
      ],
      roles: 2,
      join: fn -> :ok end,
      stop: fn -> :ok end
    }
  end

  defp policy_source(directory, :hash, :invalid) do
    good = File.read!(Path.join(directory, "leaf-good.crl.pem"))

    filename =
      Path.wildcard(Path.join([directory, "good", "*.r0"]))
      |> Enum.find(&(File.read!(&1) == good))
      |> Path.basename()

    target = Path.join(directory, "setup-invalid-#{System.unique_integer([:positive])}")
    File.mkdir!(target)
    File.write!(Path.join(target, filename), <<48, 1, 0>>)

    %{
      options: [crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: target]}}],
      roles: 2,
      join: fn -> :ok end,
      stop: fn -> File.rm_rf!(target) end
    }
  end

  defp policy_source(directory, :http, material) do
    bytes =
      if material == :revoked,
        do: File.read!(Path.join(directory, "leaf-revoked.crl.der")),
        else: <<48, 1, 0>>

    {:ok, listener} =
      :gen_tcp.listen(18_749, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    server =
      Task.async(fn ->
        try do
          {:ok, socket} = :gen_tcp.accept(listener, 5_000)

          try do
            {:ok, request} = :gen_tcp.recv(socket, 0, 2_000)
            assert hd(String.split(request, "\r\n")) == "GET /leaf.crl HTTP/1.1"

            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(bytes)}\r\n\r\n" <> bytes
              )
          after
            :gen_tcp.close(socket)
          end
        after
          :gen_tcp.close(listener)
        end
      end)

    %{
      options: [crl_cache: {:ssl_crl_cache, {:internal, [http: 2_000]}}],
      roles: 1,
      join: fn -> assert :ok = Task.await(server, 5_000) end,
      stop: fn ->
        if Process.alive?(server.pid), do: Task.shutdown(server, :brutal_kill)
        :gen_tcp.close(listener)
      end
    }
  end

  defp assert_policy_event(reference, :revoked) do
    assert_receive {^reference, {:bad_cert, {:revoked, :keyCompromise}}}, 500
  end

  defp assert_policy_event(reference, :invalid) do
    # Invalid fetched ASN.1 is rejected before a status event can be authorized.
    refute_receive {^reference, {:bad_cert, _}}, 0
  end

  defp policy_options(directory, version, source, owner, reference) do
    verify = fn _, event, state ->
      case event do
        {:bad_cert, reason} ->
          send(owner, {reference, {:bad_cert, reason}})
          {:fail, :policy_rejected}

        {:extension, _} ->
          {:unknown, state}

        _ ->
          {:valid, state}
      end
    end

    RevocationFixtures.options(directory, version) ++
      [crl_check: :peer, verify_fun: {verify, nil}] ++ source.options
  end
end
