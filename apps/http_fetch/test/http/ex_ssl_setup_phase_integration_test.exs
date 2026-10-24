defmodule HTTP.FetchExSSLSetupPhaseIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias HTTP.{Promise, RequestCompletion, RequestError}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @peer Path.expand("../support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

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

  defp hostname(:wrong_identity), do: "wrong.invalid"
  defp hostname(:wrong_ca), do: "localhost"

  defp wire(:"tlsv1.2"), do: "TLSv1.2"
  defp wire(:"tlsv1.3"), do: "TLSv1.3"
  defp alert(:"tlsv1.2", _), do: :bad_certificate
  defp alert(:"tlsv1.3", :wrong_ca), do: :unknown_ca
  defp alert(:"tlsv1.3", :wrong_identity), do: :certificate_unknown

  for version <- [:"tlsv1.2", :"tlsv1.3"], rejection <- [:wrong_ca, :wrong_identity] do
    test "#{version} #{rejection} reports structured setup phase without submitting the POST" do
      version = unquote(version)
      rejection = unquote(rejection)
      {peer, port} = peer(wire(version), "http/1.1", "forward")
      expected = alert(version, rejection)
      host = hostname(rejection)

      promise =
        HTTP.fetch("https://#{host}:#{port}/never",
          tls_backend: :ex_ssl,
          connect_address: {127, 0, 0, 1},
          http_version: :http1,
          http1_reuse: false,
          redirect: :manual,
          method: :post,
          body: "never-sent",
          error_mode: :structured,
          ssl: ssl_options(version, rejection)
        )

      assert {:error,
              %RequestError{
                phase: :tls_setup,
                request_started: false,
                reason: {:tls_alert, {^expected, _}}
              } = error} = Promise.await(promise)

      assert RequestError.pre_send?(error)
      assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
      state = stats(peer, &(&1["closed_connections"] == 1))
      assert state["requests"] == []
      assert state["accepted_connections"] == 1
      assert [%{"kind" => "tls", "reason" => reason}] = state["errors"]
      assert reason =~ expected |> Atom.to_string() |> String.upcase()
      stop_peer(peer)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      {route, overrides} <- [
        {:pooled, [http1_reuse: true]},
        {:automatic_redirect, [redirect: :follow]},
        {:automatic_version, [http_version: :auto]}
      ] do
    test "#{version} #{route} stays conservative for the same real certificate alert" do
      version = unquote(version)
      {peer, port} = peer(wire(version), "http/1.1", "forward")

      options = [
        tls_backend: :ex_ssl,
        http_version: :http1,
        http1_reuse: false,
        redirect: :manual,
        method: :post,
        body: "never-sent",
        error_mode: :structured,
        ssl: ssl_options(version, :wrong_ca)
      ]

      promise =
        HTTP.fetch("https://127.0.0.1:#{port}/never", Keyword.merge(options, unquote(overrides)))

      expected = alert(version, :wrong_ca)

      assert {:error,
              %RequestError{
                phase: :unknown,
                request_started: :unknown,
                reason: {:tls_alert, {^expected, _}}
              } = error} = Promise.await(promise)

      refute RequestError.pre_send?(error)
      assert_route_completion(unquote(route), Promise.completion(promise))
      state = stats(peer, &(&1["closed_connections"] == 1))
      assert state["requests"] == []
      assert state["accepted_connections"] == 1
      stop_peer(peer)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "verified #{version} POST keeps the existing HTTP result and cleanup" do
      version = unquote(version)
      {peer, port} = peer(wire(version), "http/1.1", "forward")

      promise =
        HTTP.fetch("https://localhost:#{port}/success",
          tls_backend: :ex_ssl,
          connect_address: {127, 0, 0, 1},
          http_version: :http1,
          http1_reuse: false,
          redirect: :manual,
          method: :post,
          body: "sent-once",
          error_mode: :structured,
          ssl: [
            versions: [version],
            alpn_advertised_protocols: ["http/1.1"],
            cacertfile: Path.join(@fixtures, "localhost-ca.pem")
          ]
        )

      assert %HTTP.Response{status: 200} = response = Promise.await(promise)
      assert HTTP.Response.read_all(response) == "sent-once"
      assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
      state = stats(peer, &(&1["closed_connections"] == 1))
      assert [%{"method" => "POST", "target" => "/success", "body" => body}] = state["requests"]
      assert body == Base.encode64("sent-once")
      assert state["accepted_connections"] == 1
      assert state["errors"] == []
      stop_peer(peer)
    end
  end

  for option <- [[handshake: :hello], [early_data: "never"]] do
    test "unsupported #{inspect(option)} never fabricates setup phase" do
      promise =
        HTTP.fetch("https://127.0.0.1:1/never",
          tls_backend: :ex_ssl,
          http_version: :http1,
          redirect: :manual,
          error_mode: :structured,
          ssl: unquote(option)
        )

      assert {:error, %RequestError{phase: :unknown, request_started: :unknown} = error} =
               Promise.await(promise)

      refute RequestError.pre_send?(error)
      assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
    end
  end

  defp assert_route_completion(:automatic_version, completion) do
    assert {:error, {:unsupported_completion, :http_version}} =
             RequestCompletion.await(completion, 2_000)
  end

  defp assert_route_completion(:automatic_redirect, completion) do
    assert {:error, {:unsupported_completion, :redirect}} =
             RequestCompletion.await(completion, 2_000)
  end

  defp assert_route_completion(_route, completion) do
    assert :ok = RequestCompletion.await(completion, 2_000)
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

defmodule HTTP.FetchExSSLPolicySetupPhaseIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :policy_setup
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}
  alias HTTP.{Promise, RequestCompletion, RequestError}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      io <- [:http, :hash],
      material <- [:revoked, :invalid] do
    test "#{version} Fetch maps builtin #{io} #{material} without submitting application data", %{
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
      reference = make_ref()
      options = policy_options(directory, version, source, self(), reference)

      try do
        promise =
          HTTP.fetch("https://r49.example:#{peer.port}/never",
            tls_backend: :ex_ssl,
            connect_address: {127, 0, 0, 1},
            http_version: :http1,
            http1_reuse: false,
            redirect: :manual,
            method: :post,
            body: "never-sent",
            error_mode: :structured,
            ssl: options
          )

        assert {:error,
                %RequestError{
                  phase: :tls_setup,
                  request_started: false,
                  reason: {:tls_alert, {^alert, _}}
                } = error} = Promise.await(promise)

        assert RequestError.pre_send?(error)
        refute inspect(error) =~ directory
        assert_policy_event(reference, unquote(material))
        assert :ok = source.join.()
        assert :ok = RequestCompletion.await(Promise.completion(promise), 3_000)
      after
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
