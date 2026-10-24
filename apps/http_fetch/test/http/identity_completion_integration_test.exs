defmodule HTTP.IdentityCompletionIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.IdentityCompletionFixtures, as: F
  alias ExSSL.TestSupport.MultiIdentityFixtures
  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}

  setup_all do
    directory =
      Path.join(
        System.tmp_dir!(),
        "identity-completion-fixtures-fetch-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  for version <- ["tls12", "tls13"],
      protocol <- [:http1, :http2],
      route <- [:direct, :connect],
      selection <- [:single_rsa, :single_ec, :later_rsa_ca, :ec_scheme] do
    test "#{version} #{protocol} #{route} #{selection} authenticated public completion witness",
         %{fixtures: fixtures} do
      {version, protocol, route, selection} =
        unquote(Macro.escape({version, protocol, route, selection}))

      peer = F.start(fixtures, version, protocol, :fetch, F.peer_options(selection))
      {ssl, expected, counts} = F.credentials(fixtures, version, protocol, selection)
      proxy = F.route_proxy(route, peer, counts)

      try do
        promise =
          HTTP.fetch(
            F.url(peer),
            [
              tls_backend: :ex_ssl,
              http_version: protocol,
              redirect: :manual,
              ssl: ssl,
              timeout: 3_000,
              connect_timeout: 3_000
            ] ++
              F.proxy_options(proxy) ++ F.http2_options(protocol, :fetch)
          )

        receipt = Promise.completion(promise)
        assert match?(%RequestCompletion{}, receipt)
        assert %Response{status: 200} = response = Promise.await(promise, 5_000)
        assert Response.read_all(response) == F.body()
        assert :ok = RequestCompletion.await(receipt, 2_000)
        assert :ok = RequestCompletion.await(receipt, 0)
        F.assert_callbacks(counts)
        F.assert_public_redacted({receipt, RequestCompletion.await(receipt, 0)}, fixtures)
      after
        F.stop(peer)
        F.stop_proxy(proxy)
      end

      F.assert_authenticated(fixtures, peer, expected)
      F.record("A01-fetch-#{version}-#{route}-#{protocol}-#{selection}")
    end
  end

  for version <- ["tls12", "tls13"],
      protocol <- [:http1, :http2],
      route <- [:direct, :connect],
      terminal <- [:deadline, :cancel, :owner_loss] do
    @tag :blocked_identity_authentication
    test "#{version} #{protocol} #{route} #{terminal} joins selected large authentication flight",
         %{fixtures: fixtures} do
      exercise_blocked(
        fixtures,
        unquote(version),
        unquote(protocol),
        unquote(route),
        unquote(terminal)
      )
    end
  end

  defp exercise_blocked(fixtures, version, protocol, route, terminal) do
    peer = F.start(fixtures, version, protocol, :fetch, gate: true)
    {ssl, _expected, counts} = F.credentials(fixtures, version, protocol, :large_rsa)
    proxy = F.route_proxy(route, peer, counts)

    promise =
      HTTP.fetch(
        F.url(peer),
        [
          tls_backend: :ex_ssl,
          http_version: protocol,
          redirect: :manual,
          ssl: ssl,
          timeout: 3_000,
          connect_timeout: 3_000
        ] ++
          F.proxy_options(proxy) ++ F.http2_options(protocol, :fetch_blocked)
      )

    receipt = Promise.completion(promise)
    blocked = F.block_authentication(peer, receipt, fixtures)

    outcome =
      try do
        assert {:error, :cleanup_pending} = RequestCompletion.await(receipt, 0)
        expected = terminate(terminal, promise, receipt, blocked.deadline)
        assert ^expected = RequestCompletion.await(receipt, 2_000)
        provider_receipt = F.assert_authentication_cleanup(blocked)
        peer_terminal = F.assert_peer_authentication_closed(peer)
        assert ^expected = RequestCompletion.await(receipt, 0)
        F.assert_callbacks(counts)
        F.assert_public_redacted({receipt, expected, provider_receipt}, fixtures)
        F.concurrent_reads(fn -> RequestCompletion.await(receipt, 100) end, expected)
        {expected, peer_terminal}
      after
        RequestCompletion.abort_and_await(receipt, 500)
        F.resume_authentication(blocked)
        F.stop(peer)
        F.stop_proxy(proxy)
      end

    F.assert_rejected(peer)
    {completion, peer_terminal} = outcome

    F.record_blocked(
      "A03-fetch-#{route}-#{protocol}-#{version}-#{terminal}",
      blocked,
      completion,
      peer_terminal
    )
  end

  defp terminate(:cancel, promise, receipt, _deadline) do
    assert :ok = RequestCompletion.abort_and_await(receipt, 2_000)
    assert {:error, _reason} = Promise.await(promise, 2_000)
    :ok
  end

  defp terminate(:deadline, promise, _receipt, deadline) do
    assert {:error, _reason} = Promise.await(promise, 4_000)
    assert System.monotonic_time(:millisecond) >= deadline
    :ok
  end

  defp terminate(:owner_loss, promise, _receipt, _deadline) do
    monitor = Process.monitor(promise.task.pid)
    Process.exit(promise.task.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, :killed}, 1_000
    {:error, :cleanup_unconfirmed}
  end

  for version <- ["tls12", "tls13"], route <- [:direct, :connect] do
    test "#{version} #{route} first H2 stream cleanup preserves authenticated sibling and reuse",
         %{fixtures: fixtures} do
      exercise_isolation(fixtures, unquote(version), unquote(route))
    end
  end

  test "request receipts redact static encrypted sources after shared requests complete", %{
    fixtures: fixtures
  } do
    exercise_isolation(fixtures, "tls13", :direct, "A02-fetch_receipt_privacy")
  end

  defp exercise_isolation(fixtures, version, route, case_id \\ nil) do
    peer = F.start(fixtures, version, :http2, :fetch)
    {ssl, expected} = F.shared_credentials(fixtures, version)
    proxy = F.route_proxy(route, peer, nil)

    options =
      [
        tls_backend: :ex_ssl,
        http_version: :http2,
        redirect: :manual,
        ssl: ssl,
        timeout: 5_000,
        connect_timeout: 3_000
      ] ++
        F.proxy_options(proxy) ++
        F.http2_options(:http2, :fetch_isolation)

    first =
      HTTP.fetch(F.url(peer, "https", "/hold"), Keyword.put(options, :stream_response, true))

    first_receipt = Promise.completion(first)

    proof =
      try do
        assert %Response{status: 200, stream: first_stream} = Promise.await(first, 3_000)
        assert is_pid(first_stream)

        F.with_shared_owner(Process.whereis(:http_fetch_http2_pool), peer, fn _shared ->
          sibling =
            HTTP.fetch(
              F.url(peer, "https", "/sibling"),
              Keyword.put(options, :stream_response, true)
            )

          sibling_receipt = Promise.completion(sibling)

          assert %Response{status: 200, stream: sibling_stream} =
                   response = Promise.await(sibling, 3_000)

          assert is_pid(sibling_stream)
          assert :ok = RequestCompletion.abort_and_await(first_receipt, 2_000)
          assert :ok = RequestCompletion.await(first_receipt, 0)
          F.concurrent_reads(fn -> RequestCompletion.await(first_receipt, 100) end, :ok)
          assert %{"stream" => 1, "code" => 8} = F.event(peer, :app, "client_reset")
          assert true = F.command(peer, :app, "tick")
          assert Response.read_all(response) == "identity-sibling-ok"
          assert :ok = RequestCompletion.await(sibling_receipt, 2_000)
          later = HTTP.fetch(F.url(peer, "https", "/later"), options)
          later_receipt = Promise.completion(later)
          assert %Response{status: 200} = later_response = Promise.await(later, 3_000)
          assert Response.read_all(later_response) == F.body()
          assert :ok = RequestCompletion.await(later_receipt, 2_000)
          assert :ok = RequestCompletion.await(first_receipt, 0)
          F.assert_public_redacted({first_receipt, sibling_receipt, later_receipt}, fixtures)
        end)
      after
        RequestCompletion.abort_and_await(first_receipt, 500)
        F.stop(peer)
        F.stop_proxy(proxy)
      end

    F.assert_authenticated(fixtures, peer, expected, 3)

    assert [1, 3, 5] ==
             for(row <- F.events(peer, :app), row["event"] == "request", do: row["stream"])

    assert [%{"stream" => 1, "code" => 8}] =
             Enum.filter(F.events(peer, :app), &(&1["event"] == "client_reset"))

    F.record(case_id || "A04-fetch-#{route}-#{version}", proof)
  end

  test "managed policy preserves password callback multiple-identity and encrypted-file exclusions",
       %{fixtures: fixtures} do
    encrypted = fixtures.encrypted["rsa2048-a"]
    base = managed_options(fixtures, "https://r47.server")

    controls = [
      {[password: encrypted.password], :invalid_transport_scope_tls_policy},
      {[password: fn -> flunk("managed password callback was invoked") end],
       :invalid_transport_scope_tls_policy},
      {[
         certs_keys: [
           %{
             certfile: encrypted.certificate,
             keyfile: encrypted.encrypted_key,
             password: encrypted.password
           }
         ]
       ], :invalid_transport_scope_tls_policy},
      {[certfile: encrypted.certificate, keyfile: encrypted.encrypted_key],
       {:invalid_transport_scope_tls_file, :keyfile}}
    ]

    for {identity, reason} <- controls do
      options = Keyword.update!(base, :ssl, &Keyword.merge(&1, identity))
      assert {:error, ^reason} = result = ManagedTransport.open(options)
      F.assert_public_redacted(result, fixtures)
    end

    F.record("A02-managed_credential_exclusions")
  end

  test "allowed managed no-identity snapshot and durable retirement redact private canaries", %{
    fixtures: fixtures
  } do
    peer = F.start(fixtures, "tls13", :http1, :fetch, auth: "none", authority_host: "r47.server")

    assert {:ok, scope} =
             ManagedTransport.open(managed_options(fixtures, "https://#{peer.authority}"))

    monitor = Process.monitor(scope.coordinator)

    try do
      assert {:ok, %{active_requests: 0, connections: 0}} =
               initial = ManagedTransport.snapshot(scope, 500)

      F.assert_public_redacted({scope, initial}, fixtures)

      promise =
        HTTP.fetch(F.url(peer),
          transport_scope: scope,
          tls_backend: :ex_ssl,
          http_version: :http1,
          redirect: :manual,
          decode_body: false,
          stream_response: true,
          timeout: 3_000
        )

      request_receipt = Promise.completion(promise)
      assert %Response{status: 200} = response = Promise.await(promise, 4_000)
      assert Response.read_all(response) == F.body()
      assert :ok = RequestCompletion.await(request_receipt, 2_000)
      assert {:ok, snapshot} = ManagedTransport.snapshot(scope, 500)
      F.assert_public_redacted({request_receipt, snapshot}, fixtures)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
      assert :ok = ManagedTransport.await_retired(receipt, 2_000)
      assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
      assert :ok = ManagedTransport.await_retired(receipt, 0)
      F.concurrent_reads(fn -> ManagedTransport.await_retired(receipt, 100) end, :ok)

      F.assert_public_redacted(
        {scope, receipt, ManagedTransport.await_retired(receipt, 0)},
        fixtures
      )
    after
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      ManagedTransport.await_retired(receipt, 1_000)
      F.stop(peer)
    end

    F.assert_no_identity_authenticated(peer)
    F.record("A02-managed_public_retirement_privacy")
  end

  defp managed_options(fixtures, origin) do
    [
      origin: origin,
      connect_address: {127, 0, 0, 1},
      http_version: :http1,
      tls_backend: :ex_ssl,
      max_requests: 1,
      max_connections: 1,
      ssl: [
        verify: :verify_peer,
        cacerts: [MultiIdentityFixtures.root(fixtures.manifest, "server-root")],
        versions: [:"tlsv1.3"],
        server_name_indication: ~c"r47.server",
        alpn_advertised_protocols: ["http/1.1"]
      ]
    ]
  end
end
