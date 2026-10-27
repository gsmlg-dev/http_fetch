defmodule SSL.IdentityCompletionIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.IdentityCompletionFixtures, as: F
  alias ExSSL.TestSupport.MultiIdentityFixtures
  alias SSL.Lifecycle

  setup_all do
    directory =
      Path.join(
        System.tmp_dir!(),
        "identity-completion-fixtures-provider-terminal-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  for version <- ["tls12", "tls13"] do
    test "#{version} frozen encrypted multi-identity snapshot attaches twice with fresh randomness" do
      version = unquote(version)

      directory =
        Path.join(
          System.tmp_dir!(),
          "identity-completion-fixtures-provider-#{System.unique_integer([:positive])}"
        )

      on_exit(fn -> File.rm_rf!(directory) end)
      fixtures = F.create(directory)
      {options, _expected, counts} = F.credentials(fixtures, version, :http1, :ec_scheme)
      assert {:ok, prepared} = SSL.prepare_upgrade(options)
      F.assert_callbacks(counts)
      F.assert_credential_snapshot_redacted(prepared, fixtures)

      # Mutate only this test's ephemeral sources after the snapshot is frozen.
      for entry <- options[:certs_keys] do
        File.write!(entry.certfile, "identity-completion-replaced-certificate")
        File.write!(entry.keyfile, "identity-completion-replaced-private-source")
      end

      randoms =
        for {selection, expected} <- [
              {:single_rsa, "rsa2048-a"},
              {:ec_scheme, "p256-a"}
            ] do
          peer = F.start(fixtures, version, :http1, :fetch, F.peer_options(selection))
          expiry = System.monotonic_time(:millisecond) + 3_000

          assert {:ok, handle, lease} =
                   Lifecycle.new(controller: self(), deadline: {:abs_ms, expiry})

          F.assert_public_redacted({handle, lease}, fixtures)

          try do
            assert {:ok, tcp} =
                     :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 1_000)

            assert {:ok, socket} =
                     SSL.connect_prepared(
                       tcp,
                       prepared,
                       [ex_ssl: [lifecycle: {handle, lease}]],
                       3_000
                     )

            try do
              assert {:ok, "http/1.1"} = SSL.negotiated_protocol(socket)

              request =
                "GET /identity-completion HTTP/1.1\r\nHost: #{peer.authority}\r\nConnection: close\r\n\r\n"

              assert :ok = SSL.send(socket, request)

              expected_response =
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: #{byte_size(F.body())}\r\n\r\n#{F.body()}"

              assert response(socket, <<>>, expected_response) == expected_response
            after
              SSL.close(socket)
            end

            assert {:ok, %{cleanup: :confirmed} = receipt} =
                     Lifecycle.await(handle, {:abs_ms, expiry})

            assert {:ok, ^receipt} =
                     Lifecycle.await(handle, {:abs_ms, System.monotonic_time(:millisecond)})

            F.assert_public_redacted({handle, lease, receipt, Lifecycle.status(handle)}, fixtures)
            F.assert_callbacks(counts)
          after
            Lifecycle.cancel(lease, {:abs_ms, System.monotonic_time(:millisecond) + 500})
            F.stop(peer)
          end

          F.assert_authenticated(fixtures, peer, expected)
          [random] = Enum.filter(F.events(peer, :tls), &(&1["event"] == "client_hello_random"))
          random["sha256"]
        end

      assert [first, second] = randoms
      refute first == second
      for index <- 1..2, do: F.record("A01-provider-#{version}-prepared-#{index}")
    end
  end

  for version <- ["tls12", "tls13"],
      route <- [:host, :prepared],
      terminal <- [:deadline, :cancel, :owner_loss] do
    @tag :blocked_identity_authentication
    test "#{version} #{route} #{terminal} joins blocked selected large authentication flight", %{
      fixtures: fixtures
    } do
      {version, route, terminal} = unquote(Macro.escape({version, route, terminal}))
      {options, _expected, counts} = F.credentials(fixtures, version, :http1, :large_rsa)
      prepared = prepare(route, options)
      peer = F.start(fixtures, version, :http1, :fetch, gate: true)
      expiry = System.monotonic_time(:millisecond) + 3_000
      assert {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: {:abs_ms, expiry})
      F.assert_public_redacted({handle, lease}, fixtures)
      caller = Task.async(fn -> connect(route, peer, options, prepared, handle, lease) end)
      blocked = F.block_authentication(peer, handle, fixtures)

      outcome =
        try do
          assert {:pending, _} =
                   Lifecycle.await(handle, {:abs_ms, System.monotonic_time(:millisecond)})

          assert Task.yield(caller, 0) == nil
          terminate(terminal, caller, lease)
          receipt = F.assert_authentication_cleanup(blocked)
          peer_terminal = F.assert_peer_authentication_closed(peer)
          F.assert_callbacks(counts)
          F.assert_public_redacted({handle, lease, receipt, Lifecycle.status(handle)}, fixtures)
          {receipt, peer_terminal}
        after
          Lifecycle.cancel(lease, {:abs_ms, System.monotonic_time(:millisecond) + 500})
          F.resume_authentication(blocked)
          if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
          F.stop(peer)
        end

      F.assert_rejected(peer)
      {receipt, peer_terminal} = outcome
      F.concurrent_reads(fn -> Lifecycle.await(handle, deadline(100)) end, {:ok, receipt})

      F.record_blocked(
        "A03-provider-#{route}-#{version}-#{terminal}",
        blocked,
        :ok,
        peer_terminal
      )
    end
  end

  defp prepare(:host, _options), do: nil

  defp prepare(:prepared, options) do
    assert {:ok, prepared} = SSL.prepare_upgrade(options)
    prepared
  end

  defp connect(:host, peer, options, _prepared, handle, lease),
    do:
      SSL.connect(
        {127, 0, 0, 1},
        peer.port,
        options ++ [ex_ssl: [lifecycle: {handle, lease}]],
        3_000
      )

  defp connect(:prepared, peer, _options, prepared, handle, lease) do
    assert {:ok, tcp} =
             :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 1_000)

    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 3_000)
  end

  defp terminate(:deadline, caller, _lease) do
    assert {:error, reason} = Task.await(caller, 4_000)
    assert reason in [:timeout, :closed]
  end

  defp terminate(:cancel, caller, lease) do
    assert :ok = Lifecycle.cancel(lease, {:abs_ms, System.monotonic_time(:millisecond) + 1_000})
    assert {:error, :closed} = Task.await(caller, 2_000)
  end

  defp terminate(:owner_loss, caller, _lease),
    do: assert(Task.shutdown(caller, :brutal_kill) == nil)

  defp response(_socket, expected, expected), do: expected

  defp response(socket, bytes, expected) do
    assert byte_size(bytes) < byte_size(expected)
    assert {:ok, part} = SSL.recv(socket, 0, 2_000)
    response(socket, bytes <> part, expected)
  end

  test "public provider handle and lease redact live encrypted multi-identity credentials", %{
    fixtures: fixtures
  } do
    log =
      ExUnit.CaptureLog.capture_log(fn ->
        with_live_identity(fixtures, fn handle, lease, socket ->
          assert {:ok, information} = SSL.connection_information(socket)

          F.assert_public_redacted(
            {handle, lease, socket, information, Lifecycle.status(handle)},
            fixtures
          )

          assert :ok = SSL.close(socket)

          assert {:ok, %{cleanup: :confirmed} = receipt} =
                   Lifecycle.await(handle, deadline(2_000))

          F.assert_public_redacted({receipt, Lifecycle.status(handle)}, fixtures)
        end)
      end)

    F.assert_public_redacted(log, fixtures)

    F.record("A02-provider_public_privacy")
  end

  test "public transfer ticket and accepted lease redact live identity credentials", %{
    fixtures: fixtures
  } do
    with_live_identity(fixtures, fn handle, lease, _socket ->
      parent = self()
      {recipient, monitor} = spawn_monitor(fn -> transfer_recipient(parent) end)

      try do
        assert {:ok, ticket} =
                 Lifecycle.offer(
                   lease,
                   %{controller: recipient, owner: recipient},
                   deadline(2_000)
                 )

        F.assert_public_redacted({handle, lease, ticket, Lifecycle.status(handle)}, fixtures)
        send(recipient, {:accept, ticket})
        assert_receive {:accepted, ^recipient, {:ok, replacement}}, 2_000
        F.assert_public_redacted({ticket, replacement, Lifecycle.status(handle)}, fixtures)
        assert {:error, :stale_lease} = Lifecycle.cancel(lease, deadline(500))
        send(recipient, :cancel)

        assert_receive {:cancelled, ^recipient, :ok, {:ok, %{cleanup: :confirmed} = receipt}},
                       2_000

        assert_receive {:DOWN, ^monitor, :process, ^recipient, :normal}, 1_000
        assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))
        F.assert_public_redacted(receipt, fixtures)
      after
        send(recipient, :cancel)
      end
    end)

    F.record("A02-provider_transfer_ticket_privacy")
  end

  test "lost public provider evidence stays unconfirmed after live identity connection exits", %{
    fixtures: fixtures
  } do
    with_live_identity(fixtures, fn handle, lease, socket ->
      observer = handle.receipt.observer
      observer_monitor = Process.monitor(observer)
      connection_monitor = Process.monitor(socket.pid)
      Process.exit(observer, :kill)
      assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :killed}, 2_000
      assert_receive {:DOWN, ^connection_monitor, :process, _, _}, 2_000
      assert {:unconfirmed, :observer_unsealed} = result = Lifecycle.await(handle, deadline(500))
      assert {:unconfirmed, :observer_unsealed} = Lifecycle.status(handle)
      assert ^result = Lifecycle.await(handle, deadline(0))
      F.assert_public_redacted({handle, lease, result}, fixtures)
    end)

    F.record("A02-provider_lost_evidence")
  end

  test "public prepared snapshot omits encrypted source paths passwords and callbacks", %{
    fixtures: fixtures
  } do
    {options, _expected, counts} = F.credentials(fixtures, "tls13", :http1, :later_rsa_ca)
    assert {:ok, prepared} = SSL.prepare_upgrade(options)
    assert inspect(prepared) == "#SSL.PreparedUpgrade<...>"
    F.assert_callbacks(counts)
    F.assert_credential_snapshot_redacted(prepared, fixtures)
    F.record("A02-prepared_snapshot_privacy")
  end

  for {control, alert} <- [
        {:wrong_server_ca, :unknown_ca},
        {:wrong_server_name, :certificate_unknown}
      ] do
    test "#{control} rejects authenticated server without application or identity retry", %{
      fixtures: fixtures
    } do
      negative_server(fixtures, unquote(control), unquote(alert))
    end
  end

  test "required client authentication rejects an ineligible encrypted identity without retry", %{
    fixtures: fixtures
  } do
    peer = F.start(fixtures, "tls13", :http1, :fetch, hint: "client-c", rejection_gate: true)
    {options, _expected, counts} = F.credentials(fixtures, "tls13", :http1, :no_eligible)
    assert {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))

    try do
      result =
        SSL.connect(
          {127, 0, 0, 1},
          peer.port,
          options ++ [ex_ssl: [lifecycle: {handle, lease}]],
          3_000
        )

      rejection =
        case result do
          {:ok, socket} ->
            try do
              F.event(peer, :tls, "rejection_gate")
              reader = Task.async(fn -> SSL.recv(socket, 0, 2_000) end)
              F.await_pending_read(socket)
              assert true = F.command(peer, :tls, "reject")
              Task.await(reader, 3_000)
            after
              SSL.close(socket)
            end

          {:error, _} = error ->
            error
        end

      assert {:error, {:tls_alert, {:certificate_required, _}}} = rejection
      assert {:ok, %{cleanup: :confirmed} = receipt} = Lifecycle.await(handle, deadline(2_000))
      F.assert_callbacks(counts)

      F.assert_public_redacted(
        {handle, lease, rejection, receipt, Lifecycle.status(handle)},
        fixtures
      )
    after
      Lifecycle.cancel(lease, deadline(500))
      F.stop(peer)
    end

    F.assert_rejected(peer)

    assert [%{"sha256" => []}] =
             Enum.filter(F.events(peer, :tls), &(&1["event"] == "wire_client_chain"))

    assert [%{"sent" => true, "level" => 2, "description" => 116}] =
             Enum.filter(F.events(peer, :tls), &(&1["event"] == "tls_alert"))

    F.record("A02-required_no_eligible_identity")
  end

  test "automatic tickets reject nonempty encrypted identity sets", %{fixtures: fixtures} do
    {options, _expected, counts} = F.credentials(fixtures, "tls13", :http1, :later_rsa_ca)

    assert {:error, {:options, {:session_tickets, :client_identity_unsupported}}} =
             result =
             SSL.prepare_upgrade(Keyword.put(options, :session_tickets, :auto))

    F.assert_callbacks(counts)
    F.assert_public_redacted(result, fixtures)
    F.record("A02-auto_ticket_nonempty_rejection")
  end

  test "explicit empty identity set allows tickets without invoking legacy password", %{
    fixtures: fixtures
  } do
    encrypted = fixtures.encrypted["rsa2048-a"]

    options = [
      verify: :verify_peer,
      cacerts: [MultiIdentityFixtures.root(fixtures.manifest, "server-root")],
      server_name_indication: ~c"r47.server",
      certs_keys: [],
      session_tickets: :auto,
      certfile: encrypted.certificate,
      keyfile: encrypted.encrypted_key,
      password: fn -> flunk("empty modern override invoked ignored password") end
    ]

    assert {:ok, prepared} = SSL.prepare_upgrade(options)
    F.assert_credential_snapshot_redacted(prepared, fixtures)

    assert {:error, {:options, {:session_tickets, :verify_peer_required}}} =
             result = SSL.prepare_upgrade(Keyword.put(options, :verify, :verify_none))

    F.assert_public_redacted(result, fixtures)
    F.record("A02-auto_ticket_empty_identity_control")
  end

  test "per-map encrypted identity never inherits the top-level password", %{fixtures: fixtures} do
    {options, _expected, {counts, _count}} =
      F.credentials(fixtures, "tls13", :http1, :later_rsa_ca)

    [first, second] = options[:certs_keys]
    options = Keyword.put(options, :certs_keys, [Map.delete(first, :password), second])
    assert {:error, {:options, _}} = result = SSL.prepare_upgrade(options)
    assert :atomics.get(counts, 1) == 0
    assert :atomics.get(counts, 3) == 0
    F.assert_public_redacted(result, fixtures)
    F.record("A02-per_map_no_password_inheritance")
  end

  defp negative_server(fixtures, control, alert) do
    peer = F.start(fixtures, "tls13", :http1, :fetch)
    {options, _expected, counts} = F.credentials(fixtures, "tls13", :http1, :single_rsa)

    options =
      case control do
        :wrong_server_ca ->
          Keyword.put(options, :cacerts, [
            MultiIdentityFixtures.root(fixtures.manifest, "client-c")
          ])

        :wrong_server_name ->
          Keyword.put(options, :server_name_indication, ~c"wrong.invalid")
      end

    assert {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))

    try do
      assert {:error, {:tls_alert, {^alert, _}}} =
               result =
               SSL.connect(
                 {127, 0, 0, 1},
                 peer.port,
                 options ++ [ex_ssl: [lifecycle: {handle, lease}]],
                 3_000
               )

      assert {:ok, %{cleanup: :confirmed} = receipt} = Lifecycle.await(handle, deadline(2_000))
      F.assert_callbacks(counts)

      F.assert_public_redacted(
        {result, handle, lease, receipt, Lifecycle.status(handle)},
        fixtures
      )
    after
      Lifecycle.cancel(lease, deadline(500))
      F.stop(peer)
    end

    F.assert_rejected(peer)
    F.record("A02-#{control}")
  end

  defp with_live_identity(fixtures, function) do
    peer = F.start(fixtures, "tls13", :http1, :sse)
    {options, expected, counts} = F.credentials(fixtures, "tls13", :http1, :later_rsa_ca)
    assert {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      assert {:ok, socket} =
               SSL.connect(
                 {127, 0, 0, 1},
                 peer.port,
                 options ++ [ex_ssl: [lifecycle: {handle, lease}]],
                 3_000
               )

      try do
        assert :ok =
                 SSL.send(
                   socket,
                   "GET /identity-completion HTTP/1.1\r\nHost: #{peer.authority}\r\nAccept: text/event-stream\r\n\r\n"
                 )

        bytes =
          "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: identity-completion\ndata: identity-completion-event\n\n"

        assert response(socket, <<>>, bytes) == bytes
        function.(handle, lease, socket)
        F.assert_callbacks(counts)
      after
        SSL.close(socket)
      end
    after
      Lifecycle.cancel(lease, deadline(500))
      F.stop(peer)
    end

    F.assert_authenticated(fixtures, peer, expected)
  end

  defp transfer_recipient(parent) do
    receive do
      {:accept, ticket} ->
        result = Lifecycle.accept(ticket, deadline(1_000))
        send(parent, {:accepted, self(), result})
        {:ok, replacement} = result

        receive do
          :cancel ->
            cancelled = Lifecycle.cancel(replacement, deadline(1_000))
            receipt = Lifecycle.await(replacement.handle, deadline(1_000))
            send(parent, {:cancelled, self(), cancelled, receipt})
        after
          3_000 -> Lifecycle.cancel(replacement, deadline(500))
        end
    after
      3_000 -> :ok
    end
  end

  defp deadline(timeout), do: {:abs_ms, System.monotonic_time(:millisecond) + timeout}
end
