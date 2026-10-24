defmodule HTTP.EventSource.IdentityCompletionIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.IdentityCompletionFixtures, as: F
  alias HTTP.{ClientCompletion, EventSource}
  alias HTTP.EventSource.Event.{Error, Message, Open}

  setup_all do
    directory =
      Path.join(
        System.tmp_dir!(),
        "identity-completion-fixtures-sse-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  for version <- ["tls12", "tls13"],
      protocol <- [:http1, :http2],
      selection <- [:later_rsa_ca, :ec_scheme] do
    test "#{version} #{protocol} #{selection} authenticated event and retained completion", %{
      fixtures: fixtures
    } do
      {version, protocol, selection} = unquote(Macro.escape({version, protocol, selection}))
      peer = F.start(fixtures, version, protocol, :sse, F.peer_options(selection))
      {ssl, expected, counts} = F.credentials(fixtures, version, protocol, selection)

      client =
        EventSource.new(
          F.url(peer),
          [
            tls_backend: :ex_ssl,
            http_version: protocol,
            ssl: ssl,
            connect_timeout: 3_000,
            reconnect_time: 10_000
          ] ++ F.http2_options(protocol, :sse)
        )

      receipt = EventSource.completion(client)
      assert %ClientCompletion{} = receipt
      monitor = Process.monitor(client.pid)

      try do
        assert_receive {EventSource, ^client, %Open{}}, 3_000

        assert_receive {EventSource, ^client,
                        %Message{
                          data: "identity-completion-event",
                          last_event_id: "identity-completion"
                        }},
                       3_000

        assert :ok = EventSource.close(client)
        assert :ok = ClientCompletion.await(receipt, 2_000)
        assert :ok = ClientCompletion.await(receipt, 0)
        assert_receive {:DOWN, ^monitor, :process, _, :normal}, 2_000
        F.assert_callbacks(counts)
        F.assert_public_redacted({receipt, ClientCompletion.await(receipt, 0)}, fixtures)
      after
        if Process.alive?(client.pid), do: EventSource.close(client)
        F.stop(peer)
      end

      F.assert_authenticated(fixtures, peer, expected)
      F.record("A01-sse-#{version}-#{protocol}-#{selection}")
    end
  end

  for version <- ["tls12", "tls13"],
      protocol <- [:http1, :http2],
      terminal <- [:deadline, :cancel, :owner_loss] do
    @tag :blocked_identity_authentication
    test "#{version} #{protocol} #{terminal} joins selected large authentication flight", %{
      fixtures: fixtures
    } do
      exercise_blocked(fixtures, unquote(version), unquote(protocol), unquote(terminal))
    end
  end

  defp exercise_blocked(fixtures, version, protocol, terminal) do
    peer = F.start(fixtures, version, protocol, :sse, gate: true)
    {ssl, _expected, counts} = F.credentials(fixtures, version, protocol, :large_rsa)

    client =
      EventSource.new(
        F.url(peer),
        [
          tls_backend: :ex_ssl,
          http_version: protocol,
          ssl: ssl,
          connect_timeout: 3_000,
          reconnect_time: 10_000
        ] ++ F.http2_options(protocol, :sse_blocked)
      )

    receipt = EventSource.completion(client)
    opening_deadline = F.client_deadline(client.pid)
    blocked = F.block_authentication(peer, receipt, fixtures)

    outcome =
      try do
        assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
        assert :sys.get_state(client.pid).opening_deadline == opening_deadline
        expected = terminate(terminal, client, opening_deadline)
        assert ^expected = ClientCompletion.await(receipt, 2_000)
        provider_receipt = F.assert_authentication_cleanup(blocked)
        peer_terminal = F.assert_peer_authentication_closed(peer)
        assert ^expected = ClientCompletion.await(receipt, 0)
        refute_receive {EventSource, ^client, %Open{}}, 0
        F.assert_callbacks(counts)
        F.assert_public_redacted({receipt, expected, provider_receipt}, fixtures)
        F.concurrent_reads(fn -> ClientCompletion.await(receipt, 100) end, expected)
        {expected, peer_terminal}
      after
        if Process.alive?(client.pid), do: EventSource.close(client)
        F.resume_authentication(blocked)
        F.stop(peer)
      end

    F.assert_rejected(peer)
    {completion, peer_terminal} = outcome

    F.record_blocked(
      "A03-sse-#{protocol}-#{version}-#{terminal}",
      blocked,
      completion,
      peer_terminal
    )
  end

  defp terminate(:cancel, client, _deadline) do
    assert :ok = EventSource.close(client)
    :ok
  end

  defp terminate(:deadline, client, deadline) do
    assert_receive {EventSource, ^client, %Error{}}, 4_000
    assert System.monotonic_time(:millisecond) >= deadline
    assert :ok = EventSource.close(client)
    :ok
  end

  defp terminate(:owner_loss, client, _deadline) do
    monitor = Process.monitor(client.pid)
    Process.exit(client.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, :killed}, 1_000
    {:error, :cleanup_unconfirmed}
  end

  for version <- ["tls12", "tls13"] do
    test "#{version} first H2 event stream cleanup preserves authenticated sibling and reuse", %{
      fixtures: fixtures
    } do
      exercise_isolation(fixtures, unquote(version))
    end
  end

  test "client receipt redacts static encrypted identity sources after shared clients exit", %{
    fixtures: fixtures
  } do
    exercise_isolation(fixtures, "tls13", "A02-sse_receipt_privacy")
  end

  defp exercise_isolation(fixtures, version, case_id \\ nil) do
    peer = F.start(fixtures, version, :http2, :sse)
    {ssl, expected} = F.shared_credentials(fixtures, version)

    options =
      [
        tls_backend: :ex_ssl,
        http_version: :http2,
        ssl: ssl,
        connect_timeout: 3_000,
        reconnect_time: 10_000
      ] ++ F.http2_options(:http2, :sse_isolation)

    first = EventSource.new(F.url(peer), options)
    first_receipt = EventSource.completion(first)

    proof =
      try do
        assert_event(first)

        F.with_shared_owner(Process.whereis(:http_fetch_http2_pool), peer, fn shared ->
          owner = shared.owner
          assert %{stream_handle: %{owner: ^owner, id: 1}} = EventSource.status(first)
          sibling = EventSource.new(F.url(peer, "https", "/sibling"), options)
          sibling_receipt = EventSource.completion(sibling)

          try do
            assert_event(sibling)
            assert %{stream_handle: %{owner: ^owner, id: 3}} = EventSource.status(sibling)
            assert :ok = EventSource.close(first)
            assert :ok = ClientCompletion.await(first_receipt, 2_000)
            assert %{"stream" => 1, "code" => 8} = F.event(peer, :app, "client_reset")
            assert Process.alive?(owner)
            assert true = F.command(peer, :app, "tick")

            assert_receive {EventSource, ^sibling,
                            %Message{data: "sibling-proof", last_event_id: "sibling"}},
                           2_000

            later = EventSource.new(F.url(peer, "https", "/later"), options)
            later_receipt = EventSource.completion(later)

            try do
              assert_event(later)
              assert %{stream_handle: %{owner: ^owner, id: 5}} = EventSource.status(later)
              assert :ok = ClientCompletion.await(first_receipt, 0)
              F.concurrent_reads(fn -> ClientCompletion.await(first_receipt, 100) end, :ok)
              F.assert_public_redacted({first_receipt, sibling_receipt, later_receipt}, fixtures)
            after
              if Process.alive?(later.pid), do: EventSource.close(later)
            end

            assert :ok = ClientCompletion.await(later_receipt, 2_000)
          after
            if Process.alive?(sibling.pid), do: EventSource.close(sibling)
          end

          assert :ok = ClientCompletion.await(sibling_receipt, 2_000)
        end)
      after
        if Process.alive?(first.pid), do: EventSource.close(first)
        F.stop(peer)
      end

    F.assert_authenticated(fixtures, peer, expected, 3)

    assert [1, 3, 5] ==
             for(row <- F.events(peer, :app), row["event"] == "request", do: row["stream"])

    F.record(case_id || "A04-sse-direct-#{version}", proof)
  end

  defp assert_event(client) do
    assert_receive {EventSource, ^client, %Open{}}, 3_000

    assert_receive {EventSource, ^client,
                    %Message{
                      data: "identity-completion-event",
                      last_event_id: "identity-completion"
                    }},
                   3_000
  end
end
