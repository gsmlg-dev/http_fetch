defmodule HTTP.WebSocket.IdentityCompletionIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.IdentityCompletionFixtures, as: F
  alias HTTP.{ClientCompletion, WebSocket}
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}

  setup_all do
    directory =
      Path.join(
        System.tmp_dir!(),
        "identity-completion-fixtures-wss-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  for version <- ["tls12", "tls13"],
      protocol <- [:http1, :http2],
      selection <- [:later_rsa_ca, :ec_scheme] do
    test "#{version} #{protocol} #{selection} authenticated frame and retained completion", %{
      fixtures: fixtures
    } do
      {version, protocol, selection} = unquote(Macro.escape({version, protocol, selection}))
      peer = F.start(fixtures, version, protocol, :wss, F.peer_options(selection))
      {ssl, expected, counts} = F.credentials(fixtures, version, protocol, selection)

      client =
        WebSocket.new(
          F.url(peer, "wss"),
          [],
          [
            tls_backend: :ex_ssl,
            http_version: protocol,
            ssl: ssl,
            opening_timeout: 3_000,
            close_timeout: 2_000
          ] ++ F.http2_options(protocol, :wss)
        )

      receipt = WebSocket.completion(client)
      assert %ClientCompletion{} = receipt
      monitor = Process.monitor(client.pid)

      try do
        assert_receive {WebSocket, ^client, %Open{}}, 3_000
        assert_receive {WebSocket, ^client, %Message{data: "identity-completion-frame"}}, 3_000
        assert :ok = WebSocket.send(client, "identity-completion-echo")
        assert_receive {WebSocket, ^client, %Message{data: "identity-completion-echo"}}, 3_000
        assert :ok = WebSocket.close(client, 1000)
        assert_receive {WebSocket, ^client, %Close{code: 1000, was_clean: true}}, 3_000
        assert :ok = ClientCompletion.await(receipt, 2_000)
        assert :ok = ClientCompletion.await(receipt, 0)
        assert_receive {:DOWN, ^monitor, :process, _, :normal}, 2_000
        F.assert_callbacks(counts)
        F.assert_public_redacted({receipt, ClientCompletion.await(receipt, 0)}, fixtures)
      after
        if Process.alive?(client.pid), do: WebSocket.close(client)
        F.stop(peer)
      end

      F.assert_authenticated(fixtures, peer, expected)

      assert [%{"masked" => true, "code" => 1000}] =
               Enum.filter(F.events(peer, :app), &(&1["event"] == "client_close"))

      F.record("A01-wss-#{version}-#{protocol}-#{selection}")
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
    peer = F.start(fixtures, version, protocol, :wss, gate: true)
    {ssl, _expected, counts} = F.credentials(fixtures, version, protocol, :large_rsa)

    client =
      WebSocket.new(
        F.url(peer, "wss"),
        [],
        [
          tls_backend: :ex_ssl,
          http_version: protocol,
          ssl: ssl,
          opening_timeout: 3_000,
          close_timeout: 2_000
        ] ++ F.http2_options(protocol, :wss_blocked)
      )

    receipt = WebSocket.completion(client)
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
        refute_receive {WebSocket, ^client, %Open{}}, 0
        F.assert_callbacks(counts)
        F.assert_public_redacted({receipt, expected, provider_receipt}, fixtures)
        F.concurrent_reads(fn -> ClientCompletion.await(receipt, 100) end, expected)
        {expected, peer_terminal}
      after
        if Process.alive?(client.pid), do: WebSocket.close(client)
        F.resume_authentication(blocked)
        F.stop(peer)
      end

    F.assert_rejected(peer)
    {completion, peer_terminal} = outcome

    F.record_blocked(
      "A03-wss-#{protocol}-#{version}-#{terminal}",
      blocked,
      completion,
      peer_terminal
    )
  end

  defp terminate(:cancel, client, _deadline) do
    assert :ok = WebSocket.close(client)
    :ok
  end

  defp terminate(:deadline, client, deadline) do
    assert_receive {WebSocket, ^client, %Error{}}, 4_000
    assert System.monotonic_time(:millisecond) >= deadline
    assert_receive {WebSocket, ^client, %Close{code: 1006}}, 2_000
    :ok
  end

  defp terminate(:owner_loss, client, _deadline) do
    monitor = Process.monitor(client.pid)
    Process.exit(client.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, :killed}, 1_000
    {:error, :cleanup_unconfirmed}
  end

  for version <- ["tls12", "tls13"] do
    test "#{version} first H2 WebSocket cleanup preserves authenticated sibling and reuse", %{
      fixtures: fixtures
    } do
      exercise_isolation(fixtures, unquote(version))
    end
  end

  test "client receipt redacts static encrypted identity sources after shared clients exit", %{
    fixtures: fixtures
  } do
    exercise_isolation(fixtures, "tls13", "A02-wss_receipt_privacy")
  end

  defp exercise_isolation(fixtures, version, case_id \\ nil) do
    peer = F.start(fixtures, version, :http2, :wss)
    {ssl, expected} = F.shared_credentials(fixtures, version)

    options =
      [
        tls_backend: :ex_ssl,
        http_version: :http2,
        ssl: ssl,
        opening_timeout: 3_000,
        close_timeout: 2_000
      ] ++ F.http2_options(:http2, :wss_isolation)

    first = WebSocket.new(F.url(peer, "wss"), [], options)
    first_receipt = WebSocket.completion(first)

    proof =
      try do
        assert_frame(first)

        F.with_shared_owner(Process.whereis(:http_fetch_http2_pool), peer, fn shared ->
          owner = shared.owner
          assert %{stream_handle: %{owner: ^owner, id: 1}} = WebSocket.status(first)
          sibling = WebSocket.new(F.url(peer, "wss", "/sibling"), [], options)
          sibling_receipt = WebSocket.completion(sibling)

          try do
            assert_frame(sibling)
            assert %{stream_handle: %{owner: ^owner, id: 3}} = WebSocket.status(sibling)
            close_cleanly(first)
            assert :ok = ClientCompletion.await(first_receipt, 2_000)

            assert %{"stream" => 1, "code" => 1000, "masked" => true} =
                     F.event(peer, :app, "client_close")

            assert Process.alive?(owner)
            assert true = F.command(peer, :app, "tick")
            assert_receive {WebSocket, ^sibling, %Message{data: "identity-sibling-frame"}}, 2_000
            assert :ok = WebSocket.send(sibling, "identity-sibling-echo")
            assert_receive {WebSocket, ^sibling, %Message{data: "identity-sibling-echo"}}, 2_000
            later = WebSocket.new(F.url(peer, "wss", "/later"), [], options)
            later_receipt = WebSocket.completion(later)

            try do
              assert_frame(later)
              assert %{stream_handle: %{owner: ^owner, id: 5}} = WebSocket.status(later)
              assert :ok = ClientCompletion.await(first_receipt, 0)
              F.concurrent_reads(fn -> ClientCompletion.await(first_receipt, 100) end, :ok)
              F.assert_public_redacted({first_receipt, sibling_receipt, later_receipt}, fixtures)
              close_cleanly(later)
            after
              if Process.alive?(later.pid), do: WebSocket.close(later)
            end

            assert :ok = ClientCompletion.await(later_receipt, 2_000)
            close_cleanly(sibling)
          after
            if Process.alive?(sibling.pid), do: WebSocket.close(sibling)
          end

          assert :ok = ClientCompletion.await(sibling_receipt, 2_000)
        end)
      after
        if Process.alive?(first.pid), do: WebSocket.close(first)
        F.stop(peer)
      end

    F.assert_authenticated(fixtures, peer, expected, 3)

    assert [1, 3, 5] ==
             for(row <- F.events(peer, :app), row["event"] == "request", do: row["stream"])

    assert [1, 5, 3] ==
             for(row <- F.events(peer, :app), row["event"] == "client_close", do: row["stream"])

    F.record(case_id || "A04-wss-direct-#{version}", proof)
  end

  defp assert_frame(client) do
    assert_receive {WebSocket, ^client, %Open{}}, 3_000
    assert_receive {WebSocket, ^client, %Message{data: "identity-completion-frame"}}, 3_000
  end

  defp close_cleanly(client) do
    assert :ok = WebSocket.close(client, 1000)
    assert_receive {WebSocket, ^client, %Close{code: 1000, was_clean: true}}, 2_000
  end
end
