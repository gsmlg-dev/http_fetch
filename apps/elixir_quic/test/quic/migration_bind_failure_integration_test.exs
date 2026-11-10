defmodule Quic.MigrationBindFailureIntegrationTest do
  # A candidate socket that cannot bind is a migration outcome, not a fault:
  # the endpoint, its linked caller and the old path all survive.
  use ExUnit.Case, async: true
  @moduletag :integration
  alias Quic.Endpoint

  defp credentials do
    fixture = Path.expand("../fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-bind"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-bind"]
     ]}
  end

  for scoped <- [true, false] do
    test "bind failure keeps the endpoint, caller and old path with cleanup scope=#{scoped}" do
      {server_tls, client_tls} = credentials()
      {:ok, holder} = :gen_udp.open(0, ip: {127, 0, 0, 1})
      {:ok, held} = :inet.port(holder)
      on_exit(fn -> :gen_udp.close(holder) end)
      {:ok, server} = Quic.listen(tls: server_tls)

      {cleanup, client_opts} =
        if unquote(scoped) do
          {:ok, cleanup, lease} = Quic.Cleanup.new()
          {cleanup, [cleanup: lease]}
        else
          {nil, []}
        end

      parent = self()

      # The client runs in a separate linked caller so an exit would be visible.
      {caller, caller_down} =
        spawn_monitor(fn ->
          {:ok, client} = Quic.client([tls: client_tls] ++ client_opts)
          send(parent, {:client, client})

          receive do
            :stop -> :ok
          end
        end)

      assert_receive {:client, client}, 2_000

      on_exit(fn ->
        send(caller, :stop)

        if Process.alive?(server) do
          try do
            GenServer.stop(server)
          catch
            :exit, _ -> :ok
          end
        end
      end)

      {:ok, connection} = Quic.connect(client, Endpoint.local(server))
      :ok = Quic.attach(connection, self())
      assert_receive {:quic_ready, ^connection, _}, 2_000
      assert_receive {:quic_accept, ^server}, 2_000
      {:ok, accepted} = Quic.accept(server)
      :ok = Quic.attach(accepted, self())
      {:ok, before} = Quic.info(connection)

      for {local, reason} <- [
            {{{127, 0, 0, 1}, held}, :eaddrinuse},
            {{{192, 0, 2, 1}, 0}, :eaddrnotavail}
          ] do
        ref = admit(connection, local)
        assert {:error, {:bind_failed, ^reason}} = await_outcome(connection, ref)
        assert {:ok, ^ref} = migrate(connection, ref, local)
        await_settled(connection)
      end

      refute_received {:DOWN, ^caller_down, :process, ^caller, _}
      assert Process.alive?(client)
      assert {:ok, %{local: local}} = Quic.info(connection)
      assert local == before.local

      {:ok, stream} = Quic.open_stream(connection, :bidi)
      {:ok, _} = Quic.send_stream(stream, "old-path", true)
      assert await_data(accepted) == "old-path"

      if cleanup do
        send(caller, :stop)
        assert_receive {:DOWN, ^caller_down, :process, ^caller, :normal}, 2_000

        # Each failed candidate births one IO actor and no native Port.
        assert {:ok, %{cleanup: :confirmed, roles: %{io: 3, port: 1}} = receipt} =
                 Quic.Cleanup.await(cleanup, {:abs_ms, now() + 5_000})

        assert receipt.down == receipt.enrolled
        assert receipt.unresolved_births == 0 and receipt.unresolved_operations == 0
      end
    end
  end

  defp migrate(connection, ref, local),
    do: Quic.migrate(connection, local: local, ref: ref, deadline: {:abs_ms, now() + 5_000})

  # quic_ready precedes HANDSHAKE_DONE on the client; retry until confirmed.
  defp admit(connection, local, deadline \\ now() + 5_000) do
    assert now() < deadline
    ref = make_ref()

    case migrate(connection, ref, local) do
      {:ok, ^ref} ->
        ref

      # The peer replaces a CID spent by an earlier failed candidate shortly after.
      {:error, reason} when reason in [:handshake_not_confirmed, :no_unused_connection_id] ->
        Process.sleep(10)
        admit(connection, local, deadline)
    end
  end

  defp await_outcome(connection, ref, deadline \\ now() + 5_000) do
    assert now() < deadline

    case Quic.operation_status(connection, ref) do
      %{outcome: {_, _} = outcome} ->
        outcome

      _ ->
        Process.sleep(5)
        await_outcome(connection, ref, deadline)
    end
  end

  defp await_settled(connection, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, info} = Quic.info(connection)

    unless map_size(info.migration.paths) == 1 do
      Process.sleep(5)
      await_settled(connection, deadline)
    end
  end

  defp await_data(accepted, acc \\ <<>>, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, events} = Quic.events(accepted, 32)

    acc =
      Enum.reduce(events, acc, fn
        {:stream_open, stream, :bidi}, acc -> acc <> read_all(stream)
        _, acc -> acc
      end)

    if acc == "old-path" do
      acc
    else
      Process.sleep(5)
      await_data(accepted, acc, deadline)
    end
  end

  defp read_all(stream, acc \\ <<>>, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc <> for({:data, _, bytes} <- items, into: <<>>, do: bytes)

    if Enum.any?(items, &match?({:fin, _}, &1)) do
      acc
    else
      Process.sleep(5)
      read_all(stream, acc, deadline)
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
