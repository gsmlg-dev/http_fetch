defmodule Quic.MigrationOwnerDeathIntegrationTest do
  # Forced death of the client endpoint (the owner of the connection, both UDP
  # actors and both native Ports) at every two-socket migration transition.
  # Each transition is held exactly by a sys debug hook that blocks inside the
  # target process before it handles the transition message.
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

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-death"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-death"]
     ]}
  end

  setup do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen(tls: server_tls)
    {:ok, cleanup, lease} = Quic.Cleanup.new()
    Process.flag(:trap_exit, true)
    {:ok, client} = Quic.client(tls: client_tls, cleanup: lease)

    on_exit(fn ->
      if Process.alive?(server) do
        try do
          :sys.resume(server)
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
    await_migratable(connection)

    %{server: server, client: client, cleanup: cleanup, lease: lease, connection: connection}
  end

  test "owner death with the candidate bound but not yet probing", ctx do
    tag = freeze_on(ctx.connection.id, &match?({:quic_path_bound, _, _, _, {:ok, _, _}}, &1))
    _ref = migrate!(ctx.connection)
    assert_receive {:frozen, ^tag, _}, 5_000
    kill_owner(ctx, {ctx.connection.id, tag})
  end

  test "owner death after the candidate probe is sent and unanswered", ctx do
    :ok = :sys.suspend(ctx.server)
    ref = migrate!(ctx.connection)

    await(fn ->
      {_, data} = :sys.get_state(ctx.connection.id)
      migration = data.local_migration

      match?(%{ref: ^ref, phase: :validating}, migration) and
        data.paths.paths[migration.id].challenges != []
    end)

    kill_owner(ctx, nil)
  end

  for {transition, message, phases} <- [
        {"validated", :quic_select_local_path, [:settling, :retiring]},
        {"old retiring", :quic_retire_local_path, [:retiring]}
      ] do
    test "owner death at #{transition} with both sockets still owned", ctx do
      message = unquote(message)
      tag = freeze_on(ctx.client, &(is_tuple(&1) and elem(&1, 0) == message))
      ref = migrate!(ctx.connection)
      assert_receive {:frozen, ^tag, _}, 5_000
      {_, data} = :sys.get_state(ctx.connection.id)
      assert data.local_migration.phase in unquote(phases)
      assert %{outcome: {:ok, _}} = Quic.operation_status(ctx.connection, ref)
      kill_owner(ctx, {ctx.client, tag})
    end
  end

  defp kill_owner(ctx, frozen) do
    resources = :sys.get_state(ctx.cleanup.observer).resources
    roles = resources |> Map.values() |> Enum.frequencies_by(& &1.role)
    assert roles == %{endpoint: 1, connection: 1, io: 2, port: 2}

    joins =
      for {resource, _} <- resources do
        type = if is_port(resource), do: :port, else: :process
        {type, resource, :erlang.monitor(type, resource)}
      end

    Process.exit(ctx.client, :kill)
    with {pid, tag} <- frozen, do: send(pid, {:thaw, tag})
    client = ctx.client
    assert_receive {:EXIT, ^client, :killed}, 2_000

    for {type, resource, monitor} <- joins do
      assert_receive {:DOWN, ^monitor, ^type, ^resource, _}, 3_000
      if type == :port, do: assert(:erlang.port_info(resource) == :undefined)
    end

    assert {:ok, receipt} = Quic.Cleanup.retire(ctx.lease, {:abs_ms, now() + 5_000})

    assert %{
             cleanup: :confirmed,
             native_outcome: :resolved,
             unresolved_births: 0,
             unresolved_operations: 0,
             roles: %{endpoint: 1, connection: 1, io: 2, port: 2},
             enrolled: 6,
             down: 6
           } = receipt
  end

  defp freeze_on(target, match) do
    parent = self()
    tag = make_ref()

    hook = fn state, event, _ ->
      message =
        case event do
          {:in, {:info, message}} -> message
          {:in, {:info, message}, _} -> message
          {:in, message} -> message
          {:in, message, _} -> message
          _ -> nil
        end

      if message != nil and match.(message) do
        send(parent, {:frozen, tag, message})

        receive do
          {:thaw, ^tag} -> :done
        end
      else
        state
      end
    end

    :ok = :sys.install(target, {hook, nil})
    tag
  end

  defp migrate!(connection) do
    ref = make_ref()
    deadline = {:abs_ms, now() + 5_000}

    assert {:ok, ^ref} =
             Quic.migrate(connection, local: {{127, 0, 0, 1}, 0}, ref: ref, deadline: deadline)

    ref
  end

  # Wait for HANDSHAKE_DONE and a spare peer CID without consuming either.
  defp await_migratable(connection) do
    await(fn ->
      {_, data} = :sys.get_state(connection.id)
      cids = data.scheduler.peer_cids

      data.scheduler.tls.facts.quic_confirmed and cids != nil and
        Enum.any?(cids.ids, fn {_, entry} -> not Map.get(entry, :used, false) end)
    end)
  end

  defp await(check, deadline \\ now() + 5_000) do
    assert now() < deadline

    unless check.() do
      Process.sleep(5)
      await(check, deadline)
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
