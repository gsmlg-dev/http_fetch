defmodule Abyss.UDPAdmission do
  @moduledoc false
  @table :abyss_udp_admission

  def reserve(server, owner, limit), do: reserve(server, owner, limit, 0, :infinity)

  def reserve(server, owner, limit, bytes, byte_limit),
    do: Abyss.TableOwner.admission({:reserve, server, owner, limit, bytes, byte_limit})

  def reserve_runtime(server, owner, limit, bytes, byte_limit, runtime),
    do:
      Abyss.TableOwner.admission(
        {:reserve_runtime, server, owner, limit, bytes, byte_limit, runtime}
      )

  def protect(token, pid), do: Abyss.TableOwner.admission({:protect, token, pid})
  def spawn_protected(token, fun), do: Abyss.TableOwner.admission({:spawn_protected, token, fun})
  def complete(token), do: Abyss.TableOwner.admission({:complete, token})

  def slots(:owner, owner), do: slots({:_, :_, owner, :_, :_})
  def slots(:server, server), do: slots({:_, server, :_, :_, :_})

  defp slots(pattern) do
    ensure_table()
    :ets.match_object(@table, pattern)
  end

  def admitted(token, pid), do: Abyss.TableOwner.admission({:admitted, token, pid})
  def release(token), do: Abyss.TableOwner.admission({:release, token})
  def release_owner(owner), do: Abyss.TableOwner.admission({:release_owner, owner})
  def release_server(server), do: Abyss.TableOwner.admission({:release_server, server})

  def transition({:reserve, server, owner, limit}),
    do: transition({:reserve, server, owner, limit, 0, :infinity})

  def transition({:reserve, server, owner, limit, bytes, byte_limit}) do
    ensure_table()
    :ets.insert_new(@table, {{:count, server}, 0})
    token = make_ref()
    :ets.insert_new(@table, {{:bytes, server}, 0})
    :ets.insert(@table, {token, server, owner, nil, bytes})
    count = :ets.update_counter(@table, {:count, server}, {2, 1})

    retained = :ets.update_counter(@table, {:bytes, server}, {2, bytes})

    if count <= limit and (byte_limit == :infinity or retained <= byte_limit) and
         Process.alive?(owner) and Process.alive?(server) do
      {:ok, token}
    else
      :ok = transition({:release, token})
      {:error, if(count > limit, do: :handler_limit, else: :input_bytes_limit)}
    end
  end

  def transition({:admitted, token, pid}) do
    case :ets.lookup(@table, token) do
      [{^token, server, owner, nil, bytes}] ->
        true = :ets.insert(@table, {token, server, owner, pid, bytes})
        Abyss.Telemetry.track_connection_accepted(server)
        :ok

      [] ->
        {:error, :stale_owner}
    end
  end

  def transition({:release, token}) do
    case :ets.take(@table, token) do
      [{^token, server, _owner, pid, bytes}] ->
        count = :ets.update_counter(@table, {:count, server}, {2, -1})
        _ = :ets.update_counter(@table, {:bytes, server}, {2, -bytes})
        if count == 0 and not Process.alive?(server), do: delete_counters(server)
        if is_pid(pid), do: Abyss.Telemetry.track_connection_closed(server)
        :ok

      [] ->
        :ok
    end
  end

  def transition({:cleanup_server, server}) do
    case :ets.lookup(@table, {:count, server}) do
      [{_, 0}] -> delete_counters(server)
      _ -> :ok
    end

    :ok
  end

  def transition({:release_owner, owner}) do
    ensure_table()

    for {token, _server, ^owner, pid, _bytes} <-
          :ets.match_object(@table, {:_, :_, owner, :_, :_}) do
      release(token)
      if is_pid(pid), do: Process.exit(pid, :kill)
    end

    :ok
  end

  def transition({:release_server, server}) do
    ensure_table()

    for {token, ^server, _owner, pid, _bytes} <-
          :ets.match_object(@table, {:_, server, :_, :_, :_}) do
      release(token)
      if is_pid(pid), do: Process.exit(pid, :kill)
    end

    :ets.delete(@table, {:count, server})
    :ets.delete(@table, {:bytes, server})
    :ok
  end

  defp delete_counters(server) do
    :ets.delete(@table, {:count, server})
    :ets.delete(@table, {:bytes, server})
  end

  defp ensure_table,
    do:
      Abyss.TableOwner.ensure_table(@table, [:named_table, :public, :set, write_concurrency: true])
end
