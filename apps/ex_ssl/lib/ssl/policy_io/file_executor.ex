defmodule SSL.PolicyIO.FileExecutor do
  @moduledoc false
  alias SSL.PolicyIO
  @slice 65_536
  @limit 16_777_216

  def init(observer, connection, capability, generation, deadline) do
    Process.flag(:sensitive, true)

    state = %{
      observer: observer,
      connection: connection,
      capability: capability,
      generation: generation,
      deadline: deadline,
      observer_monitor: Process.monitor(observer),
      connection_monitor: Process.monitor(connection),
      handle: nil,
      cleanup: nil,
      completion: nil
    }

    receive do
      {:policy_activate, ^observer, ^capability} -> await_path(state)
      {:DOWN, _, :process, _, _} -> :ok
    after
      PolicyIO.remaining(deadline) -> :ok
    end
  end

  def read(actor, capability, path, deadline) do
    monitor = Process.monitor(actor)
    send(actor, {:policy_path, self(), capability, path})
    result = collect(actor, capability, monitor, deadline, [], 0)
    Process.demonitor(monitor, [:flush])
    result
  end

  defp collect(actor, capability, monitor, deadline, slices, total) do
    receive do
      {:policy_file, ^actor, ^capability, _generation, :opened} ->
        send(actor, {:policy_next, self(), capability, :read})
        collect(actor, capability, monitor, deadline, slices, total)

      {:policy_file, ^actor, ^capability, _generation, {:bytes, bytes}} ->
        if total + byte_size(bytes) <= @limit do
          send(
            actor,
            {:policy_next, self(), capability,
             if(total + byte_size(bytes) == @limit, do: :probe, else: :read)}
          )

          collect(
            actor,
            capability,
            monitor,
            deadline,
            [bytes | slices],
            total + byte_size(bytes)
          )
        else
          send(actor, {:policy_next, self(), capability, :close})
          collect_closed(actor, capability, monitor, deadline, {:error, :policy_capacity})
        end

      {:policy_file, ^actor, ^capability, _generation, :eof} ->
        send(actor, {:policy_next, self(), capability, :close})

        collect_closed(
          actor,
          capability,
          monitor,
          deadline,
          {:ok, slices |> Enum.reverse() |> IO.iodata_to_binary()}
        )

      {:policy_file, ^actor, ^capability, generation, :enoent} ->
        {:error, :enoent, generation}

      {:policy_file, ^actor, ^capability, _, :failed} ->
        {:error, :policy_io_failed}

      {:DOWN, ^monitor, :process, ^actor, _} ->
        {:error, :policy_io_unconfirmed}
    after
      PolicyIO.remaining(deadline) -> {:error, :deadline_exceeded}
    end
  end

  defp collect_closed(actor, capability, monitor, deadline, result) do
    receive do
      {:policy_file, ^actor, ^capability, _, :closed} -> result
      {:policy_file, ^actor, ^capability, _, :failed} -> {:error, :policy_io_failed}
      {:DOWN, ^monitor, :process, ^actor, _} -> {:error, :policy_io_unconfirmed}
    after
      PolicyIO.remaining(deadline) -> {:error, :deadline_exceeded}
    end
  end

  defp await_path(state) do
    receive do
      {:policy_path, connection, capability, path}
      when connection == state.connection and capability == state.capability ->
        open(state, path)

      {:policy_stop, observer, capability}
      when observer == state.observer and capability == state.capability ->
        :ok

      {:DOWN, _, :process, _, _} ->
        :ok
    after
      PolicyIO.remaining(state.deadline) -> :ok
    end
  end

  defp open(state, path) do
    case call(state, :open) do
      {:ok, token, cleanup} ->
        state = %{state | cleanup: cleanup}

        if entry_allowed?(state) do
          open_file(state, path, token)
        else
          commit(state, {token, :open, :skipped}, :failed)
        end

      _ ->
        notify(state, :failed)
    end
  end

  defp open_file(state, path, token) do
    case :file.open(path, [:raw, :read, :binary]) do
      {:ok, handle} ->
        commit(%{state | handle: handle}, {token, :open, :opened}, :opened)

      {:error, :enoent} ->
        if proven_enoent?(),
          do: commit(state, {token, :open, :enoent}, :enoent),
          else: commit(state, {token, :open, :unknown}, :failed)

      _ ->
        commit(state, {token, :open, :unknown}, :failed)
    end
  end

  defp commit(state, completion, delivery) do
    state = %{state | completion: completion}

    case call(state, {:complete, completion}) do
      :ok ->
        if entry_allowed?(state) do
          notify(state, delivery)
          if state.handle != nil, do: await_next(state)
        else
          drain(state)
        end

      _ ->
        drain(state)
    end
  end

  defp await_next(state) do
    receive do
      {:policy_next, connection, capability, action}
      when connection == state.connection and capability == state.capability and
             action in [:read, :probe] ->
        case call(state, {:begin, :read}) do
          {:ok, token} ->
            if entry_allowed?(state) do
              case :file.read(state.handle, if(action == :probe, do: 1, else: @slice)) do
                {:ok, bytes} when byte_size(bytes) <= @slice ->
                  commit(state, {token, :read, :read_completed}, {:bytes, bytes})

                :eof ->
                  commit(state, {token, :read, :read_completed}, :eof)

                _ ->
                  state = %{state | completion: {token, :read, :read_completed}}
                  _ = call(state, {:complete, state.completion})
                  notify(state, :failed)
                  drain(state)
              end
            else
              completion = {token, :read, :skipped}
              drain(%{state | completion: completion})
            end

          _ ->
            drain(state)
        end

      {:policy_next, connection, capability, :close}
      when connection == state.connection and capability == state.capability ->
        close(state)

      {:policy_stop, observer, capability}
      when observer == state.observer and capability == state.capability ->
        drain(state)

      {:DOWN, _, :process, _, _} ->
        drain(state)
    after
      PolicyIO.remaining(state.deadline) -> drain(state)
    end
  end

  defp close(state) do
    case call(state, {:begin, :close}) do
      {:ok, token} ->
        result = if :file.close(state.handle) == :ok, do: :closed, else: :close_unknown
        completion = {token, :close, result}

        case call(state, {:complete, completion}) do
          :ok -> notify(state, if(result == :closed, do: :closed, else: :failed))
          _ -> _ = call(state, {:drain, completion, {token, result}})
        end

      _ ->
        drain(state)
    end
  end

  defp drain(%{handle: nil}), do: :ok

  defp drain(state) do
    # Exactly one contingent cleanup close: never reopen, retry or read ahead.
    result = if :file.close(state.handle) == :ok, do: :closed, else: :close_unknown
    _ = call(state, {:drain, state.completion, {state.cleanup, result}})
    :ok
  end

  defp entry_allowed?(state) do
    if PolicyIO.remaining(state.deadline) == 0 do
      false
    else
      receive do
        {:policy_stop, observer, capability}
        when observer == state.observer and capability == state.capability ->
          false

        {:DOWN, ref, :process, _, _}
        when ref == state.connection_monitor or ref == state.observer_monitor ->
          false
      after
        0 -> true
      end
    end
  end

  defp call(state, operation),
    do: PolicyIO.request(state.observer, {:policy_actor, state.capability, operation}, :infinity)

  defp notify(state, result),
    do: send(state.connection, {:policy_file, self(), state.capability, state.generation, result})

  # Linux/OTP 28 retains its accepted native observations and source-built evidence.
  # Exact OTP 29 runtimes admit normal returned ENOENT from reviewed source:
  # macOS 29.0.2 and Linux 29.1.2 have identical raw-open wrappers and native code.
  # Native binary equivalence is not established. Other runtimes fail closed.
  defp proven_enoent? do
    case {:os.type(), :erlang.system_info(:otp_release)} do
      {{:unix, :linux}, ~c"28"} -> true
      {{:unix, :linux}, ~c"29"} -> :erlang.system_info(:version) == ~c"17.1.1"
      {{:unix, :darwin}, ~c"29"} -> :erlang.system_info(:version) == ~c"17.0.2"
      _ -> false
    end
  end
end
