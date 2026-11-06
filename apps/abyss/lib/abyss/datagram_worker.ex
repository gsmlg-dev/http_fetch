defmodule Abyss.DatagramWorker do
  @moduledoc false
  use GenServer

  def start_link(runtime, key, config, context),
    do: GenServer.start_link(__MODULE__, {runtime, key, config, context})

  @impl true
  def init({runtime, key, config, context}) do
    {:ok,
     %{
       runtime: runtime,
       key: key,
       module: config.datagram_options.datagram_handler,
       options: config.handler_options,
       context: context,
       application: nil,
       initialized: false
     }}
  end

  @impl true
  def handle_cast({:invoke, token, event}, state) do
    case initialize(state) do
      {:ok, state} ->
        invoke(token, event, state)

      {:error, reason, state} ->
        _ = send(state.runtime, {:invocation_result, state.key, token, {:init_error, reason}})
        {:noreply, state}
    end
  end

  def handle_cast({:settled, token}, state) do
    _ = send(state.runtime, {:invocation_settled, state.key, token})
    {:noreply, state}
  end

  def handle_cast({:finish, reason}, state), do: {:stop, reason, state}

  defp initialize(%{initialized: true} = state), do: {:ok, state}

  defp initialize(state) do
    case protect(fn -> state.module.init(state.options, state.context) end) do
      {:ok, app} -> {:ok, %{state | application: app, initialized: true}}
      {:error, reason} -> {:error, reason, state}
      other -> {:error, {:invalid_init, other}, state}
    end
  end

  defp invoke(token, event, state) do
    _ = send(state.runtime, {:initialized, state.key, token})

    result = protect(fn -> callback(event, state) end)

    {transition, application} = normalize(result, state.application)
    # Retain the returned state even when validation of its effects subsequently fails.
    _ = send(state.runtime, {:invocation_result, state.key, token, transition})
    {:noreply, %{state | application: application}}
  end

  defp callback({:datagram, datagram}, state),
    do: state.module.handle_datagram(datagram, state.application)

  defp callback({:event, value}, state) do
    if function_exported?(state.module, :handle_event, 2),
      do: state.module.handle_event(value, state.application),
      else: {:ok, state.application, []}
  end

  defp normalize({:ok, app, actions}, _), do: {{:ok, actions}, app}
  defp normalize({:stop, reason, app, actions}, _), do: {{:stop, reason, actions}, app}
  defp normalize({:error, reason, app}, _), do: {{:error, reason}, app}
  defp normalize(other, app), do: {{:error, {:invalid_transition, other}}, app}

  defp protect(fun) do
    fun.()
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  @impl true
  def terminate(reason, %{initialized: true} = state) do
    if function_exported?(state.module, :terminate, 2),
      do: state.module.terminate(reason, state.application)

    :ok
  end

  def terminate(_, _), do: :ok
end
