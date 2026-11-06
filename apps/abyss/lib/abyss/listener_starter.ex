defmodule Abyss.ListenerStarter do
  @moduledoc false
  use GenServer

  def start_link(owner), do: GenServer.start_link(__MODULE__, owner)
  def start(pid, request), do: GenServer.cast(pid, {:start, request})
  def dispatch(pid, request), do: GenServer.cast(pid, {:dispatch, request})

  @impl true
  def init(owner), do: {:ok, owner}

  @impl true
  def handle_cast(
        {:dispatch, {token, dispatcher, {ip, port, data}, received_at, metadata}},
        owner
      ) do
    result =
      Abyss.Dispatcher.dispatch_with_metadata(
        dispatcher,
        {ip, port},
        data,
        received_at,
        metadata,
        :infinity
      )

    send(owner, {:dispatch_result, token, result})
    {:noreply, owner}
  end

  def handle_cast({:start, {token, server, socket, config, span}}, owner) do
    result = Abyss.Connection.start(server, owner, socket, :deferred, config, span)
    send(owner, {:handler_started, token, result})
    {:noreply, owner}
  end
end
