defmodule Abyss.ConnectionAdmissionTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  defmodule HoldingHandler do
    use GenServer, restart: :temporary
    def start_link(args), do: GenServer.start_link(__MODULE__, args)
    def init(_), do: {:ok, nil}

    def handle_info(message, state) do
      send(Process.whereis(:abyss_admission_test), {:handler_message, self(), message})
      {:noreply, state}
    end
  end

  setup do
    Process.register(self(), :abyss_admission_test)

    supervisor =
      start_supervised!(%{
        id: :admission_server,
        start:
          {Supervisor, :start_link,
           [
             [
               Supervisor.child_spec({DynamicSupervisor, strategy: :one_for_one, max_children: 1},
                 id: :connection_sup
               )
             ],
             [strategy: :one_for_one]
           ]}
      })

    config =
      Abyss.ServerConfig.new(handler_module: HoldingHandler, max_connections_retry_count: 5)

    %{server: supervisor, config: config, span: Abyss.Telemetry.start_span(:connection, %{}, %{})}
  end

  test "success returns the admitted pid", context do
    assert {:ok, pid} = start(context, "hello")
    assert_receive {:handler_message, ^pid, {:new_connection, _, "hello"}}
  end

  test "deferred start does not deliver before listener confirms reservation", context do
    assert {:ok, pid} = start(context, :deferred)
    refute_receive {:handler_message, ^pid, _}, 20
  end

  test "capacity rejects immediately without retry processes or late admission", context do
    assert {:ok, pid} = start(context, :deferred)

    for _ <- 1..100 do
      assert {:error, :too_many_connections} = start(context, "rejected")
    end

    :ok = DynamicSupervisor.terminate_child(Abyss.Server.connection_sup_pid(context.server), pid)

    assert DynamicSupervisor.count_children(Abyss.Server.connection_sup_pid(context.server)).active ==
             0

    refute_receive {:handler_message, _, _}, 20
  end

  defp start(context, packet) do
    Abyss.Connection.start(
      context.server,
      self(),
      make_ref(),
      packet,
      context.config,
      context.span
    )
  end
end
