ExUnit.start()

# Expose only the private gate under test; do not execute the command-line entrypoint.
{:__block__, _, [definition | _]} =
  "../http_runtime_consumer_gate.exs"
  |> Path.expand(__DIR__)
  |> File.read!()
  |> Code.string_to_quoted!()

definition =
  Macro.postwalk(definition, fn
    {:defp, meta, [{:await_release!, _, _} | _] = arguments} -> {:def, meta, arguments}
    node -> node
  end)

Code.compile_quoted(definition)

defmodule HTTP.HTTP2.Pool do
  def stats(pool) do
    Agent.get_and_update(pool, fn state ->
      {%{fixture: %{streams: 0, pending: state.pending}}, %{state | samples: state.samples + 1}}
    end)
  end
end

defmodule HTTP.HTTP2.ConnectionOwner do
  def status(owner) do
    missing? = Agent.get(:http_fetch_http2_pool, & &1.missing?)

    if missing? do
      :ok = DynamicSupervisor.terminate_child(:http_fetch_http2_connection_supervisor, owner)
    end

    GenServer.call(owner, :status)
  end
end

defmodule HTTPRuntimeReleaseTest.Owner do
  use GenServer, restart: :temporary
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)
  def init(opts), do: {:ok, opts}

  def handle_call(:status, _from, opts) do
    Agent.update(:http_fetch_http2_pool, &%{&1 | pending: opts[:pending]})
    {:stop, opts[:reason], opts}
  end
end

defmodule HTTPRuntimeReleaseTest do
  use ExUnit.Case, async: false

  setup do
    start_supervised!({Task.Supervisor, name: :http_runtime_task_supervisor})

    start_supervised!(
      {DynamicSupervisor, name: :http_fetch_http2_connection_supervisor, strategy: :one_for_one}
    )

    start_supervised!(%{
      id: :release_pool_fixture,
      start:
        {Agent, :start_link,
         [fn -> %{samples: 0, pending: 0, missing?: false} end, [name: :http_fetch_http2_pool]]}
    })

    :ok
  end

  for missing? <- [false, true] do
    test "owner status race with missing=#{missing?} requires a fresh release snapshot" do
      Agent.update(:http_fetch_http2_pool, &%{&1 | missing?: unquote(missing?)})
      owner(pending: 0)
      assert nil == HTTPRuntimeConsumerGate.await_release!(deadline())
      assert Agent.get(:http_fetch_http2_pool, & &1.samples) >= 2
    end
  end

  test "normal owner exit cannot confirm release while pool reservations remain" do
    owner(pending: 1)

    assert_raise RuntimeError, "standalone reservations leaked", fn ->
      HTTPRuntimeConsumerGate.await_release!(deadline())
    end

    assert Agent.get(:http_fetch_http2_pool, & &1.samples) >= 2
  end

  test "unexpected owner status failures remain visible" do
    owner(reason: :unexpected_teardown)

    assert {:unexpected_teardown, {GenServer, :call, [_, :status, _]}} =
             catch_exit(HTTPRuntimeConsumerGate.await_release!(deadline()))
  end

  defp owner(opts) do
    {:ok, owner} =
      DynamicSupervisor.start_child(
        :http_fetch_http2_connection_supervisor,
        {HTTPRuntimeReleaseTest.Owner, Keyword.merge([reason: :normal, pending: 0], opts)}
      )

    owner
  end

  defp deadline, do: System.monotonic_time(:millisecond) + 100
end
