ExUnit.start()

# Exercise the exact candidate supervision assertion without starting clients or
# importing umbrella modules into the external-consumer gate's code path.
{:__block__, _, [definition | _]} =
  "../http_runtime_consumer_gate.exs"
  |> Path.expand(__DIR__)
  |> File.read!()
  |> Code.string_to_quoted!()

definition =
  Macro.postwalk(definition, fn
    {:defp, meta, [{:assert_runtime_children!, _, _} | _] = arguments} ->
      {:def, meta, arguments}

    node ->
      node
  end)

Code.compile_quoted(definition)

defmodule HTTPRuntimePoolOwnershipTest do
  use ExUnit.Case, async: true

  @children [
    HTTP.Runtime.Pool.Registry,
    :http_managed_transport_supervisor,
    HTTP.HTTP1.Pool,
    HTTP.HTTP2.ConnectionSupervisor,
    HTTP.HTTP2.Pool,
    HTTP.HTTP3.ConnectionSupervisor,
    HTTP.HTTP3.Pool
  ]

  test "runtime accepts the pool-family registry alongside one default H1/H2 pair" do
    assert :ok = HTTPRuntimeConsumerGate.assert_runtime_children!(children(@children))
  end

  test "missing registry or either default pool cannot pass candidate startup" do
    for required <- [HTTP.Runtime.Pool.Registry, HTTP.HTTP1.Pool, HTTP.HTTP2.Pool] do
      assert_raise RuntimeError, "runtime has unexpected supervision owners", fn ->
        HTTPRuntimeConsumerGate.assert_runtime_children!(children(@children -- [required]))
      end
    end
  end

  test "duplicate default pools remain a failure after extraction" do
    for pool <- [HTTP.HTTP1.Pool, HTTP.HTTP2.Pool] do
      assert_raise RuntimeError, "runtime has unexpected supervision owners", fn ->
        HTTPRuntimeConsumerGate.assert_runtime_children!(children([pool | @children]))
      end
    end
  end

  defp children(ids), do: Enum.map(ids, &{&1, self(), :worker, [&1]})
end
