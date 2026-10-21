defmodule SSL.Lifecycle.HandoffTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.Handoff

  # Pure facts only: these references are not runtime monitor evidence.
  test "only the original Observer can advance a readiness challenge" do
    context = context()
    nonce = make_ref()
    assert {:ok, pending} = Handoff.writer_ready(Handoff.new(self()), context, nonce)
    foreign = %{context | observer: Process.whereis(:init)}
    assert foreign.observer != context.observer
    assert {:error, :foreign_observer} = Handoff.connection_ready(pending, foreign, nonce)
    assert {:ok, ready} = Handoff.connection_ready(pending, context, nonce)
    assert Handoff.pending?(ready)
  end

  test "an unchanged process cannot substitute its original monitor generation" do
    context = context()
    nonce = make_ref()
    assert {:ok, pending} = Handoff.writer_ready(Handoff.new(self()), context, nonce)
    {_original_ref, :process, pid} = context.identities.connection

    changed = %{
      context
      | identities: Map.put(context.identities, :connection, {make_ref(), :process, pid})
    }

    assert {:error, :stale_handoff_identity} = Handoff.connection_ready(pending, changed, nonce)
    assert {:ok, _ready} = Handoff.connection_ready(pending, context, nonce)
  end

  defp context do
    identities =
      Map.new([:setup, :connection, :writer, :owner, :controller], fn role ->
        {role, {make_ref(), :process, self()}}
      end)

    %{observer: self(), identities: identities, deadline: 100, now: 0}
  end
end
