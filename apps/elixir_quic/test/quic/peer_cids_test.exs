defmodule Quic.PeerCIDsTest do
  use ExUnit.Case, async: true
  alias Quic.PeerCIDs

  test "deduplicates consistent sequences, bounds active IDs, and rejects conflicts" do
    state = PeerCIDs.new("first")
    frame = %{sequence: 1, retire_prior_to: 0, cid: "second", token: <<1::128>>}
    assert {:ok, next, []} = PeerCIDs.receive_id(state, frame)
    assert {:ok, ^next, []} = PeerCIDs.receive_id(next, frame)

    assert {:error, :connection_id_limit} =
             PeerCIDs.receive_id(next, %{frame | sequence: 2, cid: "third"})

    assert {:error, :connection_id_conflict} =
             PeerCIDs.receive_id(next, %{frame | cid: "changed"})

    assert {:error, :connection_id_conflict} = PeerCIDs.receive_id(next, %{frame | sequence: 2})
  end

  test "retirement replaces the current ID and old reordered IDs remain retired" do
    state = PeerCIDs.new("first")
    frame = %{sequence: 1, retire_prior_to: 1, cid: "second", token: <<1::128>>}
    assert {:ok, next, [0]} = PeerCIDs.receive_id(state, frame)
    assert PeerCIDs.current(next) == "second"

    assert {:ok, ^next, [0]} =
             PeerCIDs.receive_id(next, %{frame | sequence: 0, retire_prior_to: 0, cid: "old"})

    assert {:error, :invalid_retire_prior_to} =
             PeerCIDs.receive_id(next, %{frame | retire_prior_to: 2})
  end

  test "same incoming CID permits NAT rebinding without consuming a spare" do
    state = PeerCIDs.new("initial", 8)
    assert {:ok, state} = PeerCIDs.bind_path(state, 1, :default, true)
    assert PeerCIDs.current(state, :default) == "initial"
    assert PeerCIDs.current(state, 1) == "initial"
    assert map_size(state.bindings) == 2
    assert {:error, :path_limit} = PeerCIDs.bind_path(state, 2, 1, true)
  end

  test "distinct migration consumes an unused CID and never reuses a dropped path CID" do
    state = PeerCIDs.new("initial", 8)

    assert {:error, :no_unused_connection_id} =
             PeerCIDs.bind_path(state, 1, :default, false)

    {:ok, state, []} = PeerCIDs.receive_id(state, frame(1, "second"))
    assert {:ok, state} = PeerCIDs.bind_path(state, 1, :default, false)
    assert PeerCIDs.current(state, :default) == "initial"
    assert PeerCIDs.current(state, 1) == "second"
    state = PeerCIDs.drop_path(state, :default)

    assert {:error, :no_unused_connection_id} = PeerCIDs.bind_path(state, 2, 1, false)
    {:ok, state, [0]} = PeerCIDs.receive_id(state, frame(2, "third"))
    {:ok, state} = PeerCIDs.bind_path(state, 2, 1, false)
    assert PeerCIDs.current(state, 2) == "third"
    assert map_size(state.ids) == 2
    assert Enum.all?(state.ids, fn {_, entry} -> entry.used end)
  end

  test "peer retirement prioritizes selected path and defers an inactive binding" do
    state = PeerCIDs.new("initial", 8)
    {:ok, state, []} = PeerCIDs.receive_id(state, frame(1, "second"))
    {:ok, state} = PeerCIDs.bind_path(state, 1, :default, false)

    assert {:ok, state, [0, 1]} =
             PeerCIDs.receive_id(state, %{frame(2, "third") | retire_prior_to: 2}, 1)

    assert PeerCIDs.current(state, 1) == "third"
    assert PeerCIDs.current(state, :default) == nil
    assert map_size(state.bindings) == 2
    assert {:ok, state, []} = PeerCIDs.receive_id(state, frame(3, "fourth"), 1)
    assert PeerCIDs.current(state, 1) == "third"
    assert PeerCIDs.current(state, :default) == "fourth"
    assert map_size(state.ids) == 2
    assert Enum.all?(state.ids, fn {_, entry} -> entry.used end)
  end

  test "shared NAT bindings can share a replacement after peer retirement" do
    state = PeerCIDs.new("initial")
    {:ok, state} = PeerCIDs.bind_path(state, 1, :default, true)

    {:ok, state, [0]} =
      PeerCIDs.receive_id(state, %{frame(1, "second") | retire_prior_to: 1}, 1)

    assert PeerCIDs.current(state, :default) == "second"
    assert PeerCIDs.current(state, 1) == "second"
    assert map_size(state.ids) == 1
  end

  test "repeated migration retires spent prefixes without allowing delayed CID resurrection" do
    state = PeerCIDs.new("initial")

    state =
      Enum.reduce(1..20, state, fn sequence, state ->
        previous = if sequence == 1, do: :default, else: sequence - 1
        {:ok, state, []} = PeerCIDs.receive_id(state, frame(sequence, "cid-#{sequence}"))
        {:ok, state} = PeerCIDs.bind_path(state, sequence, previous, false)
        state = PeerCIDs.drop_path(state, previous)
        assert {state, [retired]} = PeerCIDs.retire_unused(state)
        assert retired == sequence - 1
        assert state.retired_before == sequence
        assert map_size(state.ids) == 1
        assert map_size(state.bindings) == 1
        assert {:ok, ^state, [^retired]} = PeerCIDs.receive_id(state, frame(retired, "delayed"))
        assert PeerCIDs.current(state, sequence) == "cid-#{sequence}"
        state
      end)

    assert state.retired_before == 20
  end

  test "spent CID beyond a bound lower sequence stays bounded until the floor can advance" do
    state = PeerCIDs.new("initial")
    {:ok, state, []} = PeerCIDs.receive_id(state, frame(1, "second"))
    {:ok, state} = PeerCIDs.bind_path(state, 1, :default, false)
    state = PeerCIDs.drop_path(state, 1)
    assert {^state, []} = PeerCIDs.retire_unused(state)
    assert {:error, :connection_id_limit} = PeerCIDs.receive_id(state, frame(2, "third"))

    assert {:ok, state, [0, 1]} =
             PeerCIDs.receive_id(state, %{frame(2, "third") | retire_prior_to: 1})

    assert state.retired_before == 2
    assert PeerCIDs.current(state, :default) == "third"
    assert map_size(state.ids) == 1
  end

  defp frame(sequence, cid),
    do: %{sequence: sequence, retire_prior_to: 0, cid: cid, token: <<sequence::128>>}
end
