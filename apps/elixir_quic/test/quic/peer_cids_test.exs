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
end
