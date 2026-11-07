defmodule Quic.LocalCIDsTest do
  use ExUnit.Case, async: true

  alias Quic.LocalCIDs

  test "initial sequence zero and negotiated limits are independent of the peer CID cache" do
    for {peer_limit, target, limit} <- [{2, 2, 2}, {3, 3, 3}, {4, 4, 4}, {20, 4, 8}] do
      assert {:ok, state} = LocalCIDs.new("initial", peer_limit)
      assert state.highest_sent == 0
      assert state.target == target
      assert state.limit == limit
      assert map_size(state.ids) == 1
      assert LocalCIDs.active?(state, "initial")
      refute LocalCIDs.active?(state, "unknown")
      assert LocalCIDs.refill?(state)
    end

    assert {:ok, state} = LocalCIDs.new("initial")
    assert state.limit == 2
    assert {:ok, state} = LocalCIDs.configure(state, 12)
    assert {state.target, state.limit} == {4, 8}
  end

  test "registration must acknowledge the exact request before publication" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)
    request = {7, make_ref()}
    assert {:ok, reserved, entry} = LocalCIDs.reserve(state, "next", token(1), request)
    assert entry == %{sequence: 1, cid: "next", token: token(1), registration_id: request}
    assert reserved.highest_sent == 0
    refute LocalCIDs.active?(reserved, "next")
    refute LocalCIDs.refill?(reserved)

    assert {:error, :issuance_pending} =
             LocalCIDs.reserve(reserved, "third", token(2), make_ref())

    assert {:error, :registration_pending} = LocalCIDs.published(reserved, 1)
    assert {:error, :stale_registration} = LocalCIDs.registered(reserved, {8, elem(request, 1)})

    assert {:ok, ready, frame} = LocalCIDs.registered(reserved, request)

    assert frame == %{
             type: :new_connection_id,
             sequence: 1,
             retire_prior_to: 0,
             cid: "next",
             token: token(1)
           }

    assert ready.highest_sent == 0
    assert {:ok, ^ready, ^frame} = LocalCIDs.registered(ready, request)
    assert {:error, :invalid_connection_id_retirement} = LocalCIDs.retire(ready, 1, "initial")
    assert {:ok, published} = LocalCIDs.published(ready, 1)
    assert published.highest_sent == 1
    assert published.pending == nil
    assert LocalCIDs.active?(published, "next")
    assert {:ok, ^published} = LocalCIDs.published(published, 1)
    assert {:error, :stale_registration} = LocalCIDs.registered(published, request)
  end

  test "pending registration consumes the last capacity slot" do
    assert {:ok, state} = LocalCIDs.new("initial", 2)
    request = make_ref()
    assert {:ok, reserved, _} = LocalCIDs.reserve(state, "next", token(1), request)
    assert {:ok, ready, _} = LocalCIDs.registered(reserved, request)
    refute LocalCIDs.refill?(ready)
    assert {:ok, full} = LocalCIDs.published(ready, 1)
    refute LocalCIDs.refill?(full)

    assert {:error, :connection_id_capacity} =
             LocalCIDs.reserve(full, "extra", token(2), make_ref())
  end

  test "hard capacity includes every unacknowledged issuance" do
    assert {:ok, state} = LocalCIDs.new("initial", 100)
    full = Enum.reduce(1..7, state, &issue(&2, &1))
    assert map_size(full.ids) == 8
    assert full.highest_sent == 7
    refute LocalCIDs.refill?(full)

    assert {:error, :connection_id_capacity} =
             LocalCIDs.reserve(full, "ninth", token(8), make_ref())

    assert {:error, :connection_id_capacity} = LocalCIDs.configure(full, 7)
  end

  test "retirement removes CID and token once and leaves one coalesced refill need" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)
    full = Enum.reduce(1..3, state, &issue(&2, &1))
    refute LocalCIDs.refill?(full)
    assert {:ok, retired, "cid-1"} = LocalCIDs.retire(full, 1, "initial")
    refute LocalCIDs.active?(retired, "cid-1")
    refute Map.has_key?(retired.ids, 1)
    assert LocalCIDs.refill?(retired)
    assert {:ok, ^retired, nil} = LocalCIDs.retire(retired, 1, "initial")
    assert {:ok, retired, "cid-2"} = LocalCIDs.retire(retired, 2, "initial")
    assert LocalCIDs.refill?(retired)

    assert {:ok, reserved, %{sequence: 4}} =
             LocalCIDs.reserve(retired, "cid-4", token(4), make_ref())

    refute LocalCIDs.refill?(reserved)
  end

  test "retiring sequence zero is legal on a packet addressed to another active CID" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)
    state = issue(state, 1)
    assert {:ok, retired, "initial"} = LocalCIDs.retire(state, 0, "cid-1")
    refute LocalCIDs.active?(retired, "initial")
    assert {:ok, ^retired, nil} = LocalCIDs.retire(retired, 0, "cid-1")
  end

  test "unsent sequences and the containing destination CID are protocol errors" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)
    state = issue(state, 1)
    assert {:error, :invalid_connection_id_retirement} = LocalCIDs.retire(state, 2, "initial")
    assert {:error, :invalid_connection_id_retirement} = LocalCIDs.retire(state, 0, "initial")
    assert {:error, :invalid_connection_id_retirement} = LocalCIDs.retire(state, 1, "cid-1")
    assert {:error, :invalid_connection_id_retirement} = LocalCIDs.retire(state, -1, "initial")
  end

  test "late publication and registration acknowledgments never resurrect retired issuance" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)
    state = issue(state, 1)
    assert {:ok, retired, "cid-1"} = LocalCIDs.retire(state, 1, "initial")
    request = make_ref()

    assert {:ok, reserved, %{sequence: 2}} =
             LocalCIDs.reserve(retired, "cid-2", token(2), request)

    assert {:ok, ^reserved} = LocalCIDs.published(reserved, 1)
    assert {:error, :stale_registration} = LocalCIDs.registered(reserved, make_ref())
    assert {:error, :stale_issuance} = LocalCIDs.published(reserved, 3)
    assert {:ok, ready, _} = LocalCIDs.registered(reserved, request)
    assert {:ok, ^ready} = LocalCIDs.published(ready, 1)
    assert {:ok, ^ready, nil} = LocalCIDs.retire(ready, 1, "initial")
    assert {:ok, final} = LocalCIDs.published(ready, 2)
    refute LocalCIDs.active?(final, "cid-1")
    assert LocalCIDs.active?(final, "cid-2")
  end

  test "configuring a smaller capacity cannot discard an unpublished route reservation" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)
    state = issue(state, 1)
    assert {:ok, reserved, _} = LocalCIDs.reserve(state, "cid-2", token(2), make_ref())
    assert {:error, :connection_id_capacity} = LocalCIDs.configure(reserved, 2)
    assert {:ok, configured} = LocalCIDs.configure(reserved, 3)
    assert configured.pending == reserved.pending
    assert configured.limit == 3
  end

  test "rapid valid retirement has constant retained state and gapless published sequences" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)

    final =
      Enum.reduce(1..2_000, state, fn sequence, acc ->
        published = issue(acc, sequence)
        assert {:ok, retired, cid} = LocalCIDs.retire(published, sequence, "initial")
        assert cid == "cid-#{sequence}"

        if sequence > 1 do
          assert {:ok, ^retired, nil} = LocalCIDs.retire(retired, sequence - 1, "initial")
        end

        assert map_size(retired.ids) == 1
        assert retired.pending == nil
        retired
      end)

    assert final.highest_sent == 2_000
    assert :erlang.external_size(final) < 512
  end

  test "zero-length CID mode cannot issue or retire connection IDs" do
    assert {:ok, state} = LocalCIDs.new(<<>>, 8)
    refute LocalCIDs.refill?(state)

    assert {:error, :zero_length_connection_id} =
             LocalCIDs.reserve(state, "next", token(1), make_ref())

    assert {:error, :invalid_connection_id_retirement} = LocalCIDs.retire(state, 0, "other")
  end

  test "CID and reset-token validation prevents malformed or conflicting issuance" do
    assert {:ok, state} = LocalCIDs.new("initial", 8)

    for cid <- [<<>>, :binary.copy(<<1>>, 21), nil] do
      assert {:error, :invalid_connection_id} =
               LocalCIDs.reserve(state, cid, token(1), make_ref())
    end

    for reset_token <- [<<>>, <<1>>, :binary.copy(<<1>>, 17), nil] do
      assert {:error, :invalid_reset_token} =
               LocalCIDs.reserve(state, "next", reset_token, make_ref())
    end

    assert {:error, :connection_id_conflict} =
             LocalCIDs.reserve(state, "initial", token(1), make_ref())

    state = issue(state, 1)

    assert {:error, :connection_id_conflict} =
             LocalCIDs.reserve(state, "new", token(1), make_ref())

    assert {:error, :invalid_connection_id} = LocalCIDs.new(:binary.copy(<<1>>, 21), 8)
  end

  test "transport limits and sequence exhaustion are explicit local errors" do
    for limit <- [0, 1, -1, nil, 4_611_686_018_427_387_904] do
      assert {:error, :invalid_active_connection_id_limit} = LocalCIDs.new("initial", limit)
    end

    assert {:ok, state} = LocalCIDs.new("initial", 8)
    exhausted = %{state | highest_sent: 4_611_686_018_427_387_903}

    assert {:error, :connection_id_sequence_exhausted} =
             LocalCIDs.reserve(exhausted, "next", token(1), make_ref())
  end

  defp issue(state, sequence) do
    request = make_ref()

    assert {:ok, reserved, %{sequence: ^sequence}} =
             LocalCIDs.reserve(state, "cid-#{sequence}", token(sequence), request)

    assert {:ok, ready, %{sequence: ^sequence}} = LocalCIDs.registered(reserved, request)
    assert {:ok, published} = LocalCIDs.published(ready, sequence)
    published
  end

  defp token(value), do: <<value::128>>
end
