defmodule Quic.ProfileTest do
  use ExUnit.Case, async: true

  alias Quic.Profile

  test "built-in profiles are legal and distinguishable policy" do
    assert {:ok, ordered} = Profile.compile(:ordered)
    assert {:ok, compact} = Profile.compile(:compact)
    assert ordered.tls != compact.tls
    assert ordered.cid_length != compact.cid_length
    assert ordered.tls.session_id == :empty
    assert ordered.tls.record.mode == :none
    assert {:raw, 57, <<>>} in ordered.tls.extensions
  end

  test "profile limits fail closed" do
    assert {:error, {:invalid_profile, :cid_length}} = Profile.compile(:ordered, cid_length: 7)

    assert {:error, {:invalid_profile, :max_packet_size}} =
             Profile.compile(:ordered, max_packet_size: 1199)

    assert {:error, {:invalid_profile, :transport_parameters}} =
             Profile.compile(:ordered, transport_parameters: :not_binary)
  end

  test "materialization generates fresh random and key share values" do
    {:ok, profile} = Profile.compile(:ordered)
    assert {:ok, first} = Profile.materialize(profile)
    assert {:ok, second} = Profile.materialize(profile)
    refute first.client_hello.random == second.client_hello.random
    refute first.key_pairs == second.key_pairs
  end
end
