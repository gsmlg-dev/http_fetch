defmodule HTTP.HTTP2WireProfileTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.WireProfile

  test "rejects unknown fields and preserves ordered settings in the digest" do
    assert {:error, {:unknown_fields, [:typo]}} = WireProfile.compile(%{id: "x", typo: true})
    left = %{id: "ordered", settings: [{1, 4096}, {4, 65_535}]}
    right = %{id: "ordered", settings: [{4, 65_535}, {1, 4096}]}
    assert {:ok, a} = WireProfile.digest(left)
    assert {:ok, b} = WireProfile.digest(right)
    refute a == b

    assert {:ok, <<0, 1, 0, 0, 16, 0, 0, 4, 0, 0, 255, 255>>} =
             WireProfile.settings_payload(left)
  end

  test "ships native and visibly different synthetic profiles" do
    assert {:ok, native} = WireProfile.compile(WireProfile.native_v1())
    assert {:ok, first} = WireProfile.compile(WireProfile.synthetic_test_v1())
    assert {:ok, second} = WireProfile.compile(WireProfile.synthetic_test_v2())
    assert native.id == "native_v1"
    refute first.pseudo_headers == second.pseudo_headers
    refute first.settings == second.settings
    assert {:ok, 65_536} = WireProfile.initial_window_increment(first)
  end
end
