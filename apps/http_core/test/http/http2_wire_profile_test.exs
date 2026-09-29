defmodule HTTP.HTTP2WireProfileTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.WireProfile

  test "rejects unknown fields and preserves ordered settings in the digest" do
    assert {:error, {:unknown_fields, [:typo]}} = WireProfile.compile(%{id: "x", typo: true})
    left = %{id: "ordered", settings: [{1, 4096}, {4, 65_535}, {2, 0}]}
    right = %{id: "ordered", settings: [{2, 0}, {4, 65_535}, {1, 4096}]}
    assert {:ok, a} = WireProfile.digest(left)
    assert {:ok, b} = WireProfile.digest(right)
    refute a == b

    assert {:ok, <<0, 1, 0, 0, 16, 0, 0, 4, 0, 0, 255, 255, 0, 2, 0, 0, 0, 0>>} =
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

  test "disabled push is explicit on every built-in wire profile" do
    for profile <- [
          WireProfile.native_v1(),
          WireProfile.synthetic_test_v1(),
          WireProfile.synthetic_test_v2()
        ] do
      assert profile.revision == 2
      assert {2, 0} in profile.settings
      assert Enum.count(profile.settings, fn {id, _} -> id == 2 end) == 1
      assert {:ok, _} = WireProfile.compile(profile)
    end
  end

  test "rejects unsupported or inconsistent advertised profile settings" do
    base = %{id: "custom", settings: [{2, 0}]}

    for change <- [
          %{hpack: %{huffman: :sometimes, indexing: :literal, sensitive: []}},
          %{padding: {:fixed, 2}},
          %{default_user_agent: :omit},
          %{max_data_frame: 32_768},
          %{receive_window_target: 131_072},
          %{settings: [{2, 1}]},
          %{settings: [{2, 0}, {2, 0}]},
          %{settings: [{2, 0}, {4, 131_072}]},
          %{connection_initial_window: 1_048_577}
        ] do
      assert {:error, _} = WireProfile.compile(Map.merge(base, change))
    end

    assert {:ok, _} =
             WireProfile.compile(
               Map.merge(base, %{settings: [{2, 0}, {4, 131_072}], stream_initial_window: 131_072})
             )
  end

  test "runtime request headers remain in input order for one owner ordering pass" do
    request = %HTTP.Request{
      method: :get,
      url: URI.parse("http://example.test/path"),
      headers: HTTP.Headers.new([{"x-first", "1"}, {"x-second", "2"}])
    }

    assert {:ok, prepared, ""} =
             HTTP.HTTP2.request_headers(request, :synthetic_test_v2, order?: false)

    assert Enum.find_index(prepared, &(elem(&1, 0) == "x-first")) <
             Enum.find_index(prepared, &(elem(&1, 0) == "x-second"))

    {pseudo, regular} = Enum.split_with(prepared, &String.starts_with?(elem(&1, 0), ":"))
    ordered = WireProfile.order_headers(WireProfile.synthetic_test_v2(), pseudo, regular)

    assert Enum.find_index(ordered, &(elem(&1, 0) == "x-second")) <
             Enum.find_index(ordered, &(elem(&1, 0) == "x-first"))
  end
end
