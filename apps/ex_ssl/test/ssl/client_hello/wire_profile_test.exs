defmodule SSL.ClientHello.WireProfileTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.{GreasePolicy, RecordPolicy, WireProfile}

  test "default profile matches the structural golden" do
    assert %{
             name: nil,
             legacy_version: 0x0303,
             session_id: :random_32,
             cipher_suites: [0x1301],
             compression_methods: [0],
             extensions: [],
             grease: %GreasePolicy{mode: :disabled},
             record: %RecordPolicy{mode: :default}
           } = Map.from_struct(struct(WireProfile))
  end
end
