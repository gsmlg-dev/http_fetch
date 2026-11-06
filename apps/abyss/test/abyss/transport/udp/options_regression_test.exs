defmodule Abyss.Transport.UDP.OptionsRegressionTest do
  use ExUnit.Case, async: true

  @moduletag :integration
  alias Abyss.Transport.UDP.Core

  test "preserves distinct memberships and removes identical startup joins" do
    first = {:add_membership, {{239, 255, 42, 1}, {127, 0, 0, 1}}}
    second = {:add_membership, {{239, 255, 42, 2}, {127, 0, 0, 1}}}
    third = {:add_membership, {{239, 255, 42, 1}, {0, 0, 0, 0}}}
    assert Core.merge_options([], [first, second, third, first]) == [first, second, third]
  end

  test "raw operations and backend placement survive scalar overrides" do
    raw1 = {:raw, 0, 1, <<1::native-32>>}
    raw2 = {:raw, 0, 2, <<2::native-32>>}

    assert Core.merge_options([active: true], [
             raw1,
             {:inet_backend, :inet},
             raw2,
             {:active, false}
           ]) ==
             [{:inet_backend, :inet}, raw1, raw2, {:active, false}]
  end

  test "family and data-mode aliases override defaults" do
    assert Core.merge_options([:inet6, {:mode, :list}], [:inet, :binary]) == [:inet, :binary]
  end

  test "invalid port and family conflict return actionable errors" do
    assert {:error, {:invalid_port, -1}} = Core.open_socket(-1, [])

    assert {:error, {:invalid_option, :family, :conflicting}} =
             Core.open_socket(0, [:inet, :inet6])
  end
end
