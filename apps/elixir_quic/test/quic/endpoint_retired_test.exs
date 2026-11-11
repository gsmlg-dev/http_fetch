defmodule Quic.EndpointRetiredTest do
  use ExUnit.Case, async: true

  alias Quic.Endpoint

  test "retired identifiers are evicted oldest first" do
    retired =
      Enum.reduce(1..6, %{}, fn n, acc -> Endpoint.add_retired(acc, [{:cid, <<n>>}], 4) end)

    assert retired |> Map.keys() |> Enum.sort() ==
             [{:cid, <<3>>}, {:cid, <<4>>}, {:cid, <<5>>}, {:cid, <<6>>}]
  end

  test "retiring a batch beyond the limit keeps the newest entries" do
    old = Endpoint.add_retired(%{}, [{:cid, "a"}, {:cid, "b"}], 3)
    retired = Endpoint.add_retired(old, [{:cid, "c"}, {:cid, "d"}], 3)
    refute Map.has_key?(retired, {:cid, "a"})
    assert map_size(retired) == 3
    assert Map.has_key?(retired, {:cid, "d"})
  end
end
