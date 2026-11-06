defmodule Abyss.UDPBackendResolutionTest do
  use ExUnit.Case, async: true

  @moduletag :integration
  alias Abyss.Transport.UDP.Core

  test "first scalar backend wins and invalid first selectors fail before opening" do
    assert {:ok, :inet} = Core.effective_backend(inet_backend: :inet, inet_backend: :socket)

    assert {:error, {:invalid_option, :inet_backend, :bad}} =
             Core.open_socket(0, inet_backend: :bad, inet_backend: :inet)

    assert {:ok, [{:inet_backend, :socket} | _]} =
             Core.normalize_options([inet_backend: :inet], inet_backend: :socket)
  end

  if :os.type() == {:unix, :linux} do
    test "normalization is idempotent after interface aliases and IPv6 raw conversion" do
      group = {0xFF02, 0, 0, 0, 0, 0, 0, 42}
      {:ok, interfaces} = :net.if_names()
      {index, _} = Enum.find(interfaces, fn {_, name} -> name == ~c"lo" end)

      users = [
        {:inet_backend, :socket},
        :inet6,
        {:multicast_ttl, 7},
        {:multicast_loop, false},
        {:add_membership, {group, "lo"}},
        {:add_membership, {group, index}}
      ]

      assert {:ok, once} = Core.normalize_options([], users)
      assert Core.normalize_options([], once) == {:ok, once}
      assert Enum.count(once, &match?({:add_membership, _}, &1)) == 1
      assert Enum.count(once, &match?({:raw, 41, 18, _}, &1)) == 1
    end
  end
end
