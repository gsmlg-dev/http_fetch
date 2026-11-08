defmodule Quic.ClientMigrationPathsTest do
  use ExUnit.Case, async: true
  alias Quic.Paths
  @old {{127, 0, 0, 1}, 4000}
  @new {{127, 0, 0, 2}, 4001}
  @server {{127, 0, 0, 1}, 4433}

  test "local candidate retains server validation, old selection, and explicit ingress identity" do
    state = Paths.new(:client, @old, @server, true)
    assert {:ok, paths, 1} = Paths.start_local(state, @new, 10, 100, 250)
    assert paths.active == :default
    assert paths.paths[1].remote == @server
    assert paths.paths[1].validated
    refute paths.paths[1].mtu_validated
    assert paths.paths[1].deadline == 250
    assert Paths.lookup_local(paths, @new, @server) == {:ok, 1}
    assert Paths.lookup_local(paths, @old, @server) == {:ok, :default}
    assert Paths.start_local(paths, @old, 10, 100, 250) == {:blocked, :migration_busy}
    assert Paths.due(paths, 10) == [1]
  end

  test "failed candidate retains usable old path without requiring a fresh old probe" do
    state = Paths.new(:client, @old, @server, true)
    {:ok, paths, 1} = Paths.start_local(state, @new, 10, 100, 250)
    assert {:ok, paths, 1} = Paths.on_time(paths, 250)
    assert paths.active == :default
    assert {:ok, paths} = Paths.drop(paths, 1)
    assert paths.paths[:default].local == @old
  end

  test "commit requires candidate reachability and padded challenge response" do
    {:ok, paths, 1} =
      Paths.start_local(Paths.new(:client, @old, @server, true), @new, 0, 100, 300)

    assert {:error, :unvalidated_path} = Paths.commit_local(paths, 1)
    {:ok, paths} = Paths.probe(paths, 1, <<1::64>>, true, 0, 100)
    {:ok, paths, 1} = Paths.response(paths, <<1::64>>, 1)
    assert {:ok, paths} = Paths.commit_local(paths, 1)
    assert paths.active == 1
    assert paths.retiring == :default
  end
end
