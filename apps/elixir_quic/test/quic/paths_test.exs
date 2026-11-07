unless Process.whereis(ExUnit.Server), do: ExUnit.start()

defmodule Quic.PathsTest do
  use ExUnit.Case, async: true
  alias Quic.Paths

  @local {{127, 0, 0, 1}, 4433}
  @old {{127, 0, 0, 1}, 4000}
  @new {{127, 0, 0, 2}, 4001}

  test "probing admits one alternate path without redirecting application output" do
    paths = Paths.new(:server, @local, @old, true)
    assert {:ok, next, 1, true} = Paths.observe(paths, @new, 10, true, -100, 1000)
    assert next.active == :default
    assert map_size(next.paths) == 2
    assert next.paths[1].remote == @new
    refute next.paths[1].validated
    assert {:blocked, :path_limit} = Paths.observe(next, {:third, 44}, 11, false, 0, 1000)
  end

  test "only newer non-probing packets select an alternate path" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, :default, false} = Paths.observe(paths, @old, 20, false, 0, 1000)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 21, false, 1, 1000)
    assert paths.active == 1
    {:ok, paths, :default, false} = Paths.observe(paths, @old, 19, false, 2, 1000)
    assert paths.active == 1
    {:ok, paths, :default, false} = Paths.observe(paths, @old, 22, true, 3, 1000)
    assert paths.active == 1
    {:ok, paths, :default, false} = Paths.observe(paths, @old, 23, false, 4, 1000)
    assert paths.active == :default
  end

  test "clients retain their established server address" do
    paths = Paths.new(:client, @local, @old, true)

    assert {:blocked, :remote_migration_unsupported} =
             Paths.observe(paths, @new, 0, false, 0, 1000)
  end

  test "incoming CID tracking ignores reordered authenticated packets" do
    paths = Paths.new(:server, @local, @old, true)
    paths = Paths.note_cid(paths, :default, <<1>>, 10)
    paths = Paths.note_cid(paths, :default, <<2>>, 11)
    paths = Paths.note_cid(paths, :default, <<1>>, 9)
    assert paths.paths.default.dcid == <<2>>
    assert paths.paths.default.largest_authenticated == 11
  end

  test "responses validate the challenge's send path independent of arrival path" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, 0, 1000)
    {:ok, paths} = Paths.probe(paths, 1, <<1::64>>, true, 0, 1000)
    assert {:ok, paths, 1} = Paths.response(paths, <<1::64>>, 10)
    assert paths.paths[1].validated
    assert paths.paths[1].mtu_validated
    assert :ignore = Paths.response(paths, <<1::64>>, 11)
    assert :ignore = Paths.response(paths, <<2::64>>, 11)
  end

  test "short validation proves reachability without claiming the minimum MTU" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, 0, 1000)
    {:ok, paths} = Paths.probe(paths, 1, <<1::64>>, false, 0, 1000)
    {:ok, paths, 1} = Paths.response(paths, <<1::64>>, 1)
    assert paths.paths[1].validated
    refute paths.paths[1].mtu_validated
    assert 1 in Paths.due(paths, 1001)
  end

  test "challenges remain bounded and expire at the attempt deadline" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, -100, 1000)

    paths =
      Enum.reduce(1..3, paths, fn n, state ->
        {:ok, state} = Paths.probe(state, 1, <<n::64>>, true, -100 + (n - 1) * 1000, 1000)
        state
      end)

    assert length(paths.paths[1].challenges) == 3
    assert {:error, :challenge_limit} = Paths.probe(paths, 1, <<4::64>>, true, 2000, 1000)
    assert :ignore = Paths.response(paths, <<1::64>>, 2900)
  end

  test "failed candidate rolls back only to a freshly validated previous path" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, 0, 1000)
    {:ok, paths} = Paths.probe(paths, :default, <<1::64>>, true, 0, 1000)
    {:ok, paths, :default} = Paths.response(paths, <<1::64>>, 10)
    assert {:ok, paths, 1} = Paths.on_time(paths, 3000)
    assert paths.active == :default
    assert paths.retiring == 1
    {:ok, paths} = Paths.drop(paths, 1)
    assert map_size(paths.paths) == 1
    {:ok, paths, 2, true} = Paths.observe(paths, @new, 1, false, 4000, 1000)
    assert paths.active == 2
  end

  test "both paths failing validation has a finite terminal outcome" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, 0, 1000)
    assert {:error, :no_validated_path} = Paths.on_time(paths, 3000)
  end

  test "settlement prefers a reachable path with an available outgoing CID" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, 0, 1000)
    {:ok, paths} = Paths.probe(paths, :default, <<1::64>>, true, 0, 1000)
    {:ok, paths} = Paths.probe(paths, 1, <<2::64>>, true, 0, 1000)
    {:ok, paths, :default} = Paths.response(paths, <<1::64>>, 1)
    {:ok, paths, 1} = Paths.response(paths, <<2::64>>, 1)
    assert {:ok, ^paths, nil} = Paths.on_time(paths, 2999, [:default])
    assert {:ok, settled, 1} = Paths.on_time(paths, 3000, [:default])
    assert settled.active == :default
    assert {:error, :no_validated_path} = Paths.on_time(paths, 3000, [])
  end

  test "retiring old path cannot regain selection while its controller settles" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 1, false, 0, 1000)
    {:ok, paths} = Paths.probe(paths, 1, <<1::64>>, true, 0, 1000)
    {:ok, paths, 1} = Paths.response(paths, <<1::64>>, 1)
    {:ok, paths, :default} = Paths.on_time(paths, 3000)
    {:ok, paths, :default, false} = Paths.observe(paths, @old, 100, false, 3001, 1000)
    assert paths.active == 1
    assert {:ok, _paths} = Paths.drop(paths, :default)
  end

  test "duplicate old cleanup cannot clear a subsequent migration attempt" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 1, false, 0, 1000)
    {:ok, paths} = Paths.probe(paths, 1, <<1::64>>, true, 0, 1000)
    {:ok, paths, 1} = Paths.response(paths, <<1::64>>, 1)
    {:ok, paths, :default} = Paths.on_time(paths, 3000)
    {:ok, paths} = Paths.drop(paths, :default)
    {:ok, paths, 2, true} = Paths.observe(paths, @old, 2, false, 4000, 1000)
    assert {:ok, ^paths} = Paths.drop(paths, :default)
    assert {:error, :no_validated_path} = Paths.on_time(paths, 7000)
  end

  test "reachability after three short probes permits a padded probe within original deadline" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, 0, 1000)

    paths =
      Enum.reduce(1..3, paths, fn n, state ->
        {:ok, state} = Paths.probe(state, 1, <<n::64>>, false, (n - 1) * 1000, 1000)
        state
      end)

    {:ok, paths, 1} = Paths.response(paths, <<3::64>>, 2100)
    assert 1 in Paths.due(paths, 2100)
    {:ok, paths} = Paths.probe(paths, 1, <<4::64>>, true, 2100, 1000)
    {:ok, paths, 1} = Paths.response(paths, <<4::64>>, 2200)
    assert paths.paths[1].mtu_validated
    assert paths.paths[1].deadline == 3000
  end

  test "successful candidate retains the old path until bounded settlement" do
    paths = Paths.new(:server, @local, @old, true)
    {:ok, paths, 1, true} = Paths.observe(paths, @new, 0, false, 0, 1000)
    {:ok, paths} = Paths.probe(paths, 1, <<1::64>>, true, 0, 1000)
    {:ok, paths, 1} = Paths.response(paths, <<1::64>>, 10)
    assert {:ok, ^paths, nil} = Paths.on_time(paths, 2000)
    {:ok, paths, :default} = Paths.on_time(paths, 3000)
    assert paths.active == 1
    assert {:error, :active_path} = Paths.drop(paths, 1)
    {:ok, paths} = Paths.drop(paths, :default)
    assert map_size(paths.paths) == 1
    assert Paths.next_deadline(paths) == nil
  end
end
