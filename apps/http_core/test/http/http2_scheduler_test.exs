defmodule HTTP.HTTP2SchedulerTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.Scheduler

  test "rotates ready streams without allocating unregistered work" do
    scheduler = Scheduler.new([1, 3, 5])
    assert {[1, 3], scheduler} = Scheduler.ready(scheduler, [1, 3])
    assert {[3, 1], scheduler} = Scheduler.ready(scheduler, [1, 3])
    assert {[5, 1], _scheduler} = Scheduler.ready(scheduler, [1, 5])
  end

  test "removing a stream preserves bounded order" do
    scheduler = Scheduler.new([1, 3, 5]) |> Scheduler.remove(3)
    assert {[1, 5], _scheduler} = Scheduler.ready(scheduler, [1, 3, 5])
    assert Scheduler.add(scheduler, 5).order == [1, 5]
    assert Scheduler.add(scheduler, 7).order == [1, 5, 7]
  end
end
