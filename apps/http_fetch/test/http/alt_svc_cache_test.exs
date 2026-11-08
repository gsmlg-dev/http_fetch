defmodule HTTP.AltSvc.CacheTest do
  use ExUnit.Case, async: false

  alias HTTP.AltSvc.Cache

  @origin {"cache.test", 443}

  setup do
    Cache.clear()
    on_exit(&Cache.clear/0)
  end

  test "derives origins only from https URIs" do
    assert Cache.origin(URI.parse("https://Cache.Test/a")) == {"cache.test", 443}
    assert Cache.origin(URI.parse("https://cache.test:8443")) == {"cache.test", 8443}
    assert Cache.origin(URI.parse("http://cache.test")) == nil
  end

  test "keeps same-host h3 alternatives and expires them" do
    Cache.put(@origin, ~s(h2=":1", h3="other.test:2", h3=":3"; ma=10), 100)
    assert Cache.lookup(@origin, 109) == {:ok, 3}
    assert Cache.lookup(@origin, 110) == :none

    Cache.put(@origin, ~s(h3="CACHE.test:4"), 100)
    assert Cache.lookup(@origin, 100 + 86_399) == {:ok, 4}
    assert Cache.lookup(@origin, 100 + 86_400) == :none
  end

  test "clear, foreign-only and zero max-age replace the origin entry" do
    for value <- ["clear", ~s(h3="other.test:1"), ~s(h2=":1"), ~s(h3=":1"; ma=0)] do
      Cache.put(@origin, ~s(h3=":5"), 0)
      assert Cache.lookup(@origin, 1) == {:ok, 5}
      Cache.put(@origin, value, 1)
      assert Cache.lookup(@origin, 1) == :none, value
    end
  end

  test "malformed values are ignored" do
    Cache.put(@origin, ~s(h3=":5"), 0)
    Cache.put(@origin, ~s(h3=":bad"), 1)
    assert Cache.lookup(@origin, 1) == {:ok, 5}
  end

  test "broken origins are neither routed nor re-learned for five minutes" do
    Cache.put(@origin, ~s(h3=":5"), 0)
    Cache.mark_broken(@origin, 10)
    assert Cache.lookup(@origin, 10) == :none
    Cache.put(@origin, ~s(h3=":6"), 309)
    assert Cache.lookup(@origin, 309) == :none
    Cache.put(@origin, ~s(h3=":7"), 310)
    assert Cache.lookup(@origin, 310) == {:ok, 7}
  end

  test "size is bounded and expired entries are evicted first" do
    max = Cache.max_entries()
    Cache.put({"short.test", 443}, ~s(h3=":1"; ma=5), 0)

    for index <- 2..max,
        do: Cache.put({"host#{index}.test", 443}, ~s(h3=":1"; ma=#{1_000 + index}), 0)

    assert :ets.info(Cache, :size) == max

    Cache.put({"new.test", 443}, ~s(h3=":9"), 10)
    assert :ets.info(Cache, :size) == max
    assert Cache.lookup({"new.test", 443}, 10) == {:ok, 9}
    assert Cache.lookup({"host2.test", 443}, 10) == {:ok, 1}

    Cache.put({"newer.test", 443}, ~s(h3=":9"), 10)
    assert :ets.info(Cache, :size) == max
    assert Cache.lookup({"host2.test", 443}, 10) == :none
    assert Cache.lookup({"newer.test", 443}, 10) == {:ok, 9}
  end
end
