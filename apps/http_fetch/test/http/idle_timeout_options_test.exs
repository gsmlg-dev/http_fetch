defmodule HTTP.IdleTimeoutOptionsTest do
  use ExUnit.Case, async: true

  alias HTTP.FetchOptions

  test "idle deadlines normalize explicit millisecond options and aliases independently" do
    for input <- [
          [read_idle_timeout: 150, write_idle_timeout: 250],
          %{"readIdleTimeout" => 150, "writeIdleTimeout" => 250},
          %{"read_idle_timeout" => 150, "write_idle_timeout" => 250}
        ] do
      options = FetchOptions.new(input)
      assert Map.get(options, :read_idle_timeout) == 150
      assert Map.get(options, :write_idle_timeout) == 250
      transport = FetchOptions.to_transport_options(options)
      assert transport[:read_idle_timeout] == 150
      assert transport[:write_idle_timeout] == 250
    end
  end

  test "idle deadlines validate positive milliseconds rather than accepting silent options" do
    for key <- [:read_idle_timeout, :write_idle_timeout],
        value <- [0, -1, 1.5, "100", :infinity, 4_294_967_296] do
      assert_raise ArgumentError, ~r/idle_timeout/, fn -> FetchOptions.new([{key, value}]) end
    end
  end

  test "idle deadlines reject managed scopes instead of changing immutable socket policy" do
    for key <- [:read_idle_timeout, :write_idle_timeout] do
      assert_raise ArgumentError, ~r/transport_scope/, fn ->
        FetchOptions.new([{key, 100}, {:transport_scope, make_ref()}])
      end
    end
  end

  test "low-level requests reject normalized managed scope injection before I/O" do
    for key <- [:read_idle_timeout, :write_idle_timeout],
        injection <- [[transport_scope: make_ref()], [managed_coordinator: self()]] do
      request = %HTTP.Request{
        url: URI.parse("http://localhost:1/"),
        transport_options: [{key, 100}, {:http_version, :http1} | injection]
      }

      assert {:error, {:unsupported_idle_timeout, :transport_scope}} =
               HTTP.SocketClient.request(request)
    end
  end

  test "ordinary HTTP/1 pool isolation remains available with idle deadlines" do
    assert %{http1_scope: "route", read_idle_timeout: 100} =
             FetchOptions.new(http_version: :http1, http1_scope: "route", read_idle_timeout: 100)
  end

  test "idle deadlines explicitly require HTTP/1 and never downgrade automatic negotiation" do
    for version <- [:http2, :h2c, :http3, :auto],
        key <- [:read_idle_timeout, :write_idle_timeout] do
      assert_raise ArgumentError, ~r/http_version.*http1/, fn ->
        FetchOptions.new([{key, 100}, {:http_version, version}])
      end
    end
  end
end
