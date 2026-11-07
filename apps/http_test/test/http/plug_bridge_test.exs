defmodule HTTP.Test.PlugBridgeTest do
  use ExUnit.Case, async: true

  test "optional Plug bridge buffers bytes and preserves headers within finite limits" do
    request = %HTTP.Request{
      url: URI.parse("https://mock.invalid/path"),
      method: :post,
      body: "input",
      headers: HTTP.Headers.new([{"x-input", "value"}])
    }

    response =
      HTTP.Test.plug(
        request,
        fn conn ->
          assert Map.get(conn, :request_path) == "/path"
          conn = apply(Plug.Conn, :put_resp_header, [conn, "x-output", "value"])
          apply(Plug.Conn, :send_resp, [conn, 201, "output"])
        end,
        body_limit: 32
      )

    assert response.status == 201
    assert response.body == "output"
    assert HTTP.Headers.get(response.headers, "x-output") == "value"
  end

  test "Plug bridge rejects oversized request, oversized response and stream inputs" do
    request = %HTTP.Request{
      url: URI.parse("http://mock.invalid/"),
      method: :post,
      body: "too large",
      headers: HTTP.Headers.new()
    }

    assert_raise ArgumentError, ~r/request body exceeds/, fn ->
      HTTP.Test.plug(request, fn conn -> conn end, body_limit: 2)
    end

    assert_raise ArgumentError, ~r/response body exceeds/, fn ->
      HTTP.Test.plug(
        %{request | body: ""},
        fn conn ->
          apply(Plug.Conn, :send_resp, [conn, 200, "too large"])
        end,
        body_limit: 2
      )
    end

    assert_raise ArgumentError, ~r/buffered request body/, fn ->
      HTTP.Test.plug(%{request | body: self()}, fn conn -> conn end)
    end

    assert_raise ArgumentError, ~r/finite and positive/, fn ->
      HTTP.Test.plug(request, fn conn -> conn end, body_limit: :infinity)
    end
  end
end
