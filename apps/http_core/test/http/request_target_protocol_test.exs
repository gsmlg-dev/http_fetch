defmodule HTTP.RequestTargetProtocolTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{Frame, HPACK}

  @targets [
    {nil, "/a%2Fb"},
    {"", "/a%2Fb?"},
    {"x=%2F%26&y=%2520", "/a%2Fb?x=%2F%26&y=%2520"}
  ]

  test "HTTP/2 encoded request headers preserve absent, empty and escaped queries" do
    for {query, target} <- @targets do
      request = %HTTP.Request{
        url: %{URI.parse("https://example.test/a%2Fb") | query: query}
      }

      wire = request |> HTTP.HTTP2.serialize_request() |> IO.iodata_to_binary()
      preface = HTTP.HTTP2.connection_preface()
      preface_size = byte_size(preface)
      assert <<^preface::binary-size(preface_size), frames::binary>> = wire
      assert {:ok, %Frame{type: :settings}, frames} = Frame.decode(frames)
      assert {:ok, %Frame{type: :headers, payload: block}, ""} = Frame.decode(frames)
      assert {:ok, _decoder, headers} = HPACK.decode(HPACK.new_decoder(), block)
      assert {":path", target} in headers
    end
  end

  test "WebSocket HTTP/2 CONNECT headers preserve absent, empty and escaped queries" do
    for {query, target} <- @targets do
      request = %HTTP.Request{
        method: :connect,
        url: %{URI.parse("wss://example.test/a%2Fb") | query: query},
        headers: HTTP.Headers.new([{"Sec-WebSocket-Version", "13"}])
      }

      assert {:ok, headers, ""} = HTTP.HTTP2.extended_connect_headers(request, :native_v1)
      assert {":path", target} in headers
    end
  end

  test "HTTP forward proxy absolute form preserves absent, empty and escaped queries" do
    for {query, target} <- @targets do
      request = %HTTP.Request{
        request_mode: :proxy,
        url: %{URI.parse("http://example.test:8080/a%2Fb") | query: query},
        transport_options: [proxy: {:http, "127.0.0.1", 3128, []}]
      }

      wire = request |> HTTP.Request.to_iodata() |> IO.iodata_to_binary()
      [line, _headers] = String.split(wire, "\r\n", parts: 2)
      assert line == "GET http://example.test:8080#{target} HTTP/1.1"
    end
  end
end
