defmodule HTTP.WebSocket.HandshakeTest do
  use ExUnit.Case, async: true

  alias HTTP.WebSocket.Handshake

  @key "dGhlIHNhbXBsZSBub25jZQ=="

  test "calculates RFC 6455 accept key" do
    assert Handshake.accept_key(@key) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  end

  test "builds opening handshake request" do
    uri = URI.parse("ws://example.com/chat?room=1")

    assert {:ok, request} =
             Handshake.build_request(uri, ["chat.v1"], [{"Sec-WebSocket-Key", "bad"}], @key)

    assert request =~ "GET /chat?room=1 HTTP/1.1\r\n"
    assert request =~ "Host: example.com\r\n"
    assert request =~ "Upgrade: websocket\r\n"
    assert request =~ "Connection: Upgrade\r\n"
    assert request =~ "Sec-WebSocket-Key: #{@key}\r\n"
    assert request =~ "Sec-WebSocket-Version: 13\r\n"
    assert request =~ "Sec-WebSocket-Protocol: chat.v1\r\n"
    refute request =~ "Sec-WebSocket-Key: bad\r\n"
  end

  test "uses root request target when path is empty" do
    assert {:ok, request} = Handshake.build_request(URI.parse("ws://example.com"), [], [], @key)
    assert request =~ "GET / HTTP/1.1\r\n"
  end

  test "parses and validates successful response" do
    response =
      "HTTP/1.1 101 Switching Protocols\r\n" <>
        "Upgrade: websocket\r\n" <>
        "Connection: Upgrade\r\n" <>
        "Sec-WebSocket-Accept: #{Handshake.accept_key(@key)}\r\n" <>
        "Sec-WebSocket-Protocol: chat.v1\r\n\r\nextra"

    assert {:ok, 101, headers, "extra"} = Handshake.parse_response(response)

    assert {:ok, %{protocol: "chat.v1", extensions: ""}} =
             Handshake.validate_response(101, headers, @key, ["chat.v1"])
  end

  test "rejects invalid handshake responses" do
    headers =
      HTTP.Headers.new([
        {"Upgrade", "websocket"},
        {"Connection", "Upgrade"},
        {"Sec-WebSocket-Accept", "wrong"}
      ])

    assert {:error, {:unexpected_status, 200}} =
             Handshake.validate_response(200, headers, @key, [])

    assert {:error, :invalid_accept} = Handshake.validate_response(101, headers, @key, [])
  end

  test "rejects unsupported extensions and unexpected protocols" do
    headers =
      HTTP.Headers.new([
        {"Upgrade", "websocket"},
        {"Connection", "Upgrade"},
        {"Sec-WebSocket-Accept", Handshake.accept_key(@key)},
        {"Sec-WebSocket-Protocol", "other"}
      ])

    assert {:error, {:unexpected_protocol, "other"}} =
             Handshake.validate_response(101, headers, @key, ["chat"])

    headers = HTTP.Headers.set(headers, "Sec-WebSocket-Protocol", "chat")
    headers = HTTP.Headers.set(headers, "Sec-WebSocket-Extensions", "permessage-deflate")

    assert {:error, {:unsupported_extensions, "permessage-deflate"}} =
             Handshake.validate_response(101, headers, @key, ["chat"])
  end
end
