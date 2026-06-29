defmodule HTTP.WebSocket.OptionsTest do
  use ExUnit.Case, async: true

  alias HTTP.WebSocket.Options

  test "normalizes http and https schemes to ws and wss" do
    assert {:ok, %{uri: %{scheme: "ws"}, url: "ws://example.com/socket"}} =
             Options.new("http://example.com/socket")

    assert {:ok, %{uri: %{scheme: "wss"}, url: "wss://example.com/socket"}} =
             Options.new("https://example.com/socket")
  end

  test "rejects unsupported schemes and fragments" do
    assert {:error, {:unsupported_scheme, "ftp"}} = Options.new("ftp://example.com/socket")
    assert {:error, :fragment_not_allowed} = Options.new("ws://example.com/socket#frag")
  end

  test "normalizes protocols" do
    assert {:ok, %{protocols: []}} = Options.new("ws://example.com/socket")
    assert {:ok, %{protocols: ["chat"]}} = Options.new("ws://example.com/socket", "chat")

    assert {:ok, %{protocols: ["chat", "json"]}} =
             Options.new("ws://example.com/socket", ["chat", "json"])
  end

  test "rejects duplicate or invalid protocols" do
    assert {:error, :duplicate_protocol} =
             Options.new("ws://example.com/socket", ["chat", "chat"])

    assert {:error, :invalid_protocol} = Options.new("ws://example.com/socket", ["bad,token"])
    assert {:error, :invalid_protocol} = Options.new("ws://example.com/socket", [""])
  end

  test "normalizes flat init options" do
    assert {:ok, options} =
             Options.new("ws://example.com/socket", [],
               owner: self(),
               binary_type: :array_buffer,
               headers: %{"x-token" => "abc"},
               timeout: 10,
               connect_timeout: 5,
               ssl: [verify: :verify_none],
               socket_opts: [nodelay: true],
               max_message_size: 32,
               max_send_queue: 64
             )

    assert options.owner == self()
    assert options.binary_type == :array_buffer
    assert {"X-Token", "abc"} in options.headers
    assert options.timeout == 10
    assert options.connect_timeout == 5
    assert options.ssl == [verify: :verify_none]
    assert options.socket_opts == [nodelay: true]
    assert options.max_message_size == 32
    assert options.max_send_queue == 64
  end
end
