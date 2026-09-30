defmodule HTTP.WebSocket.HTTP2HelpersTest do
  use ExUnit.Case, async: true

  alias HTTP.WebSocket.Frame
  alias HTTP.WebSocket.Handshake
  alias HTTP.WebSocket.Options

  test "defaults preserve HTTP1 and bound long-lived delivery and writes" do
    assert {:ok, options} = Options.new("ws://example.com/chat", [], timeout: 123)
    assert options.http_version == :http1
    assert options.opening_timeout == 123
    assert options.idle_timeout == :infinity
    assert options.close_timeout == 5_000
    assert options.max_send_frames == 64
    assert options.max_control_frames == 16
    assert options.max_frame_parts == 16_384
    assert options.max_queue_bytes >= options.max_message_size + 7
    assert options.max_queue_events == 64
  end

  test "normalizes shared aliases and rejects incompatible ALPN before networking" do
    assert {:ok, options} =
             Options.new("wss://example.com/chat", [], %{
               "httpVersion" => "h2",
               "delivery" => "ack",
               "maxSendFrames" => 8
             })

    assert options.http_version == :http2
    assert options.delivery == :ack
    assert options.max_send_frames == 8

    assert {:error, :incompatible_alpn} =
             Options.new("wss://example.com", [],
               http_version: :http2,
               ssl: [alpn_advertised_protocols: ["http/1.1"]]
             )
  end

  test "snake case map aliases preserve explicit limits and deadlines" do
    assert {:ok, options} =
             Options.new("ws://example.com", [], %{
               "max_send_frames" => 8,
               "opening_timeout" => 77,
               "idle_timeout" => 99
             })

    assert options.max_send_frames == 8
    assert options.opening_timeout == 77
    assert options.idle_timeout == 99
  end

  test "validates finite limits timeouts URLs and headers" do
    for key <- [
          :max_message_size,
          :max_send_queue,
          :max_send_frames,
          :max_control_frames,
          :max_frame_parts
        ] do
      for value <- [0, -1, :infinity, nil, "12"] do
        assert {:error, {:invalid_option, ^key}} =
                 Options.new("ws://example.com", [], [{key, value}])
      end
    end

    for key <- [:timeout, :connect_timeout, :opening_timeout, :idle_timeout, :close_timeout] do
      assert {:error, {:invalid_option, ^key}} = Options.new("ws://example.com", [], [{key, -1}])
      assert {:ok, _} = Options.new("ws://example.com", [], [{key, :infinity}])
    end

    assert {:error, :message_limit_exceeds_delivery_limit} =
             Options.new("ws://example.com", [],
               delivery: :ack,
               max_message_size: 16,
               max_queue_bytes: 22
             )

    assert {:error, :invalid_headers} =
             Options.new("ws://example.com", [], headers: [{"bad\r\nname", "x"}])

    assert {:error, :invalid_headers} =
             Options.new("ws://example.com", [], headers: [{"x", "bad\r\nvalue"}])

    assert {:error, :invalid_url} = Options.new("ws://user:password@example.com")
    assert {:error, :invalid_url} = Options.new(%URI{scheme: "ws", host: "", port: 0})
    assert {:error, :invalid_options} = Options.new("ws://example.com", [], ["bad"])
  end

  test "builds extended CONNECT with normalized origin and no HTTP1 fields" do
    assert {:ok, request} =
             Handshake.extended_connect_request(
               URI.parse("wss://example.com/chat?q=1"),
               ["chat"],
               [{"authorization", "token"}]
             )

    assert request.method == :connect
    assert request.url.scheme == "https"
    assert request.url.path == "/chat"
    assert HTTP.Headers.get(request.headers, "sec-websocket-version") == "13"
    assert HTTP.Headers.get(request.headers, "sec-websocket-protocol") == "chat"
    assert HTTP.Headers.get(request.headers, "authorization") == "token"

    for name <- [
          "connection",
          "upgrade",
          "host",
          "keep-alive",
          "proxy-connection",
          "transfer-encoding",
          "sec-websocket-key",
          "sec-websocket-accept",
          "sec-websocket-version",
          "sec-websocket-protocol",
          ":path"
        ] do
      assert {:error, :invalid_extended_connect_headers} =
               Handshake.extended_connect_request(URI.parse("ws://example.com"), [], [{name, "x"}])
    end
  end

  test "validates CONNECT 2xx separately from HTTP1 Upgrade and rejects selections" do
    assert {:ok, %{protocol: "chat", extensions: ""}} =
             Handshake.validate_extended_response(200, [{"sec-websocket-protocol", "chat"}], [
               "chat"
             ])

    assert {:ok, %{protocol: "", extensions: ""}} =
             Handshake.validate_extended_response(204, [], [])

    assert {:error, {:unexpected_status, 101}} = Handshake.validate_extended_response(101, [], [])

    assert {:error, :invalid_extended_connect_headers} =
             Handshake.validate_extended_response(200, [{"connection", "upgrade"}], [])

    assert {:error, :invalid_protocol_selection} =
             Handshake.validate_extended_response(
               200,
               [{"sec-websocket-protocol", "chat"}, {"sec-websocket-protocol", "chat"}],
               ["chat"]
             )

    assert {:error, :invalid_protocol_selection} =
             Handshake.validate_extended_response(
               200,
               [{"sec-websocket-protocol", "chat, other"}],
               ["chat"]
             )

    assert {:error, {:unexpected_protocol, "other"}} =
             Handshake.validate_extended_response(200, [{"sec-websocket-protocol", "other"}], [
               "chat"
             ])

    assert {:error, {:unsupported_extensions, "permessage-deflate"}} =
             Handshake.validate_extended_response(
               200,
               [{"sec-websocket-extensions", "permessage-deflate"}],
               []
             )
  end

  test "rejects oversized incomplete declared frames before buffering payload" do
    assert {:error, {1009, :message_too_big}} =
             Frame.parse(Frame.new_parser(max_message_size: 2), <<0x82, 3>>)

    assert {:error, {1009, :message_too_big}} =
             Frame.parse(Frame.new_parser(max_message_size: 128), <<0x82, 126, 256::16>>)

    assert {:error, {1002, :control_payload_too_large}} =
             Frame.parse(Frame.new_parser(), <<0x89, 126, 126::16>>)

    assert {:ok, parser, []} =
             Frame.parse(Frame.new_parser(max_message_size: 3), <<0x02, 2, "ab">>)

    assert {:error, {1009, :message_too_big}} = Frame.parse(parser, <<0x80, 2>>)
  end

  test "bounds empty fragments and rejects new data during fragmentation" do
    assert {:ok, parser, []} =
             Frame.parse(Frame.new_parser(max_frame_parts: 2), <<0x01, 0, 0x00, 0>>)

    assert {:error, {1009, :too_many_frame_parts}} = Frame.parse(parser, <<0x80, 0>>)
    assert {:ok, parser, []} = Frame.parse(Frame.new_parser(), <<0x01, 0>>)
    assert {:error, {1002, :fragment_already_started}} = Frame.parse(parser, <<0x81, 0>>)
    assert {:error, {1002, :fragment_already_started}} = Frame.parse(parser, <<0x82, 0>>)
  end

  test "parse_some commits one valid event before later malformed bytes" do
    assert {:ok, parser, [{:message, :text, "a"}], <<0x8B, 0>>} =
             Frame.parse_some(Frame.new_parser(), <<0x81, 1, "a", 0x8B, 0>>)

    assert parser.buffer == <<>>
    refute Frame.incomplete?(parser)
    assert {:error, {1002, :unknown_opcode}} = Frame.parse_some(parser, <<0x8B, 0>>)
    assert {:ok, parser, [], <<>>} = Frame.parse_some(parser, <<0x81, 2, "a">>)
    assert Frame.incomplete?(parser)

    assert {:ok, parser, [{:message, :text, "ab"}], <<0x89, 0>>} =
             Frame.parse_some(parser, <<"b", 0x89, 0>>)

    refute Frame.incomplete?(parser)
    assert {:ok, parser, [], <<>>} = Frame.parse_some(parser, <<0x01, 0>>)
    assert Frame.incomplete?(parser)
  end

  test "fragment buffers do not retain trailing wire ancestors" do
    padding = :binary.copy("z", 100_000)

    assert {:ok, parser, [{:ping, ""}], ^padding} =
             Frame.parse_some(
               Frame.new_parser(),
               <<0x01, 65, 0::size(65 * 8), 0x89, 0, padding::binary>>
             )

    [fragment] = parser.fragmented_chunks
    assert :binary.referenced_byte_size(fragment) == byte_size(fragment)
  end

  test "internal protocol close allows required codes without broadening public close" do
    for code <- [1002, 1007, 1009] do
      assert {:ok, <<^code::16, "error">>} = Frame.protocol_close_payload(code, "error")
      assert {:error, :invalid_close_code} = Frame.close_payload(code, "error")
    end

    for code <- [1004, 1005, 1006, 1015, 2000] do
      assert {:error, :invalid_close_code} = Frame.protocol_close_payload(code, "")
    end

    assert {:error, :invalid_close_reason} = Frame.protocol_close_payload(1002, <<255>>)

    assert {:error, :close_reason_too_long} =
             Frame.protocol_close_payload(1002, :binary.copy("a", 124))
  end
end
