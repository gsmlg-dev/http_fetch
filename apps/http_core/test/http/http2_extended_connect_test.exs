defmodule HTTP.HTTP2.ExtendedConnectTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{Connection, Settings, StreamState, WireProfile}

  test "setting 8 is directional, defaults disabled, and cannot reverse even within one frame" do
    assert Settings.defaults().enable_connect_protocol == 0
    assert Settings.id(:enable_connect_protocol) == 8
    assert Settings.key(8) == :enable_connect_protocol
    assert {:ok, <<8::16, 1::32>>} = Settings.encode(enable_connect_protocol: 1)
    assert {:ok, [enable_connect_protocol: 1]} = Settings.decode(<<8::16, 1::32>>)

    for value <- [0, 1] do
      assert {:ok, _, _} = Settings.apply_peer(Settings.new(), [{8, value}])
    end

    assert {:error, :invalid_enable_connect_protocol} = Settings.validate([{8, 2}])

    assert {:error, :enable_connect_protocol_reversed} =
             Settings.apply_peer(Settings.new(), [{8, 1}, {:enable_connect_protocol, 0}])

    {:ok, enabled, _} = Settings.apply_peer(Settings.new(), [{8, 1}])
    assert {:error, :enable_connect_protocol_reversed} = Settings.apply_peer(enabled, [{8, 0}])
    assert {:ok, _, _} = Settings.apply_peer(enabled, [])
    {:ok, local} = Settings.begin_local(Settings.new(), [{8, 1}])
    assert {:error, :enable_connect_protocol_reversed} = Settings.begin_local(local, [{8, 0}])

    assert {:error, :enable_connect_protocol_reversed} =
             Settings.begin_local(Settings.new(), [{8, 1}, {8, 0}])
  end

  test "local advertisement never grants peer permission and delayed permission opens only later" do
    conn = Connection.new()
    assert {:ok, stream, _} = Connection.open_stream(conn)
    assert stream.purpose == :request
    assert {:error, :invalid_stream_purpose} = Connection.open_stream(conn, purpose: :unknown)

    assert {:error, :extended_connect_not_supported} =
             Connection.open_stream(conn, purpose: :extended_connect)

    {:ok, local, _} = Connection.update_local_settings(conn, [{8, 1}])

    assert {:error, :extended_connect_not_supported} =
             Connection.open_stream(local, purpose: :extended_connect)

    {:ok, conn, _} = Connection.update_peer_settings(local, [{8, 0}])

    assert {:error, :extended_connect_not_supported} =
             Connection.open_stream(conn, purpose: :extended_connect)

    {:ok, conn, _} = Connection.update_peer_settings(conn, [{8, 1}])

    assert {:error, :invalid_enable_connect_protocol} =
             Connection.update_peer_settings(conn, [{8, 2}])

    assert {:error, :enable_connect_protocol_reversed} =
             Connection.update_peer_settings(conn, [{8, 0}])

    assert {:ok, stream, _} = Connection.open_stream(conn, purpose: :extended_connect)
    assert stream.purpose == :extended_connect
  end

  test "all successful 2xx responses establish duplex tunnels without body framing rules" do
    for status <- ["200", "204", "299"] do
      {conn, stream} = opening()

      assert {:error, :extended_connect_not_established} =
               Connection.send_data(conn, stream.id, "ws")

      assert {:error, :extended_connect_not_established} = StreamState.send_data(stream, 0, true)
      refute StreamState.sendable?(stream)

      assert {:ok, tunnel, :final} =
               StreamState.receive_response_headers(
                 stream,
                 [{":status", status}, {"content-length", "nonsense"}],
                 false
               )

      assert tunnel.response_phase == :tunnel
      assert tunnel.expected_content_length == nil
      assert StreamState.sendable?(tunnel)
      assert {:ok, tunnel} = StreamState.receive_response_data(tunnel, 70_000, false)
      assert {:ok, _} = StreamState.send_data(tunnel, 12, false)

      assert {:error, :invalid_headers_transition} =
               StreamState.receive_response_headers(tunnel, [], true)
    end
  end

  test "rejected CONNECT retains ordinary response bounds and disallows tunnel writes" do
    {_conn, stream} = opening()

    assert {:error, :invalid_response_headers} =
             StreamState.receive_response_headers(stream, [{":status", "101"}], false)

    assert {:ok, rejected, :final} =
             StreamState.receive_response_headers(
               stream,
               [{":status", "403"}, {"content-length", "3"}],
               false
             )

    assert rejected.response_phase == :body
    assert {:error, :extended_connect_not_established} = StreamState.send_data(rejected, 1)

    assert {:error, :content_length_mismatch} =
             StreamState.receive_response_data(rejected, 4, true)

    assert {:ok, complete} = StreamState.receive_response_data(rejected, 3, true)
    assert complete.response_phase == :complete
  end

  test "tunnels retain flow control, SETTINGS shrink/resume and independent half-close" do
    {conn, stream} = opening()

    {:ok, tunnel, :final} =
      StreamState.receive_response_headers(stream, [{":status", "200"}], false)

    conn = Connection.put_stream(conn, tunnel)
    data = :binary.copy("x", 65_535)
    assert {:ok, conn, _} = Connection.send_data(conn, stream.id, data)
    assert {:error, :flow_control_blocked} = Connection.send_data(conn, stream.id, "x")
    assert {:ok, conn, _} = Connection.update_peer_settings(conn, initial_window_size: 0)
    assert conn.streams[stream.id].send_window == -65_535
    assert {:ok, conn, _} = Connection.update_send_window(conn, stream.id, 65_536)
    assert {:ok, conn, _} = Connection.update_send_window(conn, 0, 1)
    assert {:ok, conn, _} = Connection.send_data(conn, stream.id, "x")
    assert {:ok, conn, _} = Connection.receive_data(conn, stream.id, 65_535)
    assert {:error, :flow_control_error} = Connection.receive_data(conn, stream.id, 1)
    assert {:ok, conn, _} = Connection.acknowledge_data(conn, stream.id, 65_535)
    assert {:ok, conn, _} = Connection.receive_data(conn, stream.id, 1, true)
    remote_closed = conn.streams[stream.id]
    assert remote_closed.state == :half_closed_remote
    assert {:ok, remote_closed} = StreamState.receive_response_data(remote_closed, 1, true)
    assert remote_closed.response_phase == :tunnel
    assert {:ok, closed} = StreamState.send_data(remote_closed, 0, true)
    assert closed.state == :closed

    {:ok, local_closed} = StreamState.send_data(tunnel, 0, true)
    assert local_closed.state == :half_closed_local
    assert {:ok, closed} = StreamState.receive_data(local_closed, 1, true)
    assert closed.state == :closed
  end

  test "dedicated CONNECT headers map WebSocket URIs and avoid HTTP/1 handshake fields" do
    for {scheme, expected} <- [{"ws", "http"}, {"wss", "https"}] do
      request = request(scheme)
      assert {:ok, headers, ""} = HTTP.HTTP2.extended_connect_headers(request, :native_v1)

      assert Enum.take(headers, 5) == [
               {":method", "CONNECT"},
               {":protocol", "websocket"},
               {":scheme", expected},
               {":authority", "example.test:8080"},
               {":path", "/chat?q=1"}
             ]

      assert {"sec-websocket-version", "13"} in headers
      assert {"origin", "https://origin.test"} in headers

      refute Enum.any?(
               headers,
               &(elem(&1, 0) in [
                   "host",
                   "connection",
                   "upgrade",
                   "sec-websocket-key",
                   "sec-websocket-accept",
                   "content-length"
                 ])
             )
    end
  end

  test "CONNECT rejects bodies, caller pseudo-fields and forbidden handshake fields" do
    request = request("wss")

    assert {:error, :extended_connect_body_not_supported} =
             HTTP.HTTP2.extended_connect_headers(%{request | body: "body"}, :native_v1)

    assert {:error, :invalid_profile} =
             HTTP.HTTP2.extended_connect_headers(request, :missing_profile)

    for name <- [
          ":protocol",
          "Connection",
          "Upgrade",
          "Sec-WebSocket-Key",
          "Sec-WebSocket-Accept",
          "Transfer-Encoding",
          "content-length"
        ] do
      assert {:error, {:invalid_extended_connect_header, _}} =
               HTTP.HTTP2.extended_connect_headers(
                 %{request | headers: HTTP.Headers.new([{name, "x"}])},
                 :native_v1
               )
    end

    for {name, value} <- [{"bad name", "x"}, {"x-safe", "injected\r\n"}, {"te", "gzip"}] do
      assert {:error, {:invalid_extended_connect_header, _}} =
               HTTP.HTTP2.extended_connect_headers(
                 %{request | headers: HTTP.Headers.new([{name, value}])},
                 :native_v1
               )
    end
  end

  test "invalid CONNECT URLs fail with typed errors before serialization" do
    request = request("wss")

    for url <- [
          nil,
          URI.parse("ftp://example.test/chat"),
          %{request.url | path: "/bad target"},
          %{request.url | port: 65_536},
          %{request.url | host: "bad\rhost"},
          %{request.url | fragment: "fragment"},
          %{request.url | userinfo: "user:password"}
        ] do
      assert {:error, :invalid_extended_connect_url} =
               HTTP.HTTP2.extended_connect_headers(%{request | url: url}, :native_v1)
    end
  end

  test "explicit tunnel header order preserves profile order and one regular sort" do
    request = request("wss")

    for profile <- [
          WireProfile.native_v1(),
          WireProfile.synthetic_test_v1(),
          WireProfile.synthetic_test_v2()
        ] do
      assert {:ok, raw, ""} = HTTP.HTTP2.extended_connect_headers(request, profile, order?: false)
      {pseudo, regular} = Enum.split_with(raw, &String.starts_with?(elem(&1, 0), ":"))
      assert {:ok, ordered, ""} = HTTP.HTTP2.extended_connect_headers(request, profile)
      assert ordered == WireProfile.order_headers(profile, pseudo, regular, :extended_connect)
      names = Enum.take(ordered, 5) |> Enum.map(&elem(&1, 0))

      assert names ==
               Enum.flat_map(profile.pseudo_headers, fn
                 ":method" -> [":method", ":protocol"]
                 name -> [name]
               end)

      ordinary = Enum.reject(pseudo, &(elem(&1, 0) == ":protocol"))

      assert WireProfile.order_headers(profile, ordinary, regular) ==
               WireProfile.order_headers(profile, ordinary, regular, :request)
    end
  end

  defp opening do
    {:ok, conn, _} = Connection.update_peer_settings(Connection.new(), [{8, 1}])

    {:ok, stream, conn} =
      Connection.open_stream(conn, purpose: :extended_connect, request_method: :connect)

    {:ok, conn, _} =
      Connection.commit_headers(conn, stream.id, [{":method", "CONNECT"}], end_stream: false)

    {conn, conn.streams[stream.id]}
  end

  defp request(scheme) do
    %HTTP.Request{
      url: URI.parse("#{scheme}://example.test:8080/chat?q=1"),
      headers:
        HTTP.Headers.new([
          {"Sec-WebSocket-Version", "13"},
          {"Origin", "https://origin.test"},
          {"x-first", "1"},
          {"x-second", "2"}
        ])
    }
  end
end
