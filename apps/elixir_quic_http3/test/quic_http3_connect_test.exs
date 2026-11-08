defmodule QuicHttp3.ConnectTest do
  use ExUnit.Case, async: true
  alias QuicHttp3.{Connect, Control, Frame, Qpack, Response, Session}

  defmodule Transport do
    def open_stream(_, :bidi, _) do
      send(self(), :allocated)
      Process.get(:open_result, {:ok, :bidi})
    end

    def operation_status(_, _, _), do: Process.get(:operation_result, :unknown)
    def events(_, _, _), do: {:ok, [{:readable, :bidi}]}
    def read(_, _, _), do: {:ok, Process.delete(:items) || []}
    def send_stream(_, bytes, fin, _), do: send(self(), {:wire, bytes, fin}) && :ok
  end

  @fields [
    {":method", "CONNECT"},
    {":scheme", "https"},
    {":authority", "example.test"},
    {":path", "/ws"}
  ]

  test "settings readiness distinguishes waiting from definitive refusal" do
    {:ok, control} = Control.new(:client)
    assert :pending = Connect.ready(control)

    assert {:error, :extended_connect_not_supported} =
             Connect.ready(%{control | received_settings?: true, peer_settings: []})

    assert :ready = Connect.ready(%{control | received_settings?: true, peer_settings: [{8, 1}]})
  end

  test "CONNECT allocation waits for settings then keeps its upload open" do
    {:ok, session} = Session.new(transport: Transport)
    {:ok, control} = Control.new(:client)
    session = %{session | connection: :connection, control: control, open?: true}

    assert {:blocked, ^session, :peer_settings_pending} =
             Session.extended_connect(session, "websocket", @fields)

    assert {:error, ^session, :deadline_expired} =
             Session.extended_connect(session, "websocket", @fields,
               deadline: {:abs_ms, System.monotonic_time(:millisecond) - 1}
             )

    refute_received {:wire, _, _}
    control = %{control | received_settings?: true, peer_settings: [{8, 1}]}

    assert {:error, _, :webtransport_network_not_ready} =
             Session.extended_connect(%{session | control: control}, "webtransport-h3", @fields)

    assert {:ok, session, ref} =
             Session.extended_connect(%{session | control: control}, "websocket", @fields)

    assert session.requests[ref].upload == :open
    assert_received {:wire, bytes, false}
    assert {:ok, %{type: 1, payload: block}, <<>>} = Frame.decode(bytes)
    assert {:ok, fields} = Qpack.decode_header_block(block)
    assert {":protocol", "websocket"} in fields
    assert {:error, _, :tunnel_not_accepted} = Session.send_data(session, ref, "early", false, [])
    assert {:error, _, :tunnel_trailers_forbidden} = Session.send_trailers(session, ref, [], [])
  end

  test "remote tunnel FIN preserves local Close reply and retires only after both halves" do
    {:ok, session} = Session.new(transport: Transport)
    {:ok, control} = Control.new(:client)

    session = %{
      session
      | connection: :connection,
        control: %{control | received_settings?: true, peer_settings: [{8, 1}]},
        open?: true
    }

    {:ok, session, ref} = Session.extended_connect(session, "websocket", @fields)

    Process.put(:items, [
      {:data, headers([{":status", "200"}]) <> Frame.encode!(:data, "close")},
      {:fin}
    ])

    assert {:ok, session, [{:headers, ^ref, _}, {:data, ^ref, "close"}, {:done, ^ref}]} =
             Session.poll(session, 8)

    assert session.requests[ref].remote_fin?
    assert session.requests[ref].upload == :open
    assert {:ok, session} = Session.send_data(session, ref, "close-reply", true, [])
    assert session.requests == %{}
    assert_received {:wire, _, true}
  end

  test "unknown CONNECT allocation retains reference and cannot replay on reconciliation" do
    {:ok, session} = Session.new(transport: Transport)
    {:ok, control} = Control.new(:client)

    session = %{
      session
      | connection: :connection,
        control: %{control | received_settings?: true, peer_settings: [{8, 1}]},
        open?: true
    }

    operation = make_ref()
    Process.put(:open_result, {:unknown, operation})

    assert {:unknown, pending, ^operation} =
             Session.extended_connect(session, "websocket", @fields)

    assert_received :allocated
    original_deadline = pending.pending.deadline
    assert {:unknown, ^pending, ^operation} = Session.resume(pending)
    refute_received :allocated
    assert pending.pending.deadline == original_deadline
    Process.put(:operation_result, %{status: :admitted, result: {:ok, :bidi}})
    assert {:ok, ready, ref} = Session.resume(pending)
    assert ready.requests[ref].upload == :open
    refute_received :allocated
    assert_received {:wire, _, false}
  end

  test "ordinary requests cannot acquire extension semantics via protocol field" do
    {:ok, session} = Session.new()
    session = %{session | open?: true}

    assert {:error, _, :protocol_requires_extended_connect} =
             Session.request(session, [{":protocol", "websocket"}], "", [])
  end

  test "tunnel response ignores body length semantics without altering ordinary response" do
    bytes =
      headers([{":status", "204"}, {"content-length", "0"}]) <> Frame.encode!(:data, "close")

    assert {:ok, tunnel, [{:headers, 204, _}, {:data, "close"}]} =
             Response.feed(Response.new(purpose: :extended_connect), bytes)

    assert tunnel.phase == :tunnel
    assert {:ok, _, [:done]} = Response.finish(tunnel)

    assert {:error, {:http3_error, :stream, _, :content_length_forbidden}} =
             Response.feed(Response.new(), bytes)

    assert {:error, {:http3_error, :stream, _, :tunnel_trailers_forbidden}} =
             Response.feed(tunnel, headers([{"x-trailer", "no"}]))
  end

  test "informational and rejected responses retain normal HTTP semantics" do
    bytes =
      headers([{":status", "103"}]) <>
        headers([{":status", "403"}, {"content-length", "1"}]) <> Frame.encode!(:data, "x")

    assert {:ok, state, [{:informational, 103, []}, {:headers, 403, _}, {:data, "x"}]} =
             Response.feed(Response.new(purpose: :extended_connect), bytes)

    assert state.phase == :final
    assert {:ok, _, [:done]} = Response.finish(state)
  end

  test "invalid pseudo headers and HTTP1 fields fail explicitly" do
    for fields <- [
          @fields ++ [{"upgrade", "websocket"}],
          @fields ++ [{":protocol", "websocket"}],
          List.keydelete(@fields, ":path", 0)
        ] do
      assert {:error, _} = Connect.fields("websocket", fields)
    end
  end

  defp headers(fields) do
    {:ok, block} = Qpack.encode_header_block(fields)
    Frame.encode!(:headers, block)
  end
end
