defmodule QuicHttp3.WebTransportRouterTest do
  use ExUnit.Case, async: true
  alias HTTP.H3.{Datagram, WebTransport.Draft17}
  alias QuicHttp3.WebTransportRouter, as: Router

  test "reordered streams and datagrams wait for CONNECT acceptance and retain shared credit" do
    {:ok, state} = Router.new(max_bytes: 16)
    {:ok, state} = Router.register(state, 4)
    {:ok, prefix} = Draft17.prefix(:bidi, 4)
    <<first, rest::binary>> = prefix
    assert {:ok, state, []} = Router.stream_data(state, :stream, :bidi, <<first>>, false)
    assert state.retained_bytes == 1
    assert {:ok, state, []} = Router.stream_data(state, :stream, :bidi, rest <> "abc", true)
    {:ok, wire} = Datagram.encode(4, "dg", 1200)
    assert {:ok, state, []} = Router.datagram(state, wire)
    assert state.retained_bytes == 5

    assert {:ok, state,
            [{r1, {:stream, 4, :stream, :bidi, "abc", true}}, {r2, {:datagram, 4, "dg"}}]} =
             Router.accept(state, 4)

    assert {:ok, state} = Router.acknowledge(state, r1)
    assert state.retained_bytes == 2
    assert {:error, :unknown_receipt} = Router.acknowledge(state, r1)
    assert {:ok, state} = Router.acknowledge(state, r2)
    assert state.retained_bytes == 0
  end

  test "stream/item/byte overflow resets only excess streams and drops whole datagrams" do
    {:ok, state} = Router.new(max_bytes: 4, max_items: 1, max_streams: 1)
    {:ok, state} = Router.register(state, 0)
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    assert {:ok, state, []} = Router.stream_data(state, :one, :uni, prefix <> "1234", false)

    assert {:ok, ^state, [{:reset, :two, 0x3994BD84}]} =
             Router.stream_data(state, :two, :uni, prefix, false)

    {:ok, wire} = Datagram.encode(0, "x", 1200)
    assert {:ok, ^state, []} = Router.datagram(state, wire)
    assert {:ok, state, [{:reset, :one, 0x170D7B68}]} = Router.close(state, 0)
    assert state.retained_bytes == 0
    assert {:ok, ^state, []} = Router.close(state, 0)
    assert {:ok, ^state, []} = Router.datagram(state, wire)
    assert {:error, :session_capacity} = Router.register(state, 4)
  end

  test "malformed IDs, truncated prefixes and unknown receipts fail explicitly" do
    {:ok, state} = Router.new()
    assert {:error, :invalid_session_id} = Router.register(state, 1)
    {:ok, state} = Router.register(state, 0)

    assert {:error, :invalid_session_id} =
             Router.stream_data(state, :bad, :uni, <<0x40, 0x54, 1>>, false)

    assert {:error, :truncated_webtransport_prefix} =
             Router.stream_data(state, :bad, :uni, <<0x40>>, true)

    assert {:error, :unknown_receipt} = Router.acknowledge(state, make_ref())
  end

  test "local streams need no prefix, FIN and reset release entries, resets carry no receipt" do
    {:ok, state} = Router.new(max_streams: 1)
    assert {:error, :session_not_accepted} = Router.local_stream(state, 0, :bidi)
    {:ok, state} = Router.register(state, 0)
    {:ok, state, []} = Router.accept(state, 0)
    {:ok, state} = Router.local_stream(state, 4, :bidi)
    assert {:error, :duplicate_stream} = Router.local_stream(state, 4, :bidi)

    assert {:ok, state, [{r1, {:stream, 0, 4, :bidi, "echo", true}}]} =
             Router.stream_data(state, 4, :bidi, "echo", true)

    refute Map.has_key?(state.streams, 4)
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    {:ok, state, [_]} = Router.stream_data(state, 3, :uni, prefix <> "a", false)
    assert {:ok, state, [{nil, {:reset, 0, 3, 42}}]} = Router.reset(state, 3, 42)
    assert {:ok, ^state, []} = Router.reset(state, 3, 42)

    {:ok, state, []} = Router.stream_data(state, 7, :uni, binary_part(prefix, 0, 1), false)
    # "echo" and "a" stay charged until acknowledged; one buffered prefix byte.
    assert state.retained_bytes == 6
    state = Router.forget(state, 7)
    assert state.retained_bytes == 5
    assert {:ok, _} = Router.acknowledge(state, r1)
  end
end
