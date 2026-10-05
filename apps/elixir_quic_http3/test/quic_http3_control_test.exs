defmodule QuicHttp3.ControlTest do
  use ExUnit.Case, async: true

  alias QuicHttp3.{Control, Frame, Settings, Varint}

  test "server MAX_PUSH_ID and unpermitted CANCEL_PUSH are connection errors" do
    {:ok, state} = Control.new(:client)
    {:ok, state, _} = Control.receive(state, 3, <<0>> <> Frame.encode!(:settings, <<>>))

    assert {:error, {:http3_error, :connection, 0x105, :forbidden_control_frame}} =
             Control.receive(state, 3, Frame.encode!(:max_push_id, <<0>>))

    assert {:error, {:http3_error, :connection, 0x108, :push_not_permitted}} =
             Control.receive(state, 3, Frame.encode!(:cancel_push, <<0>>))
  end

  test "opens a local control stream with a SETTINGS frame" do
    assert {:ok, state} = Control.new(:client)
    assert {:error, :control_stream_must_be_local} = Control.open(state, 3)
    assert {:ok, _opened, <<0, frame::binary>>} = Control.open(state, 2)
    assert {:ok, %{type: 4, payload: payload}, <<>>} = Frame.decode(frame)
    assert {:ok, _settings} = Settings.decode(payload)
  end

  test "buffers peer control bytes until the SETTINGS frame is complete" do
    assert {:ok, state} = Control.new(:client)
    settings = Frame.encode!(:settings, Settings.encode!(h3_datagram: 1))
    bytes = <<0>> <> settings

    assert {:ok, state, []} = Control.receive(state, 3, binary_part(bytes, 0, 1))

    assert {:ok, state, [{:settings, [{51, 1}]}]} =
             Control.receive(state, 3, binary_part(bytes, 1, byte_size(bytes) - 1))

    assert state.received_settings?
  end

  test "buffers a split peer stream type and rejects a second peer control stream" do
    assert {:ok, state} = Control.new(:client)
    assert {:ok, state1, []} = Control.receive(state, 3, <<0x40>>)
    assert {:error, :duplicate_peer_control_stream} = Control.receive(state1, 7, <<0x01>>)
    assert {:error, :invalid_peer_control_stream_type} = Control.receive(state1, 3, <<0x01>>)

    assert {:ok, state2} = Control.new(:client)
    assert {:error, :control_stream_must_be_peer_owned} = Control.receive(state2, 2, <<0>>)
    bytes = <<0>> <> Frame.encode!(:settings, Settings.encode!([]))
    assert {:ok, state3, [{:settings, []}]} = Control.receive(state2, 3, bytes)
    assert {:error, :duplicate_peer_control_stream} = Control.receive(state3, 7, bytes)
  end

  test "rejects duplicate SETTINGS and forbidden control frames" do
    assert {:ok, state} = Control.new(:client)
    settings = <<0>> <> Frame.encode!(:settings, Settings.encode!([]))
    assert {:ok, state, [{:settings, []}]} = Control.receive(state, 3, settings)

    assert {:error, :duplicate_settings} =
             Control.receive(state, 3, Frame.encode!(:settings, <<>>))

    assert {:ok, fresh} = Control.new(:client)
    assert {:error, :settings_must_be_first} = Control.receive(fresh, 3, <<0, 0, 0>>)
  end

  test "emits GOAWAY after SETTINGS" do
    assert {:ok, state} = Control.new(:client)
    settings = <<0>> <> Frame.encode!(:settings, Settings.encode!([]))
    assert {:ok, state, [{:settings, []}]} = Control.receive(state, 3, settings)

    goaway = Frame.encode!(:goaway, Varint.encode!(8))
    assert {:ok, next, [{:goaway, 8}]} = Control.receive(state, 3, goaway)
    assert next.goaway_id == 8

    assert {:ok, next, [{:goaway, 4}]} =
             Control.receive(next, 3, Frame.encode!(:goaway, Varint.encode!(4)))

    assert {:error, :increasing_goaway} = Control.receive(next, 3, goaway)

    assert {:error, :invalid_goaway} =
             Control.receive(state, 3, Frame.encode!(:goaway, Varint.encode!(7)))
  end

  test "initial profile advertises useful headers with dynamic QPACK disabled" do
    assert {:ok, state} = Control.new(:client)
    <<0, bytes::binary>> = Control.local_payload(state)
    {:ok, %{payload: payload}, <<>>} = Frame.decode(bytes)
    {:ok, settings} = Settings.decode(payload)
    assert {1, 0} in settings
    assert {7, 0} in settings
    assert {6, 65_536} in settings
  end

  test "oversized declared control frames fail before buffering their payload" do
    {:ok, state} = Control.new(:client)

    assert {:error, :control_frame_too_large} =
             Control.receive(state, 3, <<0>> <> Varint.encode!(4) <> Varint.encode!(65_537))
  end
end
