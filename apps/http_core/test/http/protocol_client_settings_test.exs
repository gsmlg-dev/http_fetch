defmodule HTTP.ProtocolClientSettingsTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.Connection

  test "live local initial-window settings adjust existing receive credit only" do
    {:ok, connection, _} =
      Connection.update_local_settings(Connection.new(), initial_window_size: 1)

    {:ok, stream, connection} = Connection.open_stream(connection)
    {:ok, connection, _} = Connection.receive_data(connection, stream.id, 1)

    assert connection.streams[stream.id].receive_window == 0

    {:ok, connection, _} =
      Connection.update_local_settings(connection, initial_window_size: 65_535)

    assert connection.streams[stream.id].receive_window == 65_534
    assert connection.streams[stream.id].send_window == 65_535
    assert connection.connection_receive_window == 65_534
  end
end
