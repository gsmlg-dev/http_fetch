defmodule HTTP.HTTP2.SettingsAckTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP2.Settings

  test "multiple local SETTINGS acknowledgements apply FIFO snapshots" do
    {:ok, state} = Settings.begin_local(Settings.new(), header_table_size: 0)
    {:ok, state} = Settings.begin_local(state, header_table_size: 128)
    assert {:ok, state} = Settings.ack(state)
    assert state.pending_ack?
    assert state.acknowledged_values.header_table_size == 0
    assert {:ok, state} = Settings.ack(state)
    refute state.pending_ack?
    assert state.acknowledged_values.header_table_size == 128
    assert {:error, :unexpected_settings_ack} = Settings.ack(state)
  end
end
