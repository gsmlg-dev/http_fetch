defmodule Quic.Phase1ConsumerTest do
  use ExUnit.Case, async: true

  alias Quic.Runtime.{ConnectionHandle, StreamHandle}

  test "public handles retain opaque pid, generation, and stream identity" do
    Code.ensure_loaded!(Quic)
    connection = %ConnectionHandle{id: self(), generation: make_ref()}
    stream = %StreamHandle{connection: connection, id: 4}

    assert stream.connection == connection
    assert stream.id == 4
    assert function_exported?(Quic, :events, 2)
    assert function_exported?(Quic, :operation_status, 2)
  end
end
