defmodule Quic.Phase1StreamLifecycleTest do
  use ExUnit.Case, async: true
  alias Quic.Streams

  test "a reset after delivered FIN checks final size without emitting another terminal" do
    state = Streams.new(:client)

    {:ok, state, [{:data, 1, "a"}, {:fin, 1}]} =
      Streams.receive(state, %{type: :stream, stream_id: 1, offset: 0, data: "a", fin: true})

    assert {:ok, _, []} = Streams.receive_reset(state, 1, 9, 1)
    assert {:error, :final_size_error} = Streams.receive_reset(state, 1, 9, 2)
  end

  test "reading a nonexistent stream fails explicitly" do
    assert {:error, :unknown_stream} =
             Streams.consume(Streams.new(:client, delivery: :manual), 99, 1)
  end
end
