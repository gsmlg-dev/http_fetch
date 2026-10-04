defmodule Quic.Phase1StreamPropertyTest do
  use ExUnit.Case, async: true
  alias Quic.Streams

  test "seeded frame reorder, duplicates and different boundaries preserve one ordered byte stream" do
    :rand.seed(:exsss, {28, 9, 2026})
    payload = :binary.list_to_bin(Enum.to_list(0..255))

    for {receiver, id} <- [server: 0, client: 1, server: 2, client: 3], _ <- 1..25 do
      base =
        for offset <- 0..15 do
          %{
            type: :stream,
            stream_id: id,
            offset: offset * 16,
            data: binary_part(payload, offset * 16, 16),
            fin: offset == 15
          }
        end

      overlap =
        for offset <- [5, 23, 39, 101, 175],
            do: %{
              type: :stream,
              stream_id: id,
              offset: offset,
              data: binary_part(payload, offset, 47),
              fin: false
            }

      frames =
        Enum.shuffle(
          base ++
            base ++
            overlap ++ [%{type: :stream, stream_id: id, offset: 256, data: <<>>, fin: true}]
        )

      {state, events} =
        Enum.reduce(frames, {Streams.new(receiver), []}, fn frame, {state, events} ->
          assert {:ok, state, delivered} = Streams.receive(state, frame)
          {state, events ++ delivered}
        end)

      assert IO.iodata_to_binary(for {:data, ^id, bytes} <- events, do: bytes) == payload
      assert Enum.count(events, &(&1 == {:fin, id})) == 1
      assert state.data_received == 256
      assert state.streams[id].recv_chunks == %{}
    end
  end
end
