defmodule HTTP.HTTP2.CreditInvariantTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP2.Connection

  test "seeded interleaved consumption conserves credit and leaves no historical streams" do
    :rand.seed(:exsss, {9113, 7541, 2026})
    initial = 65_535
    conn = Connection.new(receive_window: initial)

    conn =
      Enum.reduce(1..100, conn, fn request, conn ->
        assert {:ok, stream, conn} = Connection.open_stream(conn)
        assert stream.id == request * 2 - 1

        {conn, pending} =
          Enum.reduce(1..100, {conn, 0}, fn _, {conn, pending} ->
            {conn, pending} =
              if pending > 0 and :rand.uniform(3) == 1 do
                bytes = :rand.uniform(pending)
                assert {:ok, conn, _effects} = Connection.acknowledge_data(conn, stream.id, bytes)
                {conn, pending - bytes}
              else
                bytes = min(:rand.uniform(2048), initial - pending)
                assert {:ok, conn, []} = Connection.receive_data(conn, stream.id, bytes)
                {conn, pending + bytes}
              end

            assert conn.connection_receive_window + pending == initial
            assert conn.connection_unacknowledged == pending
            assert conn.streams[stream.id].receive_window + pending == initial
            assert conn.streams[stream.id].unacknowledged == pending

            assert {:error, :invalid_acknowledgement} =
                     Connection.acknowledge_data(conn, stream.id, pending + 1)

            {conn, pending}
          end)

        assert {:ok, conn, _effects} = Connection.acknowledge_data(conn, stream.id, pending)
        conn = Connection.remove_stream(conn, stream.id)
        assert conn.connection_receive_window == initial
        assert conn.connection_unacknowledged == 0
        assert conn.streams == %{}
        assert conn.pending_headers == %{}
        assert conn.priorities == %{}
        conn
      end)

    assert conn.next_stream_id == 201
  end
end
