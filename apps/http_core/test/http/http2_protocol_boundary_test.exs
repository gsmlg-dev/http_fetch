defmodule HTTP.HTTP2.ProtocolBoundaryTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP2.{Boundary, Frame}

  defp frame(type, id, payload, flags \\ 0),
    do: %Frame{type: type, stream_id: id, payload: payload, flags: flags}

  test "rejects an oversized declared length before collecting its payload" do
    assert {:error, :frame_size_error} = Boundary.decode(<<16_385::24, 0, 0, 0::32>>, 16_384)
  end

  test "requires first peer frame to be non-ACK SETTINGS" do
    assert {:error, :expected_settings} =
             Boundary.validate(frame(:ping, 0, <<0::64>>), false, nil)

    assert {:error, :expected_settings} =
             Boundary.validate(frame(:settings, 0, <<>>, 1), false, nil)

    assert :ok = Boundary.validate(frame(:settings, 0, <<>>), false, nil)
  end

  test "continuation lock precedes every control and extension frame" do
    for type <- [:settings, :ping, :goaway, :window_update, 99] do
      assert {:error, :expected_continuation} =
               Boundary.validate(frame(type, 0, <<>>), true, 1)
    end

    assert :ok = Boundary.validate(frame(:continuation, 1, <<>>, 4), true, 1)

    assert {:error, :expected_continuation} =
             Boundary.validate(frame(:continuation, 3, <<>>), true, 1)
  end

  test "validates fixed frame lengths and stream identifiers" do
    for {type, id, payload} <- [
          {:ping, 0, <<0>>},
          {:rst_stream, 1, <<0>>},
          {:priority, 1, <<0>>},
          {:window_update, 0, <<0>>}
        ] do
      assert {:error, :frame_size_error} = Boundary.validate(frame(type, id, payload), true, nil)
    end

    for f <- [
          frame(:ping, 1, <<0::64>>),
          frame(:settings, 1, <<>>),
          frame(:goaway, 1, <<0::64>>),
          frame(:data, 0, <<>>),
          frame(:headers, 0, <<>>),
          frame(:rst_stream, 0, <<0::32>>)
        ] do
      assert {:error, :protocol_error} = Boundary.validate(f, true, nil)
    end

    assert {:error, :frame_size_error} =
             Boundary.validate(frame(:settings, 0, <<0::48>>, 1), true, nil)
  end

  test "strips padding and priority without treating reserved dependency bit as ID" do
    assert {:ok, "ok", 6} = Boundary.data_payload(frame(:data, 1, <<3, "ok", 0, 0, 0>>, 8))

    assert {:ok, <<0x88>>} =
             Boundary.header_payload(frame(:headers, 1, <<2, 1::1, 0::31, 15, 0x88, 0, 0>>, 0x28))

    assert {:error, :protocol_error} = Boundary.data_payload(frame(:data, 1, <<2, 0>>, 8))

    assert {:error, :protocol_error} =
             Boundary.header_payload(frame(:headers, 1, <<0::1, 1::31, 15>>, 0x20))
  end
end
