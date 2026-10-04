defmodule Quic.CodecTest do
  use ExUnit.Case, async: true

  test "NEW_CONNECTION_ID and RETIRE_CONNECTION_ID preserve their bounded wire fields" do
    frame = %{
      type: :new_connection_id,
      sequence: 1,
      retire_prior_to: 0,
      cid: <<9, 8>>,
      token: <<1::128>>
    }

    wire = <<0x18, 1, 0, 2, 9, 8, 1::128, 0x19, 1>>
    frames = [frame, %{type: :retire_connection_id, sequence: 1}]
    assert {:ok, ^wire} = Quic.Codec.encode_frames(frames)
    assert {:ok, ^frames, <<>>} = Quic.Codec.decode_frames(wire)

    assert {:error, :malformed_new_connection_id} =
             Quic.Codec.decode_frames(<<0x18, 1, 0, 0, 0::128>>)

    assert {:error, :malformed_new_connection_id} =
             Quic.Codec.decode_frames(<<0x18, 1, 0, 21, 0::296>>)
  end

  test "packet reconstruction retains epoch high bits across gaps and windows" do
    assert {:ok, 4} = Quic.Codec.reconstruct_packet_number(4, 1, 1)
    assert {:ok, 0x204} = Quic.Codec.reconstruct_packet_number(4, 0x201, 1)
  end

  test "varint boundaries and truncation" do
    for value <- [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, 0x3FFF_FFFF_FFFF_FFFF] do
      assert {:ok, encoded} = Quic.Codec.encode_varint(value)
      assert {:ok, ^value, <<>>} = Quic.Codec.decode_varint(encoded)
    end

    assert {:error, :varint_overflow} = Quic.Codec.encode_varint(0x4000_0000_0000_0000)
    assert {:error, :truncated_varint} = Quic.Codec.decode_varint(<<0x40>>)
  end

  test "Initial header builds and parses, while unknown versions are rejected" do
    fields = %{
      version: 1,
      dcid: <<1, 2>>,
      scid: <<3, 4>>,
      token: <<5>>,
      packet_number: 0x1234,
      packet_number_length: 2,
      payload: <<1, 2, 3>>
    }

    assert {:ok, packet} = Quic.Codec.build_initial(fields)
    assert {:ok, parsed} = Quic.Codec.parse_initial(packet <> <<9, 9>>)
    assert parsed.dcid == fields.dcid
    assert parsed.scid == fields.scid
    assert parsed.token == fields.token
    assert parsed.packet_number == fields.packet_number
    assert parsed.payload == fields.payload
    assert parsed.trailing == <<9, 9>>
    <<first, _version::32, rest::binary>> = packet
    unknown = <<first, 2::32, rest::binary>>
    assert {:error, :unsupported_version} = Quic.Codec.parse_initial(unknown)

    <<first, version::32, rest::binary>> = packet

    assert {:error, :invalid_header_fixed_bit} =
             Quic.Codec.parse_initial(<<Bitwise.band(first, 0xBF), version::32, rest::binary>>)
  end

  test "Initial parser rejects non-Initial packet types and impossible CID lengths" do
    fields = %{
      dcid: <<1>>,
      scid: <<2>>,
      packet_number: 0,
      packet_number_length: 1,
      payload: <<0>>
    }

    assert {:ok, packet} = Quic.Codec.build_initial(fields)
    <<_first, version::32, rest::binary>> = packet

    assert {:error, :not_initial} =
             Quic.Codec.parse_initial(<<0xD0, version::32, rest::binary>>)

    assert {:error, :invalid_connection_id} =
             Quic.Codec.parse_initial(<<0xC0, version::32, 21, 0::168>>)
  end

  test "coalesced datagram boundaries are length bounded" do
    fields = %{
      dcid: <<1>>,
      scid: <<2>>,
      packet_number: 1,
      packet_number_length: 1,
      payload: <<7>>
    }

    assert {:ok, one} = Quic.Codec.build_initial(fields)
    assert {:ok, two} = Quic.Codec.build_initial(%{fields | packet_number: 2})
    assert {:ok, [^one, ^two]} = Quic.Codec.split_datagram(one <> two)

    assert {:error, :truncated_payload} =
             Quic.Codec.split_datagram(binary_part(one, 0, byte_size(one) - 1))
  end

  test "packet number reconstruction selects the closest epoch" do
    assert {:ok, 0x100} = Quic.Codec.reconstruct_packet_number(0, 0xFF, 1)
    assert {:ok, 0xFF} = Quic.Codec.reconstruct_packet_number(0xFF, 0x100, 1)
    assert {:error, :invalid_packet_number} = Quic.Codec.reconstruct_packet_number(256, 0, 1)
  end

  test "encodes and decodes ACK ranges with independent wire bytes" do
    frame = %{type: :ack, largest: 10, delay: 1, ranges: [{8, 10}, {4, 5}]}
    expected = <<2, 10, 1, 1, 2, 1, 1>>

    assert {:ok, ^expected} = Quic.Codec.encode_frames([frame])
    assert {:ok, [^frame], <<>>} = Quic.Codec.decode_frames(expected)
    assert {:error, :malformed_ack_frame} = Quic.Codec.decode_frames(<<2, 10, 1, 1, 2, 1>>)

    assert {:error, :invalid_ack_ranges} =
             Quic.Codec.encode_frames([%{frame | ranges: [{8, 10}, {7, 7}]}])
  end

  test "encodes and decodes close and handshake control frames" do
    frames = [
      %{type: :connection_close, error_code: 16, frame_type: 6, reason: "bad"},
      %{type: :application_close, error_code: 42, reason: "done"},
      %{type: :handshake_done}
    ]

    expected = <<0x1C, 16, 6, 3, "bad", 0x1D, 42, 4, "done", 0x1E>>
    assert {:ok, ^expected} = Quic.Codec.encode_frames(frames)
    assert {:ok, ^frames, <<>>} = Quic.Codec.decode_frames(expected)
    assert {:error, :malformed_connection_close} = Quic.Codec.decode_frames(<<0x1D, 42, 4, "do">>)

    long_reason = :binary.copy(<<0>>, 1025)

    assert {:error, :reason_too_large} =
             Quic.Codec.encode_frames([
               %{type: :application_close, error_code: 1, reason: long_reason}
             ])
  end

  test "encodes and decodes stream and flow-control frames with bounded fields" do
    frames = [
      %{type: :stream, stream_id: 4, offset: 3, data: "abc", fin: true},
      %{type: :reset_stream, stream_id: 4, error_code: 7, final_size: 6},
      %{type: :stop_sending, stream_id: 4, error_code: 8},
      %{type: :max_data, value: 100},
      %{type: :max_stream_data, stream_id: 4, value: 50},
      %{type: :max_streams_bidi, value: 2},
      %{type: :max_streams_uni, value: 3}
    ]

    assert {:ok, wire} = Quic.Codec.encode_frames(frames)
    assert {:ok, ^frames, <<>>} = Quic.Codec.decode_frames(wire)
    assert {:error, :malformed_stream_frame} = Quic.Codec.decode_frames(<<0x0E, 4, 3, 4, "a">>)
  end
end
