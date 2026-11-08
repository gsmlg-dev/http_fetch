defmodule QuicHttp3.QpackDynamicTest do
  use ExUnit.Case, async: true

  alias QuicHttp3.{Frame, Qpack, Response}

  defp hex(value), do: Base.decode16!(value, case: :lower)

  describe "RFC 9204 Appendix B" do
    test "B.1 literal field line with static name reference" do
      table = Qpack.new(max_capacity: 220)

      assert {:ok, [{":path", "/index.html"}], 0} =
               Qpack.decode_field_section(hex("0000510b2f696e6465782e68746d6c"), table)
    end

    test "B.2 to B.5 dynamic table, duplicate, cancellation and eviction" do
      table = Qpack.new(max_capacity: 220)

      # B.2: the section arrives before its inserts and is blocked.
      assert {:blocked, section} = Qpack.decode_field_section(hex("03811011"), table)
      assert Qpack.section_required_insert_count(section) == 2

      encoder =
        hex("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468")

      assert {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, encoder)
      assert {table.capacity, table.size, table.insert_count} == {220, 106, 2}

      assert {:ok, [{":authority", "www.example.com"}, {":path", "/sample/path"}], 2} =
               Qpack.resume_field_section(section, table, [])

      assert Qpack.section_ack(4) == hex("84")

      # B.3 speculative insert acknowledged with Insert Count Increment.
      assert {:ok, table, <<>>} =
               Qpack.apply_encoder_instructions(
                 table,
                 hex("4a637573746f6d2d6b65790c637573746f6d2d76616c7565")
               )

      assert table.size == 160
      assert Qpack.insert_count_increment(1) == hex("01")

      # B.4 duplicate then a relative-index section, cancelled.
      assert {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, hex("02"))
      assert table.size == 217

      assert {:ok,
              [
                {":authority", "www.example.com"},
                {":path", "/"},
                {"custom-key", "custom-value"}
              ], 4} = Qpack.decode_field_section(hex("050080c181"), table)

      assert Qpack.stream_cancel(8) == hex("48")

      # B.5 insert with dynamic name reference evicts the oldest entry.
      assert {:ok, table, <<>>} =
               Qpack.apply_encoder_instructions(
                 table,
                 hex("810d637573746f6d2d76616c756532")
               )

      assert {table.size, table.insert_count} == {215, 5}
      assert {:error, :invalid_dynamic_reference} = Qpack.absolute(table, 0)
      assert {:ok, {"custom-key", "custom-value2"}} = Qpack.absolute(table, 4)
    end
  end

  describe "encoder instructions" do
    test "capacity above the advertised maximum and oversized inserts are errors" do
      table = Qpack.new(max_capacity: 100)
      {:ok, too_big} = Qpack.encode_integer(101, 5, 0x20)

      assert {:error, :invalid_dynamic_table_capacity} =
               Qpack.apply_encoder_instructions(table, too_big)

      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, set_capacity(64))

      assert {:error, :dynamic_entry_too_large} =
               Qpack.apply_encoder_instructions(
                 table,
                 insert_literal("x", String.duplicate("v", 32))
               )
    end

    test "reducing capacity evicts oldest entries" do
      table = Qpack.new(max_capacity: 200)

      {:ok, table, <<>>} =
        Qpack.apply_encoder_instructions(
          table,
          set_capacity(200) <> insert_literal("a", "1") <> insert_literal("b", "2")
        )

      assert table.size == 68
      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, set_capacity(40))
      assert {table.size, table.insert_count} == {34, 2}
      assert {:error, :invalid_dynamic_reference} = Qpack.absolute(table, 0)
      assert {:ok, {"b", "2"}} = Qpack.absolute(table, 1)
    end

    test "partial instructions are buffered and bounded" do
      table = Qpack.new(max_capacity: 200)
      wire = set_capacity(200) <> insert_literal("custom", "value")
      split = byte_size(wire) - 3
      <<head::binary-size(^split), tail::binary>> = wire

      assert {:ok, partial, rest} = Qpack.apply_encoder_instructions(table, head)
      assert partial.insert_count == 0 and partial.capacity == 200
      assert {:ok, done, <<>>} = Qpack.apply_encoder_instructions(partial, rest <> tail)
      assert {:ok, {"custom", "value"}} = Qpack.absolute(done, 0)

      assert {:error, :encoder_instruction_too_large} =
               Qpack.apply_encoder_instructions(table, head, max_buffer: 4)
    end

    test "invalid references on the encoder stream are errors" do
      table = Qpack.new(max_capacity: 200)
      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, set_capacity(200))
      # Duplicate of a nonexistent entry and dynamic name reference to it.
      assert {:error, :invalid_dynamic_reference} = Qpack.apply_encoder_instructions(table, <<0>>)

      assert {:error, :invalid_dynamic_reference} =
               Qpack.apply_encoder_instructions(table, <<0x80, 1, "v">>)

      assert {:error, :invalid_static_index} =
               Qpack.apply_encoder_instructions(table, <<0xFF, 0x40, 1, "v">>)
    end
  end

  describe "field sections" do
    setup do
      table = Qpack.new(max_capacity: 4_096)

      {:ok, table, <<>>} =
        Qpack.apply_encoder_instructions(
          table,
          set_capacity(4_096) <> insert_literal("x-a", "one") <> insert_literal("x-b", "two")
        )

      %{table: table}
    end

    test "post-base indexed and post-base name references", %{table: table} do
      # Required Insert Count 2, Base 0 (sign bit, delta 1).
      block = <<3, 0x81, 0x10, 0x01, 3, "new">>

      assert {:ok, [{"x-a", "one"}, {"x-b", "new"}], 2} =
               Qpack.decode_field_section(block, table)
    end

    test "dynamic name reference with literal value", %{table: table} do
      assert {:ok, [{"x-b", "three"}, {"x-a", "one"}], 2} =
               Qpack.decode_field_section(<<3, 0, 0x40, 5, "three", 0x81>>, table)
    end

    test "invalid prefixes and references fail", %{table: table} do
      # Encoded insert count above FullRange.
      assert {:error, :invalid_required_insert_count} =
               Qpack.decode_field_section(<<0xFF, 0x82, 0x01, 0>>, table)

      # Negative Base.
      assert {:error, :invalid_base} = Qpack.decode_field_section(<<2, 0x81, 0x80>>, table)
      # Reference at or above the Required Insert Count.
      assert {:error, :invalid_dynamic_reference} =
               Qpack.decode_field_section(<<2, 0x80, 0x11>>, table)

      # Required Insert Count larger than the largest reference + 1.
      assert {:error, :invalid_required_insert_count} =
               Qpack.decode_field_section(<<3, 0, 0x81>>, table)

      # Zero-capacity decoder rejects any nonzero Required Insert Count.
      assert {:error, :invalid_required_insert_count} =
               Qpack.decode_field_section(<<2, 0, 0x80>>, Qpack.new())
    end

    test "required insert count wraps around MaxEntries", %{table: table} do
      max_entries = Qpack.max_entries(table)
      full_range = 2 * max_entries

      table =
        Enum.reduce(1..(full_range + 3), table, fn index, acc ->
          {:ok, next, <<>>} =
            Qpack.apply_encoder_instructions(acc, insert_literal("x-n", Integer.to_string(index)))

          next
        end)

      required = table.insert_count
      encoded = Qpack.encode_required_insert_count(required, table.max_capacity)
      assert encoded < full_range + 1
      {:ok, prefix} = Qpack.encode_integer(encoded, 8, 0)
      value = Integer.to_string(full_range + 3)

      assert {:ok, [{"x-n", ^value}], ^required} =
               Qpack.decode_field_section(prefix <> <<0, 0x80>>, table)
    end

    test "blocked sections resume once inserts arrive", %{table: table} do
      assert {:blocked, section} = Qpack.decode_field_section(<<4, 0, 0x80>>, table)
      assert Qpack.section_required_insert_count(section) == 3
      assert {:blocked, ^section} = Qpack.resume_field_section(section, table, [])

      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, insert_literal("x-c", "3"))
      assert {:ok, [{"x-c", "3"}], 3} = Qpack.resume_field_section(section, table, [])
    end

    test "static profile keeps rejecting dynamic references" do
      assert {:error, :dynamic_table_not_supported} = Qpack.decode_header_block(<<2, 0, 0x80>>)

      assert {:error, :unsupported_field_representation} =
               Qpack.decode_header_block(<<0, 0, 0x10>>)
    end
  end

  describe "decoder instructions" do
    test "round trip and reject a zero increment" do
      bytes = Qpack.section_ack(200) <> Qpack.stream_cancel(4) <> Qpack.insert_count_increment(70)

      assert {:ok, [{:section_ack, 200}, {:stream_cancel, 4}, {:insert_count_increment, 70}],
              <<>>} = Qpack.decode_decoder_instructions(bytes)

      assert {:ok, [], <<0xFF>>} = Qpack.decode_decoder_instructions(<<0xFF>>)
      assert {:error, :invalid_insert_count_increment} = Qpack.decode_decoder_instructions(<<0>>)
    end
  end

  describe "response blocking" do
    test "holds DATA and FIN behind a blocked HEADERS section and replays in order" do
      table = Qpack.new(max_capacity: 4_096)
      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, set_capacity(4_096))
      decoder = Response.new()
      headers = Frame.encode!(:headers, <<2, 0, 0xD9, 0x80>>)
      wire = headers <> Frame.encode!(:data, "ok")

      assert {:ok, decoder, []} = Response.feed(decoder, wire, table)
      assert Response.blocked?(decoder)
      assert Response.required_insert_count(decoder) == 1
      assert Response.retained_bytes(decoder) > 0
      assert {:ok, decoder, []} = Response.finish(decoder)
      assert decoder.phase != :done
      assert {:ok, ^decoder, []} = Response.resume(decoder, table)

      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, insert_literal("x-dyn", "v"))

      assert {:ok, decoder, events} = Response.resume(decoder, table)

      assert events == [
               {:qpack_ack, 1},
               {:headers, 200, [{"x-dyn", "v"}]},
               {:data, "ok"},
               :done
             ]

      assert decoder.phase == :done
      assert Response.retained_bytes(decoder) == 0
    end

    test "blocked trailers keep the held FIN" do
      table = Qpack.new(max_capacity: 4_096)
      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, set_capacity(4_096))

      wire =
        Frame.encode!(:headers, <<0, 0, 0xD9>>) <>
          Frame.encode!(:data, "a") <> Frame.encode!(:headers, <<2, 0, 0x80>>)

      assert {:ok, decoder, [{:headers, 200, []}, {:data, "a"}]} =
               Response.feed(Response.new(), wire, table)

      assert {:ok, decoder, []} = Response.finish(decoder)
      {:ok, table, <<>>} = Qpack.apply_encoder_instructions(table, insert_literal("x-t", "1"))

      assert {:ok, %{phase: :done}, [{:qpack_ack, 1}, {:trailers, [{"x-t", "1"}]}, :done]} =
               Response.resume(decoder, table)
    end
  end

  defp set_capacity(capacity) do
    {:ok, bytes} = Qpack.encode_integer(capacity, 5, 0x20)
    bytes
  end

  defp insert_literal(name, value) do
    {:ok, length} = Qpack.encode_integer(byte_size(name), 5, 0x40)
    {:ok, encoded} = Qpack.encode_string(value)
    length <> name <> encoded
  end
end
