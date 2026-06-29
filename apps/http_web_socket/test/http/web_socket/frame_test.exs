defmodule HTTP.WebSocket.FrameTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias HTTP.WebSocket.Frame

  test "encodes masked client text frames" do
    assert {:ok, frame} = Frame.encode(:text, "hello")
    <<first, second, rest::binary>> = frame

    assert first == 0x81
    assert (second &&& 0x80) == 0x80
    assert (second &&& 0x7F) == 5
    <<mask_key::binary-size(4), masked::binary>> = rest
    assert unmask(masked, mask_key) == "hello"
  end

  test "encodes minimal payload lengths" do
    assert {:ok, <<0x82, second, _rest::binary>>} = Frame.encode(:binary, :binary.copy("a", 125))
    assert (second &&& 0x7F) == 125

    assert {:ok, <<0x82, second, 126::16, _rest::binary>>} =
             Frame.encode(:binary, :binary.copy("a", 126))

    assert (second &&& 0x7F) == 126

    assert {:ok, <<0x82, second, 66_000::64, _rest::binary>>} =
             Frame.encode(:binary, :binary.copy("a", 66_000))

    assert (second &&& 0x7F) == 127
  end

  test "rejects oversized control frames" do
    assert {:error, :control_payload_too_large} = Frame.encode(:ping, :binary.copy("a", 126))
  end

  test "parses unmasked server frames" do
    parser = Frame.new_parser()

    assert {:ok, parser, [{:message, :text, "hello"}]} =
             Frame.parse(parser, server_frame(0x1, "hello"))

    assert {:ok, _parser, [{:message, :binary, <<1, 2>>}]} =
             Frame.parse(parser, server_frame(0x2, <<1, 2>>))
  end

  test "parses close ping and pong frames" do
    parser = Frame.new_parser()

    assert {:ok, parser, [{:ping, "a"}]} = Frame.parse(parser, server_frame(0x9, "a"))
    assert {:ok, parser, [{:pong, "b"}]} = Frame.parse(parser, server_frame(0xA, "b"))

    assert {:ok, _parser, [{:close, 1000, "done"}]} =
             Frame.parse(parser, server_frame(0x8, <<1000::16, "done">>))
  end

  test "rejects protocol errors" do
    assert {:ok, masked} = Frame.encode(:text, "hello")
    assert {:error, {1002, :masked_server_frame}} = Frame.parse(Frame.new_parser(), masked)

    assert {:error, {1002, :unknown_opcode}} = Frame.parse(Frame.new_parser(), <<0x8B, 0>>)
    assert {:error, {1002, :unexpected_rsv}} = Frame.parse(Frame.new_parser(), <<0xC1, 0>>)

    assert {:error, {1002, :fragmented_control_frame}} =
             Frame.parse(Frame.new_parser(), <<0x09, 0>>)
  end

  test "reassembles fragmented messages" do
    parser = Frame.new_parser()
    assert {:ok, parser, []} = Frame.parse(parser, server_frame(0x1, "hel", fin?: false))

    assert {:ok, _parser, [{:message, :text, "hello"}]} =
             Frame.parse(parser, server_frame(0x0, "lo"))
  end

  test "rejects invalid utf8 and oversized messages" do
    assert {:error, {1007, :invalid_utf8}} =
             Frame.parse(Frame.new_parser(), server_frame(0x1, <<255>>))

    assert {:error, {1009, :message_too_big}} =
             Frame.parse(Frame.new_parser(max_message_size: 2), server_frame(0x1, "abc"))
  end

  defp server_frame(opcode, payload, opts \\ []) do
    fin = if Keyword.get(opts, :fin?, true), do: 0x80, else: 0x00
    <<fin ||| opcode, byte_size(payload), payload::binary>>
  end

  defp unmask(payload, <<a, b, c, d>>) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {byte, index} ->
      bxor(byte, Enum.at([a, b, c, d], rem(index, 4)))
    end)
    |> :binary.list_to_bin()
  end
end
