defmodule HTTP.HTTP1StrictFramingTest do
  use ExUnit.Case, async: true

  @head "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
  @valid [
    "1",
    "01",
    "1;flag",
    "1;one;two=value",
    "1 \t; \tname \t= \tvalue",
    "1;empty=\"\"",
    "1;quoted=\"a;b\\\"c\\\\d\"",
    "1;quoted=\"\t \\ \x80\xff\"",
    "1;x=!#$%&'*+-.^_`|~012aZ"
  ]
  @invalid [
    " 1",
    "\t1",
    "1 ",
    "1\t",
    "+1",
    "-1",
    "0x1",
    "g",
    "",
    "1;",
    "1;=value",
    "1;name=",
    "1;name=\"open",
    "1;name=\"escape\\",
    "1;name=\"\0\"",
    "1;name=\"\x7f\"",
    "1;name=\"\\\0\"",
    "1;name=value ",
    "1;name=value/other",
    "1;name=\"closed\"suffix"
  ]

  for line <- @valid do
    test "valid chunk extension #{inspect(line)} survives every wire split" do
      wire = @head <> unquote(line) <> "\r\na\r\n0;end=\"\"\r\n\r\n"

      for split <- 0..byte_size(wire) do
        assert {:ok, parser, events} = fragmented(wire, split)
        assert parser.state == :done
        assert Enum.filter(events, &match?({:body, _}, &1)) == [{:body, "a"}]
        assert List.last(events) == :done
      end
    end
  end

  for line <- @invalid do
    test "invalid chunk extension #{inspect(line)} rejects at every wire split" do
      wire = @head <> unquote(line) <> "\r\na\r\n0\r\n\r\n"

      for split <- 0..byte_size(wire),
          do: assert({:error, :invalid_chunk_size} = fragmented(wire, split))
    end
  end

  test "status syntax requires exactly three digits in the range 100 through 599" do
    for status <- ["600", "099", "0200", "+200", "20", "200x", "200\tOK"] do
      wire = "HTTP/1.1 #{status} Invalid\r\nContent-Length: 0\r\n\r\n"

      for split <- 0..byte_size(wire),
          do: assert({:error, :invalid_status_line} = fragmented(wire, split))
    end

    for status <- [200, 599] do
      assert {:ok, %{status: ^status, state: :done}, _} =
               HTTP.HTTP1.stream(
                 HTTP.HTTP1.new(:post),
                 "HTTP/1.1 #{status} \r\nContent-Length: 0\r\n\r\n"
               )
    end
  end

  test "conflicting TE and CL fail before headers for HEAD, bodyless and informational responses" do
    for method <- [:post, :head],
        status <- [100, 101, 103, 200, 204, 304],
        coding <- ["chunked", "gzip"] do
      wire =
        "HTTP/1.1 #{status} Test\r\nTransfer-Encoding: #{coding}\r\nContent-Length: 0\r\n\r\n"

      reason =
        if method != :head and status == 200 and coding == "gzip",
          do: {:unsupported_transfer_encoding, ["gzip"]},
          else: :conflicting_response_framing

      for split <- 0..byte_size(wire),
          do: assert({:error, ^reason} = fragmented(wire, split, method))
    end
  end

  test "HEAD and 304 still admit a lone hypothetical unsupported transfer coding" do
    for {method, status} <- [{:head, 200}, {:post, 304}] do
      assert {:ok, %{state: :done}, [{:headers, ^status, _}, :done]} =
               HTTP.HTTP1.stream(
                 HTTP.HTTP1.new(method),
                 "HTTP/1.1 #{status} Test\r\nTransfer-Encoding: gzip\r\n\r\n"
               )
    end
  end

  test "the 8 KiB chunk-line bound applies to complete and fragmented lines" do
    valid = "1;x=" <> String.duplicate("a", 8_188)
    assert byte_size(valid) == 8_192

    wire = @head <> valid <> "\r\na\r\n0\r\n\r\n"

    for split <- [0, byte_size(@head) + 8_192, byte_size(@head) + 8_193, byte_size(wire)] do
      assert {:ok, %{state: :done}, _} = fragmented(wire, split)
    end

    oversized = @head <> valid <> "a\r\na\r\n0\r\n\r\n"

    for split <- [
          0,
          byte_size(@head),
          byte_size(@head) + 8_192,
          byte_size(@head) + 8_193,
          byte_size(oversized)
        ] do
      assert {:error, :line_too_long} = fragmented(oversized, split)
    end
  end

  defp fragmented(wire, split, method \\ :post) do
    <<first::binary-size(split), second::binary>> = wire

    with {:ok, parser, events} <- HTTP.HTTP1.stream(HTTP.HTTP1.new(method), first),
         {:ok, parser, more} <- HTTP.HTTP1.stream(parser, second),
         do: {:ok, parser, events ++ more}
  end
end
