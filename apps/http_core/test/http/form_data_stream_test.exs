defmodule HTTP.FormDataStreamTest do
  use ExUnit.Case, async: true

  alias HTTP.FormData

  test "exposes matching boundary, type and exact length while preserving part order" do
    form =
      FormData.new()
      |> FormData.append_field("first", "one")
      |> FormData.append_file("file", "bytes.bin", <<0, 255, 13, 10>>, "application/octet-stream")
      |> FormData.append_field("last", "two")
      |> Map.put(:boundary, "fixed-boundary")

    assert {:ok, envelope} = FormData.to_stream(form, chunk_size: 7)
    assert {:multipart, buffered, "fixed-boundary"} = FormData.to_body(form)
    chunks = Enum.to_list(envelope.body)
    body = IO.iodata_to_binary(chunks)

    assert body == IO.iodata_to_binary(buffered)
    assert envelope.content_length == byte_size(body)
    assert envelope.boundary == "fixed-boundary"
    assert envelope.content_type == "multipart/form-data; boundary=fixed-boundary"
    assert Enum.all?(chunks, &(is_binary(&1) and byte_size(&1) in 1..7))
  end

  test "streams empty and ordinary-field forms as multipart with their selected boundary" do
    for form <- [FormData.new(), FormData.append_field(FormData.new(), "name", "value")] do
      assert {:ok, envelope} = FormData.to_stream(form)
      body = Enum.join(envelope.body)
      assert envelope.content_type == "multipart/form-data; boundary=#{envelope.boundary}"
      assert envelope.content_length == byte_size(body)
      assert String.ends_with?(body, "--#{envelope.boundary}--\r\n")
    end
  end

  test "rejects invalid chunks, options and nonbinary parts before creating a producer" do
    for size <- [0, -1, 65_537, :infinity, "1024"] do
      assert {:error, :invalid_multipart_chunk_size} =
               FormData.to_stream(FormData.new(), chunk_size: size)
    end

    assert {:error, :invalid_multipart_options} = FormData.to_stream(FormData.new(), other: 1)
    assert {:error, :invalid_multipart_options} = FormData.to_stream(FormData.new(), :invalid)

    assert {:error, :invalid_multipart_part} =
             FormData.new() |> FormData.append_field("field", 123) |> FormData.to_stream()
  end

  test "a large in-memory field is split into bounded chunks" do
    value = :binary.copy("x", 100_003)
    form = FormData.new() |> FormData.append_field("field", value)
    assert {:ok, envelope} = FormData.to_stream(form, chunk_size: 1_024)
    chunks = Enum.to_list(envelope.body)
    assert Enum.all?(chunks, &(byte_size(&1) <= 1_024))
    assert envelope.content_length == Enum.reduce(chunks, 0, &(byte_size(&1) + &2))
    assert Enum.join(chunks) =~ value
  end
end
