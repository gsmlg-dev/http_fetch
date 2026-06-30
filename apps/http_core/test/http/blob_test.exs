defmodule HTTP.BlobTest do
  use ExUnit.Case, async: true

  alias HTTP.Blob

  describe "new/2" do
    test "creates blob with data, type, and size" do
      data = <<1, 2, 3, 4, 5>>
      blob = Blob.new(data, "image/png")

      assert blob.data == data
      assert blob.type == "image/png"
      assert blob.size == 5
    end

    test "uses default type" do
      blob = Blob.new(<<1, 2, 3>>)

      assert blob.type == "application/octet-stream"
    end
  end

  test "to_binary/1 extracts data" do
    data = <<1, 2, 3, 4>>
    blob = Blob.new(data, "image/jpeg")

    assert Blob.to_binary(blob) == data
  end

  test "type/1 returns MIME type" do
    blob = Blob.new(<<>>, "text/plain")

    assert Blob.type(blob) == "text/plain"
  end

  test "size/1 returns byte size" do
    blob = Blob.new(<<1, 2, 3, 4, 5, 6, 7, 8>>, "application/octet-stream")

    assert Blob.size(blob) == 8
  end
end
