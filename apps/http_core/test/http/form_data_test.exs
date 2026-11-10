defmodule HTTP.FormDataTest do
  use ExUnit.Case

  describe "new/0" do
    test "creates empty form data" do
      form = HTTP.FormData.new()
      assert %HTTP.FormData{parts: [], boundary: nil} = form
    end
  end

  describe "append_field/3" do
    test "adds form field" do
      form = HTTP.FormData.new() |> HTTP.FormData.append_field("name", "value")
      assert {:field, "name", "value"} in form.parts
    end

    test "adds multiple fields" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("name", "value")
        |> HTTP.FormData.append_field("key", "val")

      assert {:field, "name", "value"} in form.parts
      assert {:field, "key", "val"} in form.parts
    end
  end

  describe "append_file/4" do
    test "adds file with string content" do
      form = HTTP.FormData.new() |> HTTP.FormData.append_file("upload", "test.txt", "content")
      assert {:file, "upload", "test.txt", "application/octet-stream", "content"} in form.parts
    end

    test "adds file with custom content type" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file(
          "upload",
          "test.json",
          ~s({"test": true}),
          "application/json"
        )

      assert {:file, "upload", "test.json", "application/json", ~s({"test": true})} in form.parts
    end

    @tag :tmp_dir
    @tag :integration
    test "adds file with stream", %{tmp_dir: tmp_dir} do
      test_content = "test file content"
      path = Path.join(tmp_dir, "test.txt")
      File.write!(path, test_content)
      file_stream = File.stream!(path)

      form = HTTP.FormData.new() |> HTTP.FormData.append_file("upload", "test.txt", file_stream)

      assert match?(
               {:file, "upload", "test.txt", "application/octet-stream", %File.Stream{}},
               hd(form.parts)
             )
    end
  end

  describe "to_body/1" do
    test "encodes regular form data as url-encoded" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("name", "John Doe")
        |> HTTP.FormData.append_field("email", "john@example.com")

      assert {:url_encoded, body} = HTTP.FormData.to_body(form)
      assert body == "name=John+Doe&email=john%40example.com"
    end

    test "encodes multipart with fields" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("name", "John")
        |> HTTP.FormData.append_file("upload", "test.txt", "file content")
        |> Map.put(:boundary, "test-boundary")

      assert {:multipart, body, "test-boundary"} = HTTP.FormData.to_body(form)
      # Convert iodata to binary for testing
      body_string = IO.iodata_to_binary(body)
      assert body_string =~ "Content-Disposition: form-data; name=\"name\""
      assert body_string =~ "John"

      assert body_string =~
               "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\""

      assert body_string =~ "file content"
    end

    test "encodes multipart with files" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("description", "test file")
        |> HTTP.FormData.append_file("upload", "test.txt", "file content")

      assert {:multipart, body, boundary} = HTTP.FormData.to_body(form)
      assert is_binary(boundary)
      # Convert iodata to binary for testing
      body_string = IO.iodata_to_binary(body)
      assert body_string =~ "Content-Disposition: form-data; name=\"description\""
      assert body_string =~ "test file"

      assert body_string =~
               "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\""

      assert body_string =~ "file content"
    end

    @tag :tmp_dir
    @tag :integration
    test "encodes multipart with file stream", %{tmp_dir: tmp_dir} do
      test_content = "test file content"
      path = Path.join(tmp_dir, "test.txt")
      File.write!(path, test_content)
      file_stream = File.stream!(path)

      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file("upload", "test.txt", file_stream)
        |> Map.put(:boundary, "test-boundary")

      assert {:multipart, body, "test-boundary"} = HTTP.FormData.to_body(form)
      # Convert iodata to binary for testing
      body_string = IO.iodata_to_binary(body)

      assert body_string =~
               "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\""

      assert body_string =~ test_content
    end

    @tag :tmp_dir
    @tag :integration
    test "encodes binary file streams without line-mode truncation", %{tmp_dir: tmp_dir} do
      test_content = :crypto.strong_rand_bytes(100_000)
      path = Path.join(tmp_dir, "test.bin")
      File.write!(path, test_content)
      file_stream = File.stream!(path)

      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file("upload", "test.bin", file_stream)
        |> Map.put(:boundary, "test-boundary")

      assert {:multipart, body, "test-boundary"} = HTTP.FormData.to_body(form)
      body_binary = IO.iodata_to_binary(body)
      [_headers, rest] = String.split(body_binary, "\r\n\r\n", parts: 2)
      [file_content, _closing] = :binary.split(rest, "\r\n--test-boundary--\r\n")

      assert file_content == test_content
    end
  end

  describe "get_content_type/1" do
    test "returns url-encoded for regular forms" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("name", "value")

      assert HTTP.FormData.get_content_type(form) == "application/x-www-form-urlencoded"
    end

    test "returns multipart for file uploads" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file("upload", "test.txt", "content")

      assert HTTP.FormData.get_content_type(form) =~ "multipart/form-data"
    end

    test "uses the form's own boundary so it matches to_body/1" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file("upload", "test.txt", "content")
        |> Map.put(:boundary, "form-boundary")

      {:multipart, _body, boundary} = HTTP.FormData.to_body(form)
      assert boundary == "form-boundary"

      assert HTTP.FormData.get_content_type(form) ==
               "multipart/form-data; boundary=form-boundary"
    end
  end

  describe "multipart header escaping" do
    test "escapes quote, CR and LF in names and filenames per the WHATWG encoding" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field(~s(a"; x="y), "v")
        |> HTTP.FormData.append_file(
          "up\rload",
          "f\r\nContent-Type: text/html\r\n\r\n<script>",
          "content"
        )
        |> Map.put(:boundary, "b")

      expected =
        "--b\r\n" <>
          ~s(Content-Disposition: form-data; name="a%22; x=%22y"\r\n\r\nv\r\n) <>
          "--b\r\n" <>
          ~s(Content-Disposition: form-data; name="up%0Dload"; ) <>
          ~s(filename="f%0D%0AContent-Type: text/html%0D%0A%0D%0A<script>"\r\n) <>
          "Content-Type: application/octet-stream\r\n\r\ncontent\r\n--b--\r\n"

      assert {:multipart, body, "b"} = HTTP.FormData.to_body(form)
      assert IO.iodata_to_binary(body) == expected

      assert {:ok, %{body: stream, content_length: length}} = HTTP.FormData.to_stream(form)
      assert Enum.join(stream) == expected
      assert length == byte_size(expected)
    end

    test "rejects control characters in a part content type" do
      for content_type <- ["text/html\r\nX-Injected: 1", "text/plain\n", "text/\0plain", "a\x7f"] do
        assert_raise ArgumentError, fn ->
          HTTP.FormData.new() |> HTTP.FormData.append_file("f", "f.txt", "x", content_type)
        end

        form = %HTTP.FormData{parts: [{:file, "f", "f.txt", content_type, "x"}], boundary: "b"}

        assert_raise ArgumentError, fn -> HTTP.FormData.to_body(form) end
        assert {:error, :invalid_multipart_content_type} = HTTP.FormData.to_stream(form)
      end

      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file("f", "f.txt", "x", "text/plain;\tcharset=utf-8")

      assert {:multipart, _body, _boundary} = HTTP.FormData.to_body(form)
    end
  end

  describe "generate_boundary/0" do
    test "is long, prefixed and drawn from a strong random source" do
      boundaries = for _ <- 1..64, do: HTTP.FormData.generate_boundary()

      assert length(Enum.uniq(boundaries)) == 64

      for boundary <- boundaries do
        assert "http-fetch-" <> random = boundary
        assert byte_size(random) == 32
        assert {:ok, <<_::binary-size(16)>>} = Base.decode16(random, case: :lower)
        assert byte_size(boundary) <= 70
      end
    end
  end
end
