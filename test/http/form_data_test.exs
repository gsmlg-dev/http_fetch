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

    test "adds file with stream" do
      # Create a temporary file for testing
      test_content = "test file content"
      {:ok, path} = Briefly.create()
      File.write!(path, test_content)
      file_stream = File.stream!(path)

      form = HTTP.FormData.new() |> HTTP.FormData.append_file("upload", "test.txt", file_stream)

      assert match?(
               {:file, "upload", "test.txt", "application/octet-stream", %File.Stream{}},
               hd(form.parts)
             )

      File.rm(path)
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
      assert body =~ "Content-Disposition: form-data; name=\"name\""
      assert body =~ "John"
      assert body =~ "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\""
      assert body =~ "file content"
    end

    test "encodes multipart with files" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("description", "test file")
        |> HTTP.FormData.append_file("upload", "test.txt", "file content")

      assert {:multipart, body, boundary} = HTTP.FormData.to_body(form)
      assert is_binary(boundary)
      assert body =~ "Content-Disposition: form-data; name=\"description\""
      assert body =~ "test file"
      assert body =~ "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\""
      assert body =~ "file content"
    end

    test "encodes multipart with file stream" do
      test_content = "test file content"
      {:ok, path} = Briefly.create()
      File.write!(path, test_content)
      file_stream = File.stream!(path)

      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file("upload", "test.txt", file_stream)
        |> Map.put(:boundary, "test-boundary")

      assert {:multipart, body, "test-boundary"} = HTTP.FormData.to_body(form)
      assert body =~ "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\""
      assert body =~ test_content

      File.rm(path)
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
  end
end
