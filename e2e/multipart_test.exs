defmodule E2E.MultipartTest do
  @moduledoc """
  multipart/form-data uploads via `HTTP.FormData.append_file/4`, including
  text fields, single files, multiple files, and a file large enough to
  confirm streaming works.
  """
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 60_000

  alias E2E.ResponseView

  setup do
    # Create three temp files of different shapes that we'll upload.
    small_text = Briefly.create!(directory: true, prefix: "small_")
    small_path = Path.join(small_text, "hello.txt")
    File.write!(small_path, "hello multipart\n")

    binary_dir = Briefly.create!(directory: true, prefix: "bin_")
    binary_path = Path.join(binary_dir, "blob.bin")
    # Random-ish bytes that are not valid UTF-8, to confirm binary uploads.
    File.write!(binary_path, <<0, 1, 2, 255, 254, 0, 0, 128, 200>>)

    large_dir = Briefly.create!(directory: true, prefix: "large_")
    large_path = Path.join(large_dir, "big.bin")
    # 1.5 MB; large enough to exercise multi-chunk body framing.
    File.write!(large_path, :crypto.strong_rand_bytes(1_500_000))

    on_exit(fn ->
      File.rm_rf!(small_text)
      File.rm_rf!(binary_dir)
      File.rm_rf!(large_dir)
    end)

    {:ok,
     small_path: small_path,
     small_text: "hello multipart\n",
     binary_path: binary_path,
     binary_bytes: <<0, 1, 2, 255, 254, 0, 0, 128, 200>>,
     large_path: large_path,
     large_size: 1_500_000}
  end

  describe "single file upload" do
    test "uploads a small text file with one extra field", ctx do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("title", "my doc")
        |> HTTP.FormData.append_file(
          "document",
          "hello.txt",
          File.stream!(ctx.small_path),
          "text/plain"
        )

      resp =
        E2E.Server.url("/multipart")
        |> HTTP.fetch(method: "POST", body: form)
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      decoded = E2E.ResponseView.json!(view)

      assert decoded["fields"] == %{"title" => ["my doc"]}

      [file] = decoded["files"]["document"]
      assert file["filename"] == "hello.txt"
      assert file["content_type"] == "text/plain"
      assert file["size"] == byte_size(ctx.small_text)
      assert Base.decode64!(file["data_b64"]) == ctx.small_text
    end
  end

  describe "binary file upload" do
    test "preserves non-UTF-8 bytes", ctx do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file(
          "blob",
          "blob.bin",
          ctx.binary_bytes,
          "application/octet-stream"
        )

      resp =
        E2E.Server.url("/multipart")
        |> HTTP.fetch(method: "POST", body: form)
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      [file] = E2E.ResponseView.json!(view)["files"]["blob"]
      assert file["content_type"] == "application/octet-stream"
      assert Base.decode64!(file["data_b64"]) == ctx.binary_bytes
    end
  end

  describe "multiple files in one form" do
    test "sends two file fields with a text field", ctx do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("description", "two files")
        |> HTTP.FormData.append_file(
          "first",
          "hello.txt",
          File.stream!(ctx.small_path),
          "text/plain"
        )
        |> HTTP.FormData.append_file(
          "second",
          "blob.bin",
          File.stream!(ctx.binary_path),
          "application/octet-stream"
        )

      resp =
        E2E.Server.url("/multipart")
        |> HTTP.fetch(method: "POST", body: form)
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      decoded = E2E.ResponseView.json!(view)

      assert decoded["fields"] == %{"description" => ["two files"]}

      assert [first] = decoded["files"]["first"]
      assert Base.decode64!(first["data_b64"]) == ctx.small_text

      assert [second] = decoded["files"]["second"]
      assert Base.decode64!(second["data_b64"]) == ctx.binary_bytes
    end
  end

  describe "large file upload" do
    test "uploads 1.5MB binary file intact", ctx do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_file(
          "big",
          "big.bin",
          File.stream!(ctx.large_path),
          "application/octet-stream"
        )

      resp =
        E2E.Server.url("/multipart")
        |> HTTP.fetch(method: "POST", body: form, options: [timeout: 30_000])
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200

      [file] = E2E.ResponseView.json!(view)["files"]["big"]
      assert file["size"] == ctx.large_size
      assert Base.decode64!(file["data_b64"]) == File.read!(ctx.large_path)
    end
  end
end
