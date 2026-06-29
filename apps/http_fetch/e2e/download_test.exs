defmodule E2E.DownloadTest do
  @moduledoc """
  Full file downloads and HTTP Range requests.
  """
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias E2E.ResponseView

  describe "full download" do
    test "returns the requested number of bytes" do
      n = 4096
      resp = E2E.Server.url("/download/#{n}") |> HTTP.fetch() |> HTTP.Promise.await()
      view = E2E.ResponseView.from(resp)

      assert view.status == 200
      assert E2E.ResponseView.get_header(view, "content-length") == to_string(n)
      assert byte_size(E2E.ResponseView.text(view)) == n
    end

    test "writes the download directly to a file (streaming path)" do
      tmp = Briefly.create!(directory: true, prefix: "dl_")
      out = Path.join(tmp, "out.bin")
      n = 100_000

      resp = E2E.Server.url("/download/#{n}") |> HTTP.fetch() |> HTTP.Promise.await()
      :ok = HTTP.Response.write_to(resp, out)

      assert File.stat!(out).size == n
    end
  end

  describe "byte range" do
    # The important client contract for range responses is that the
    # Content-Range header and response body slice are preserved.
    test "explicit range returns the correct Content-Range and body slice" do
      resp =
        E2E.Server.url("/range")
        |> HTTP.fetch(headers: %{"Range" => "bytes=0-9"})
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert E2E.ResponseView.get_header(view, "content-range") == "bytes 0-9/1000"
      assert byte_size(E2E.ResponseView.text(view)) == 10
    end

    test "open-ended range returns from offset to end" do
      resp =
        E2E.Server.url("/range")
        |> HTTP.fetch(headers: %{"Range" => "bytes=900-"})
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert E2E.ResponseView.get_header(view, "content-range") == "bytes 900-999/1000"
      assert byte_size(E2E.ResponseView.text(view)) == 100
    end

    test "suffix range returns the last N bytes" do
      resp =
        E2E.Server.url("/range")
        |> HTTP.fetch(headers: %{"Range" => "bytes=-50"})
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert E2E.ResponseView.get_header(view, "content-range") == "bytes 950-999/1000"
      assert byte_size(E2E.ResponseView.text(view)) == 50
    end

    test "out-of-range request returns 416" do
      resp =
        E2E.Server.url("/range")
        |> HTTP.fetch(headers: %{"Range" => "bytes=99999-"})
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 416
    end

    test "no Range header returns the full 1000-byte body" do
      resp = E2E.Server.url("/range") |> HTTP.fetch() |> HTTP.Promise.await()
      view = E2E.ResponseView.from(resp)

      assert view.status == 200
      assert E2E.ResponseView.get_header(view, "accept-ranges") == "bytes"
      assert byte_size(E2E.ResponseView.text(view)) == 1000
    end
  end
end
