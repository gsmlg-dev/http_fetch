defmodule HTTP.HeadersTest do
  use ExUnit.Case

  describe "new/1" do
    test "creates new struct with headers" do
      headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      assert %HTTP.Headers{headers: [{"Content-Type", "application/json"}]} = headers
    end

    test "creates empty struct" do
      headers = HTTP.Headers.new()
      assert %HTTP.Headers{headers: []} = headers
    end
  end

  describe "normalize_name/1" do
    test "normalizes lowercase headers" do
      assert HTTP.Headers.normalize_name("content-type") == "Content-Type"
      assert HTTP.Headers.normalize_name("authorization") == "Authorization"
    end

    test "normalizes uppercase headers" do
      assert HTTP.Headers.normalize_name("CONTENT-TYPE") == "Content-Type"
      assert HTTP.Headers.normalize_name("AUTHORIZATION") == "Authorization"
    end

    test "normalizes mixed case headers" do
      assert HTTP.Headers.normalize_name("cOnTeNt-TyPe") == "Content-Type"
      assert HTTP.Headers.normalize_name("AuThOrIzAtIoN") == "Authorization"
    end

    test "handles single-word headers" do
      assert HTTP.Headers.normalize_name("content") == "Content"
      assert HTTP.Headers.normalize_name("AUTHORIZATION") == "Authorization"
    end
  end

  describe "parse/1" do
    test "parses basic header" do
      assert HTTP.Headers.parse("Content-Type: application/json") ==
               {"Content-Type", "application/json"}
    end

    test "parses header with extra spaces" do
      assert HTTP.Headers.parse("  Content-Type  :  application/json  ") ==
               {"Content-Type", "application/json"}
    end

    test "parses header without value" do
      assert HTTP.Headers.parse("X-Custom-Header:") == {"X-Custom-Header", ""}
    end

    test "normalizes header name during parsing" do
      assert HTTP.Headers.parse("content-type: application/json") ==
               {"Content-Type", "application/json"}
    end
  end

  describe "to_map/1" do
    test "converts headers to map with lowercase keys" do
      headers =
        HTTP.Headers.new([
          {"Content-Type", "application/json"},
          {"Authorization", "Bearer token"}
        ])

      result = HTTP.Headers.to_map(headers)
      assert result == %{"content-type" => "application/json", "authorization" => "Bearer token"}
    end

    test "handles empty headers" do
      assert HTTP.Headers.to_map(HTTP.Headers.new()) == %{}
    end
  end

  describe "from_map/1" do
    test "converts map to headers with normalized names" do
      map = %{"content-type" => "application/json", "authorization" => "Bearer token"}
      result = HTTP.Headers.from_map(map)
      assert {"Content-Type", "application/json"} in result.headers
      assert {"Authorization", "Bearer token"} in result.headers
    end

    test "handles empty map" do
      assert HTTP.Headers.from_map(%{}).headers == []
    end
  end

  describe "get/2" do
    test "gets header value case-insensitive" do
      headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      assert HTTP.Headers.get(headers, "content-type") == "application/json"
      assert HTTP.Headers.get(headers, "CONTENT-TYPE") == "application/json"
      assert HTTP.Headers.get(headers, "Content-Type") == "application/json"
    end

    test "returns nil for missing header" do
      headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      assert HTTP.Headers.get(headers, "missing") == nil
    end

    test "handles empty struct" do
      assert HTTP.Headers.get(HTTP.Headers.new(), "content-type") == nil
    end
  end

  describe "set/3" do
    test "sets new header" do
      headers = HTTP.Headers.new([{"Content-Type", "text/plain"}])
      result = HTTP.Headers.set(headers, "Authorization", "Bearer token")
      assert HTTP.Headers.get(result, "Authorization") == "Bearer token"
      assert HTTP.Headers.get(result, "Content-Type") == "text/plain"
    end

    test "replaces existing header" do
      headers = HTTP.Headers.new([{"Content-Type", "text/plain"}])
      result = HTTP.Headers.set(headers, "Content-Type", "application/json")
      assert HTTP.Headers.get(result, "Content-Type") == "application/json"
    end

    test "normalizes header name when setting" do
      headers = HTTP.Headers.new()
      result = HTTP.Headers.set(headers, "content-type", "application/json")
      assert HTTP.Headers.get(result, "Content-Type") == "application/json"
    end
  end

  describe "merge/2" do
    test "merges headers with second taking precedence" do
      headers1 = HTTP.Headers.new([{"Content-Type", "text/plain"}, {"A", "1"}])
      headers2 = HTTP.Headers.new([{"Content-Type", "application/json"}, {"B", "2"}])
      merged = HTTP.Headers.merge(headers1, headers2)

      assert HTTP.Headers.get(merged, "Content-Type") == "application/json"
      assert HTTP.Headers.get(merged, "A") == "1"
      assert HTTP.Headers.get(merged, "B") == "2"
    end

    test "handles empty structs" do
      result = HTTP.Headers.merge(HTTP.Headers.new(), HTTP.Headers.new([{"A", "1"}]))
      assert HTTP.Headers.get(result, "A") == "1"
    end
  end

  describe "has?/2" do
    test "checks if header exists case-insensitive" do
      headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      assert HTTP.Headers.has?(headers, "content-type")
      assert HTTP.Headers.has?(headers, "CONTENT-TYPE")
      refute HTTP.Headers.has?(headers, "missing")
    end

    test "handles empty struct" do
      refute HTTP.Headers.has?(HTTP.Headers.new(), "content-type")
    end
  end

  describe "delete/2" do
    test "deletes header case-insensitive" do
      headers =
        HTTP.Headers.new([
          {"Content-Type", "application/json"},
          {"Authorization", "Bearer token"}
        ])

      updated = HTTP.Headers.delete(headers, "content-type")
      refute HTTP.Headers.has?(updated, "content-type")
      assert HTTP.Headers.has?(updated, "Authorization")
    end
  end

  describe "parse_content_type/1" do
    test "parses basic content type" do
      assert HTTP.Headers.parse_content_type("application/json") == {"application/json", %{}}
    end

    test "parses content type with charset" do
      assert HTTP.Headers.parse_content_type("application/json; charset=utf-8") ==
               {"application/json", %{"charset" => "utf-8"}}
    end

    test "parses content type with multiple parameters" do
      assert HTTP.Headers.parse_content_type("text/html; charset=utf-8; boundary=something") ==
               {"text/html", %{"charset" => "utf-8", "boundary" => "something"}}
    end
  end

  describe "format/1" do
    test "formats headers for display" do
      headers =
        HTTP.Headers.new([
          {"Content-Type", "application/json"},
          {"Authorization", "Bearer token"}
        ])

      result = HTTP.Headers.format(headers)
      assert result == "Content-Type: application/json\nAuthorization: Bearer token"
    end

    test "handles empty headers" do
      assert HTTP.Headers.format(HTTP.Headers.new()) == ""
    end
  end

  describe "to_list/1" do
    test "returns underlying list" do
      headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      assert HTTP.Headers.to_list(headers) == [{"Content-Type", "application/json"}]
    end
  end

  describe "get_all/2" do
    test "returns all values for a header name case-insensitive" do
      headers =
        HTTP.Headers.new([
          {"Accept", "text/html"},
          {"Accept", "application/json"},
          {"Accept", "*/*"}
        ])

      assert HTTP.Headers.get_all(headers, "accept") == ["text/html", "application/json", "*/*"]
      assert HTTP.Headers.get_all(headers, "ACCEPT") == ["text/html", "application/json", "*/*"]
    end

    test "returns single value when only one exists" do
      headers =
        HTTP.Headers.new([
          {"Content-Type", "application/json"},
          {"Authorization", "Bearer token"}
        ])

      assert HTTP.Headers.get_all(headers, "content-type") == ["application/json"]
    end

    test "returns empty list for missing header" do
      headers =
        HTTP.Headers.new([
          {"Content-Type", "application/json"}
        ])

      assert HTTP.Headers.get_all(headers, "missing") == []
    end

    test "handles empty headers" do
      assert HTTP.Headers.get_all(HTTP.Headers.new(), "content-type") == []
    end

    test "returns empty list when no headers match" do
      headers =
        HTTP.Headers.new([
          {"Content-Type", "application/json"},
          {"Authorization", "Bearer token"}
        ])

      assert HTTP.Headers.get_all(headers, "x-custom-header") == []
    end
  end

  describe "add/3" do
    test "adds new header without replacing existing ones" do
      headers =
        HTTP.Headers.new([
          {"Accept", "text/html"}
        ])

      updated = HTTP.Headers.add(headers, "Accept", "application/json")
      assert HTTP.Headers.get_all(updated, "Accept") == ["text/html", "application/json"]
    end

    test "adds new header to existing structure" do
      headers =
        HTTP.Headers.new([
          {"Content-Type", "text/plain"}
        ])

      updated = HTTP.Headers.add(headers, "Authorization", "Bearer token")
      assert HTTP.Headers.get(updated, "Authorization") == "Bearer token"
      assert HTTP.Headers.get(updated, "Content-Type") == "text/plain"
    end

    test "adds header to empty structure" do
      headers = HTTP.Headers.new()
      updated = HTTP.Headers.add(headers, "Authorization", "Bearer token")
      assert HTTP.Headers.get(updated, "Authorization") == "Bearer token"
    end

    test "normalizes header name when adding" do
      headers = HTTP.Headers.new()
      updated = HTTP.Headers.add(headers, "content-type", "application/json")
      assert HTTP.Headers.get(updated, "Content-Type") == "application/json"
    end

    test "adds multiple headers with same name" do
      headers = HTTP.Headers.new()

      headers = HTTP.Headers.add(headers, "Accept", "text/html")
      headers = HTTP.Headers.add(headers, "Accept", "application/json")
      headers = HTTP.Headers.add(headers, "Accept", "*/*")

      assert HTTP.Headers.get_all(headers, "Accept") == ["text/html", "application/json", "*/*"]
    end

    test "adds headers case-insensitive" do
      headers =
        HTTP.Headers.new([
          {"Accept", "text/html"}
        ])

      updated = HTTP.Headers.add(headers, "accept", "application/json")
      updated = HTTP.Headers.add(updated, "ACCEPT", "*/*")

      assert HTTP.Headers.get_all(updated, "Accept") == ["text/html", "application/json", "*/*"]
    end
  end
end
