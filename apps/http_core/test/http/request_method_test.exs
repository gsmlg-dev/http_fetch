defmodule HTTP.RequestMethodTest do
  use ExUnit.Case, async: true

  test "accepts DAV and arbitrary ASCII tokens in both request modes" do
    for mode <- [:fetch, :proxy],
        {method, token} <- [
          {:propfind, "PROPFIND"},
          {:report, "REPORT"},
          {:mkcol, "MKCOL"},
          {"MiXeD", "MiXeD"},
          {"!#$%&'*+-.^_`|~012aZ", "!#$%&'*+-.^_`|~012aZ"}
        ] do
      request = %HTTP.Request{
        url: URI.parse("http://example.test/dav"),
        method: method,
        request_mode: mode,
        body: "<xml/>"
      }

      wire = request |> HTTP.Request.to_iodata() |> IO.iodata_to_binary()
      assert String.starts_with?(wire, token <> " /dav HTTP/1.1\r\n")
      assert String.ends_with?(wire, "\r\n\r\n<xml/>")
    end
  end

  test "rejects invalid original bytes before atom uppercasing" do
    for method <- [
          "",
          "BAD METHOD",
          "BAD\tMETHOD",
          "BAD\r\nMETHOD",
          "BAD/METHOD",
          "BAD:METHOD",
          "BAD\0METHOD",
          "BAD\x7fMETHOD",
          "ß",
          :ß,
          <<255>>,
          123,
          [71, 69, 84]
        ] do
      assert_raise ArgumentError, ~r/unsupported HTTP method/, fn ->
        HTTP.Request.method_token(method)
      end
    end
  end
end
