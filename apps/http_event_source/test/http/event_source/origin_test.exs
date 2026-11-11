defmodule HTTP.EventSource.OriginTest do
  use ExUnit.Case, async: true

  alias HTTP.EventSource.Connection

  defp origin(url), do: url |> URI.parse() |> Connection.serialize_origin()
  defp same?(a, b), do: Connection.same_origin?(URI.parse(a), URI.parse(b))

  test "serializes origins per WHATWG, omitting default ports" do
    assert origin("http://[::1]/e") == "http://[::1]"
    assert origin("https://[::1]:443/e") == "https://[::1]"
    assert origin("http://[::1]:8080/e") == "http://[::1]:8080"
    assert origin("https://[2001:DB8::A]:8443/e") == "https://[2001:db8::a]:8443"
    assert origin("http://[0:0:0:0:0:0:0:1]/e") == "http://[::1]"
    assert origin("http://127.0.0.1:80/e") == "http://127.0.0.1"
    assert origin("http://127.0.0.1:9000/e") == "http://127.0.0.1:9000"
    assert origin("HTTPS://Example.COM/e") == "https://example.com"
    assert origin("http://example.com:81/e") == "http://example.com:81"
  end

  test "same-origin comparison handles IPv6 forms, ports and controls" do
    assert same?("http://[::1]/a", "http://[::1]:80/b")
    assert same?("http://[::1]:8080/a", "http://[0:0:0:0:0:0:0:1]:8080/b")
    assert same?("https://[2001:DB8::1]/a", "https://[2001:db8:0::1]/b")
    refute same?("http://[::1]:8080/a", "http://[::1]:8081/b")
    refute same?("http://[::1]/a", "http://[::2]/b")
    refute same?("http://[::1]/a", "https://[::1]/b")
    refute same?("http://[::1]/a", "http://127.0.0.1/b")
    assert same?("http://127.0.0.1/a", "http://127.0.0.1:80/b")
    refute same?("http://127.0.0.1/a", "http://127.0.0.2/b")
    assert same?("http://Example.com/a", "http://example.COM:80/b")
    refute same?("http://example.com/a", "http://example.org/b")
  end
end
