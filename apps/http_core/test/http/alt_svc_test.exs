defmodule HTTP.AltSvcTest do
  use ExUnit.Case, async: true

  alias HTTP.AltSvc

  test "parses quoted alt-authority with defaults" do
    assert [%{alpn: "h3", host: "", port: 443, max_age: 86_400, persist?: false}] =
             AltSvc.parse(~s(h3=":443"))
  end

  test "parses comma lists, parameters and whitespace" do
    value = ~s(h3=":8443"; ma=3600 ,  h2="alt.example:443";persist=1, h3-29=":1")

    assert [
             %{alpn: "h3", host: "", port: 8443, max_age: 3600},
             %{alpn: "h2", host: "alt.example", port: 443, persist?: true},
             %{alpn: "h3-29", port: 1}
           ] = AltSvc.parse(value)
  end

  test "decodes percent-encoded protocol ids and lowercases hosts" do
    assert [%{alpn: "w=x:y#z", host: "alt.example"}] =
             AltSvc.parse(~s(w%3Dx%3Ay#z="ALT.Example:1"))
  end

  test "accepts escaped quoted strings, IPv6 hosts and quoted parameters" do
    assert [%{host: "::1", port: 9, max_age: 60}] = AltSvc.parse(~s(h3="[::1]:9"; ma="60"))
    assert [%{host: "a,b", port: 2}] = AltSvc.parse(~s(h3="a\\,b:2"))
  end

  test "accepts token alt-authority leniently and ignores unknown parameters" do
    assert [%{alpn: "h3", host: "", port: 443}] = AltSvc.parse("h3=:443; foo=bar")
  end

  test "skips empty list elements" do
    assert [%{port: 1}, %{port: 2}] = AltSvc.parse(~s(, h3=":1",, h3=":2" ,))
  end

  test "recognizes clear" do
    assert AltSvc.parse("clear") == :clear
    assert AltSvc.parse("  clear ") == :clear
  end

  test "rejects malformed values" do
    for value <- [
          "",
          " , ",
          "h3",
          ~s(h3=":0"),
          ~s(h3=":65536"),
          ~s(h3=":+1"),
          ~s(h3="host"),
          ~s(h3="[::1:9"),
          ~s(h3="[nothost]:9"),
          ~s(h3=":443"; ma=-1),
          ~s(h3=":443"; ma=soon),
          ~s(h3=":443),
          ~s(h3=":443"x),
          ~s(h 3=":443"),
          ~s(h3%zz=":443"),
          ~s(h3=":443"; =1),
          "clear, h3=\":443\""
        ] do
      assert {:error, _} = AltSvc.parse(value), "expected error for #{inspect(value)}"
    end

    assert {:error, _} = AltSvc.parse(nil)
  end
end
