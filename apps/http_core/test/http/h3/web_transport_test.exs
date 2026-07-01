defmodule HTTP.H3.WebTransportTest do
  use ExUnit.Case, async: true

  alias HTTP.H3.Settings
  alias HTTP.H3.WebTransport

  test "builds WebTransport extended CONNECT pseudo-headers from a URI" do
    assert {:ok,
            [
              {":method", "CONNECT"},
              {":protocol", "webtransport-h3"},
              {":scheme", "https"},
              {":authority", "example.com:8443"},
              {":path", "/transport?room=1"}
            ]} = WebTransport.connect_pseudo_headers("https://example.com:8443/transport?room=1")
  end

  test "builds bracketed IPv6 authority values" do
    assert {:ok, headers} = WebTransport.connect_pseudo_headers("https://[::1]/wt")
    assert {":authority", "[::1]"} in headers
  end

  test "rejects URLs that cannot carry WebTransport over HTTP/3" do
    assert {:error, {:unsupported_scheme, "http"}} =
             WebTransport.connect_pseudo_headers("http://example.com/wt")

    assert {:error, :fragment_not_allowed} =
             WebTransport.connect_pseudo_headers("https://example.com/wt#frag")

    assert {:error, :invalid_path} =
             WebTransport.connect_pseudo_headers(%URI{
               scheme: "https",
               host: "example.com",
               path: "wt"
             })
  end

  test "validates WebTransport CONNECT pseudo-headers" do
    assert {:ok, headers} = WebTransport.connect_pseudo_headers("https://example.com/wt")

    assert {:ok,
            %{
              ":method" => "CONNECT",
              ":protocol" => "webtransport-h3",
              ":scheme" => "https",
              ":authority" => "example.com",
              ":path" => "/wt"
            }} =
             WebTransport.validate_connect_pseudo_headers(headers ++ [{"WT-Protocol", "chat"}])
  end

  test "rejects malformed WebTransport CONNECT pseudo-headers" do
    assert {:ok, headers} = WebTransport.connect_pseudo_headers("https://example.com/wt")

    assert {:error, {:duplicate_pseudo_header, ":path"}} =
             WebTransport.validate_connect_pseudo_headers(headers ++ [{":path", "/other"}])

    assert {:error, :pseudo_header_after_regular_header} =
             WebTransport.validate_connect_pseudo_headers([{"WT-Protocol", "chat"} | headers])

    assert {:error, {:missing_pseudo_header, ":protocol"}} =
             headers
             |> Enum.reject(fn {name, _value} -> name == ":protocol" end)
             |> WebTransport.validate_connect_pseudo_headers()

    assert {:error, :invalid_connect_protocol} =
             headers
             |> List.keystore(":protocol", 0, {":protocol", "websocket"})
             |> WebTransport.validate_connect_pseudo_headers()
  end

  test "builds and validates client WebTransport settings" do
    settings =
      WebTransport.client_settings(
        initial_max_streams_uni: 3,
        initial_max_streams_bidi: 4,
        initial_max_data: 5
      )

    assert [
             {wt_enabled, 1},
             {h3_datagram, 1},
             {wt_initial_max_streams_uni, 3},
             {wt_initial_max_streams_bidi, 4},
             {wt_initial_max_data, 5}
           ] = settings

    assert wt_enabled == Settings.wt_enabled()
    assert h3_datagram == Settings.h3_datagram()
    assert wt_initial_max_streams_uni == Settings.wt_initial_max_streams_uni()
    assert wt_initial_max_streams_bidi == Settings.wt_initial_max_streams_bidi()
    assert wt_initial_max_data == Settings.wt_initial_max_data()
    assert :ok = WebTransport.validate_client_settings(settings)
  end

  test "validates server WebTransport settings" do
    assert :ok =
             WebTransport.validate_server_settings(
               wt_enabled: 1,
               enable_connect_protocol: 1,
               h3_datagram: 1
             )

    assert {:error, :webtransport_not_enabled} =
             WebTransport.validate_server_settings(enable_connect_protocol: 1, h3_datagram: 1)

    assert {:error, :extended_connect_disabled} =
             WebTransport.validate_server_settings(wt_enabled: 1, h3_datagram: 1)

    assert {:error, :h3_datagram_disabled} =
             WebTransport.validate_server_settings(
               wt_enabled: 1,
               enable_connect_protocol: 1
             )
  end
end
