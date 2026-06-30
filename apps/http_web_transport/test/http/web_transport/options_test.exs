defmodule HTTP.WebTransport.OptionsTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport.FakeBackend
  alias HTTP.WebTransport.Options

  test "normalizes supported URL scheme" do
    assert {:ok, %{uri: %{scheme: "https"}, url: "https://example.com/transport"}} =
             Options.new("https://example.com/transport")
  end

  test "rejects unsupported URLs and fragments" do
    assert {:error, {:unsupported_scheme, "http"}} = Options.new("http://example.com/transport")
    assert {:error, {:unsupported_scheme, nil}} = Options.new("/transport")
    assert {:error, :fragment_not_allowed} = Options.new("https://example.com/transport#frag")
  end

  test "normalizes flat init options" do
    assert {:ok, options} =
             Options.new("https://example.com/transport",
               owner: self(),
               allow_pooling: true,
               require_unreliable: true,
               headers: %{"x-token" => "abc"},
               congestion_control: :low_latency,
               anticipated_concurrent_incoming_unidirectional_streams: 2,
               anticipated_concurrent_incoming_bidirectional_streams: 3,
               protocols: ["chat.v1"],
               datagrams_readable_type: :bytes,
               backend: FakeBackend,
               connect_timeout: 10,
               idle_timeout: 20,
               ssl: [verify: :verify_none],
               quic: [alpn: "h3"],
               socket_opts: [active: false],
               max_incoming_datagrams: 4,
               max_outgoing_datagrams: 5,
               max_datagram_size: 6
             )

    assert options.owner == self()
    assert options.allow_pooling == true
    assert options.require_unreliable == true
    assert {"X-Token", "abc"} in options.headers
    assert options.congestion_control == :low_latency
    assert options.anticipated_concurrent_incoming_unidirectional_streams == 2
    assert options.anticipated_concurrent_incoming_bidirectional_streams == 3
    assert options.protocols == ["chat.v1"]
    assert options.datagrams_readable_type == :bytes
    assert options.backend == FakeBackend
    assert options.connect_timeout == 10
    assert options.idle_timeout == 20
    assert options.ssl == [verify: :verify_none]
    assert options.quic == [alpn: "h3"]
    assert options.socket_opts == [active: false]
    assert options.max_incoming_datagrams == 4
    assert options.max_outgoing_datagrams == 5
    assert options.max_datagram_size == 6
  end

  test "normalizes browser-style string keys" do
    assert {:ok, %{require_unreliable: true, congestion_control: :throughput}} =
             Options.new("https://example.com/transport", %{
               "requireUnreliable" => true,
               "congestionControl" => "throughput"
             })
  end

  test "rejects invalid init options" do
    assert {:error, :invalid_owner} =
             Options.new("https://example.com/transport", owner: :bad)

    assert {:error, :duplicate_protocol} =
             Options.new("https://example.com/transport", protocols: ["chat", "chat"])

    assert {:error, :unsupported_server_certificate_hashes} =
             Options.new("https://example.com/transport",
               server_certificate_hashes: [%{algorithm: "sha-256", value: <<0>>}]
             )
  end
end
