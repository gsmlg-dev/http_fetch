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
               max_incoming_datagrams: 4,
               max_outgoing_datagrams: 5,
               max_datagram_size: 6
             )

    assert options.owner == self()
    assert options.allow_pooling == false
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
    assert options.socket_opts == []
    assert options.max_incoming_datagrams == 4
    assert options.max_outgoing_datagrams == 5
    assert options.max_datagram_size == 6
  end

  test "rejects accepted-but-unimplemented options explicitly" do
    url = "https://example.com/transport"
    assert_invalid(:pooling_unsupported, fn -> Options.new(url, allow_pooling: true) end)

    assert_invalid(:socket_opts_unsupported, fn ->
      Options.new(url, socket_opts: [active: false])
    end)

    assert_invalid(:unsupported_server_certificate_hashes, fn ->
      Options.new(url, server_certificate_hashes: [%{algorithm: "sha-256", value: <<0>>}])
    end)
  end

  test "normalizes browser-style string keys" do
    assert {:ok, %{require_unreliable: true, congestion_control: :throughput}} =
             Options.new("https://example.com/transport", %{
               "requireUnreliable" => true,
               "congestionControl" => "throughput"
             })
  end

  test "rejects invalid init options" do
    assert_invalid(:invalid_owner, fn ->
      Options.new("https://example.com/transport", owner: :bad)
    end)

    assert_invalid(:duplicate_protocol, fn ->
      Options.new("https://example.com/transport", protocols: ["chat", "chat"])
    end)

    assert_invalid(:unsupported_server_certificate_hashes, fn ->
      Options.new("https://example.com/transport",
        server_certificate_hashes: [%{algorithm: "sha-256", value: <<0>>}]
      )
    end)
  end

  test "QUIC TLS is separate from TCP TLS and exposes no tls_backend option" do
    assert {:ok, options} = Options.new("https://example.com/transport")
    refute Map.has_key?(options, :tls_backend)
  end

  test "unknown keys, including the removed tls_backend, raise ArgumentError" do
    for init <- [[tls_backend: :ssl], %{"tls_backend" => :ssl}, [{"tlsBackend", :ssl}]] do
      key = init |> Enum.at(0) |> elem(0)

      assert_raise ArgumentError, "unknown HTTP.WebTransport option: #{inspect(key)}", fn ->
        Options.new("https://example.com/transport", init)
      end
    end

    assert_raise ArgumentError, "unknown HTTP.WebTransport option: :tls_backend", fn ->
      HTTP.WebTransport.new("https://example.com/transport", tls_backend: :ssl)
    end
  end

  test "malformed init raises ArgumentError at the public constructor" do
    for init <- [:bad, [:bad], [{1, :bad}]] do
      assert_invalid(:invalid_options, fn ->
        Options.new("https://example.com/transport", init)
      end)

      assert_invalid(:invalid_options, fn ->
        HTTP.WebTransport.new("https://example.com/transport", init)
      end)
    end
  end

  defp assert_invalid(reason, fun),
    do: assert_raise(ArgumentError, "invalid HTTP.WebTransport options: #{inspect(reason)}", fun)
end
