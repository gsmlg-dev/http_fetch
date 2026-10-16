defmodule HTTP.ResponseStreamAckOptionsTest do
  use ExUnit.Case, async: true

  alias HTTP.FetchOptions

  test "response stream acknowledgement policy normalizes aliases and forwards independently" do
    for key <- [
          :response_stream_ack_timeout,
          "response_stream_ack_timeout",
          "responseStreamAckTimeout"
        ],
        value <- [nil, 1, 123_000, 4_294_967_295, :infinity] do
      options = FetchOptions.new(%{key => value})
      assert Map.get(options, :response_stream_ack_timeout) == value
      assert FetchOptions.to_transport_options(options)[:response_stream_ack_timeout] == value
    end
  end

  test "response stream acknowledgement policy validates bounded positive milliseconds or infinity" do
    for value <- [0, -1, 1.5, "100", "infinity", false, 4_294_967_296] do
      assert_raise ArgumentError, ~r/response_stream_ack_timeout/, fn ->
        FetchOptions.new(response_stream_ack_timeout: value)
      end
    end
  end

  test "explicit policies reject unsupported protocols and managed scopes" do
    for value <- [100, :infinity], version <- [:http2, :h2c, :http3, :auto] do
      assert_raise ArgumentError, ~r/response_stream_ack_timeout.*http1/, fn ->
        FetchOptions.new(response_stream_ack_timeout: value, http_version: version)
      end
    end

    assert_raise ArgumentError, ~r/response_stream_ack_timeout.*transport_scope/, fn ->
      FetchOptions.new(response_stream_ack_timeout: :infinity, transport_scope: make_ref())
    end
  end

  test "nil retains legacy behavior for other protocols and ordinary H1 scopes remain valid" do
    for version <- [:http1, :http2, :h2c, :http3, :auto] do
      assert %{http_version: ^version} =
               FetchOptions.new(response_stream_ack_timeout: nil, http_version: version)
    end

    assert %{http1_scope: "response", response_stream_ack_timeout: :infinity} =
             FetchOptions.new(http1_scope: "response", response_stream_ack_timeout: :infinity)
  end

  test "low-level requests reject policy injection on managed and unsupported routes before I/O" do
    for extra <- [
          [http_version: :auto],
          [http_version: :http2],
          [managed_coordinator: self()],
          [transport_scope: make_ref()]
        ] do
      request = %HTTP.Request{
        url: URI.parse("http://localhost:1/"),
        transport_options:
          Keyword.merge([http_version: :http1, response_stream_ack_timeout: :infinity], extra)
      }

      assert {:error, {:unsupported_response_stream_ack_timeout, _}} =
               HTTP.SocketClient.request(request)
    end
  end
end
