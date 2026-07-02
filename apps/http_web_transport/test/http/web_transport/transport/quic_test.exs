defmodule HTTP.WebTransport.Transport.QUICTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.Transport.QUIC

  test "default backend module exposes the QUIC transport contract" do
    assert {:ok, options} = Options.new("https://example.com/transport")
    assert options.backend == QUIC
    assert Code.ensure_loaded?(QUIC)
    assert function_exported?(QUIC, :connect, 2)
  end

  test "rejects invalid H3 WebTransport CONNECT targets before backend setup" do
    assert {:ok, options} = Options.new("https://example.com/transport")

    assert {:error, {:unsupported_scheme, "http"}} =
             QUIC.connect(URI.parse("http://example.com/transport"), options)

    assert {:error, :fragment_not_allowed} =
             QUIC.connect(URI.parse("https://example.com/transport#frag"), options)
  end

  test "rejects non-normalized backend inputs" do
    assert {:error, :invalid_quic_connect_options} =
             QUIC.connect(URI.parse("https://example.com/"), [])
  end

  test "closes an established QUIC connection when CONNECT is rejected" do
    test_pid = self()

    assert {:ok, options} =
             Options.new("https://example.com/transport",
               quic: [quic_ops: __MODULE__.FakeOps, test_pid: test_pid]
             )

    assert {:error, {:webtransport_connect_failed, 404}} =
             QUIC.connect(URI.parse("https://example.com/transport"), options)

    assert_receive {:fake_quic_closed, ^test_pid}
  end

  defmodule FakeOps do
    def connect(_host, _port, %{quic_opts: %{test_pid: test_pid}}), do: {:ok, test_pid}

    def wait_connected(_conn, _timeout), do: :ok

    def request(conn, _headers, _options) do
      send(self(), {:quic_h3, conn, {:response, 1, 404, []}})
      {:ok, 1}
    end

    def close(conn) do
      send(conn, {:fake_quic_closed, self()})
      :ok
    end

    def get_peer_settings(_conn), do: :undefined
    def h3_datagrams_enabled(_conn), do: false
    def max_datagram_size(_conn, _stream_id), do: 0
  end
end
