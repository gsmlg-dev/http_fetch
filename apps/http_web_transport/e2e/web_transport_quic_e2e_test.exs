defmodule E2E.WebTransportQUICE2ETest do
  use ExUnit.Case, async: false

  require Logger

  alias HTTP.WebTransport
  alias HTTP.WebTransport.DatagramDuplexStream
  alias HTTP.WebTransport.DatagramsWritable

  @moduletag :e2e
  @moduletag timeout: 30_000

  @certfile Path.expand("../../http_fetch/test/support/fixtures/localhost.pem", __DIR__)
  @keyfile Path.expand("../../http_fetch/test/support/fixtures/localhost.key", __DIR__)

  setup_all do
    previous_level = Logger.level()
    Logger.configure(level: :warning)

    on_exit(fn -> Logger.configure(level: previous_level) end)
  end

  test "connects with the default QUIC backend over HTTP/3" do
    test_pid = self()

    url =
      start_webtransport_server!(fn conn, stream_id, method, path, headers ->
        send(test_pid, {:webtransport_connect, method, path, headers})
        :ok = :quic_h3.send_response(conn, stream_id, 200, [{"x-webtransport", "ok"}])
      end)

    transport =
      WebTransport.new(url,
        ssl: [verify: :verify_none],
        connect_timeout: 5_000,
        protocols: ["chat.v1"],
        require_unreliable: true
      )

    assert %WebTransport{} = transport
    assert :ok = WebTransport.await_ready(transport, 5_000)
    assert WebTransport.state(transport) == :connected
    assert WebTransport.protocol(transport) == "chat.v1"
    assert WebTransport.reliability(transport) == "supports-unreliable"
    assert {"X-Webtransport", "ok"} in WebTransport.response_headers(transport)

    datagrams = WebTransport.datagrams(transport)
    writable = DatagramDuplexStream.create_writable(datagrams)
    assert %DatagramsWritable{} = writable
    assert :ok = DatagramsWritable.write(writable, "client-datagram")

    assert_receive {:webtransport_connect, <<"CONNECT">>, <<"/transport">>, headers}
    assert {<<":protocol">>, <<"webtransport-h3">>} in headers

    assert :ok = WebTransport.close(transport, close_code: 0, reason: "done")
  end

  defp start_webtransport_server!(handler) do
    :ok = ensure_quic_started!()

    name = :"webtransport_e2e_#{System.unique_integer([:positive])}"

    {:ok, _pid} =
      :quic_h3.start_server(name, 0, %{
        cert: cert_der(),
        key: private_key(),
        handler: handler,
        h3_datagram_enabled: true,
        settings: %{
          wt_enabled: 1,
          enable_connect_protocol: 1,
          h3_datagram: 1
        }
      })

    {:ok, port} = :quic.get_server_port(name)

    on_exit(fn -> :quic_h3.stop_server(name) end)

    "https://localhost:#{port}/transport"
  end

  defp ensure_quic_started! do
    case Application.ensure_all_started(:quic) do
      {:ok, _apps} -> :ok
      {:error, reason} -> raise "failed to start quic: #{inspect(reason)}"
    end
  end

  defp cert_der do
    @certfile
    |> pem_entries()
    |> Enum.find_value(fn
      {:Certificate, der, _} -> der
      _entry -> nil
    end)
  end

  defp private_key do
    @keyfile
    |> pem_entries()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp pem_entries(path) do
    path
    |> File.read!()
    |> :public_key.pem_decode()
  end
end
