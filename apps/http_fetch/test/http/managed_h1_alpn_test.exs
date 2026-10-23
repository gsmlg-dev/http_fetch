defmodule HTTP.ManagedH1ALPNTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  @fixtures Path.expand("../support/fixtures", __DIR__)

  for advertise? <- [false, true] do
    test "verified H1 TLS advertise=#{advertise?} keeps bytes, reuse and public retirement" do
      {peer, origin} = peer()
      options = ssl()

      options =
        if unquote(advertise?),
          do: options ++ [alpn_advertised_protocols: ["http/1.1"]],
          else: options

      scope = open(origin, options)
      first = fetch(origin <> "/first?x=1", scope)
      assert %Response{status: 200} = response = Promise.await(first, 5_000)

      assert event(peer, "tls") == %{
               "event" => "tls",
               "alpn" => if(unquote(advertise?), do: "http/1.1", else: nil),
               "sni" => "localhost"
             }

      assert event(peer, "request") == %{
               "event" => "request",
               "line" => "GET /first?x=1 HTTP/1.1",
               "host" => "localhost:#{URI.parse(origin).port}",
               "body" => "",
               "content_length" => ""
             }

      assert Response.read_all(response) == <<0, 255, 10, 13>>
      assert :ok = RequestCompletion.await(Promise.completion(first), 3_000)

      conflicting = Keyword.put(options, :alpn_advertised_protocols, ["h2"])

      for overrides <- [[ssl: conflicting], [http_version: :http2], [tls_backend: :ex_ssl]] do
        assert {:error, :transport_scope_policy_mismatch} =
                 Promise.await(fetch(origin <> "/override", scope, overrides))
      end

      body = <<0, 13, 10, 255, 42>>
      second = fetch(origin <> "/second", scope, method: :post, body: body)
      assert %Response{status: 200} = response = Promise.await(second, 5_000)

      assert event(peer, "request") == %{
               "event" => "request",
               "line" => "POST /second HTTP/1.1",
               "host" => "localhost:#{URI.parse(origin).port}",
               "body" => Base.encode16(body, case: :lower),
               "content_length" => "5"
             }

      assert Response.read_all(response) == <<0, 255, 10, 13>>
      assert :ok = RequestCompletion.await(Promise.completion(second), 3_000)
      assert {:ok, %{connections: 1, active_requests: 0}} = ManagedTransport.snapshot(scope, 100)
      retire(scope)
      assert %{"event" => "closed", "transport" => closure} = event(peer, "closed")
      assert closure in ["eof", "reset"]

      assert event(peer, "complete") == %{
               "event" => "complete",
               "connections" => 1,
               "requests" => 2
             }

      assert_exit(peer)
    end
  end

  test "negotiated H1 never replays a POST after its reused TLS peer closes" do
    {peer, origin} = peer(["--drop"])
    scope = open(origin, ssl() ++ [alpn_advertised_protocols: ["http/1.1"]])
    first = fetch(origin <> "/first?x=1", scope)
    assert %Response{} = response = Promise.await(first, 5_000)
    assert event(peer, "tls")["alpn"] == "http/1.1"
    assert event(peer, "request")["line"] == "GET /first?x=1 HTTP/1.1"
    assert Response.read_all(response) == <<0, 255, 10, 13>>
    assert :ok = RequestCompletion.await(Promise.completion(first), 3_000)
    second = fetch(origin <> "/second", scope, method: :post, body: "once")
    assert {:error, _} = Promise.await(second, 5_000)
    assert event(peer, "request")["body"] == Base.encode16("once", case: :lower)
    assert :ok = RequestCompletion.await(Promise.completion(second), 3_000)
    retire(scope)

    assert event(peer, "complete") == %{
             "event" => "complete",
             "connections" => 1,
             "requests" => 2
           }

    assert_exit(peer)
  end

  defp ssl do
    [{:Certificate, der, :not_encrypted}] =
      @fixtures |> Path.join("localhost-ca.pem") |> File.read!() |> :public_key.pem_decode()

    [
      verify: :verify_peer,
      depth: 4,
      versions: [:"tlsv1.3", :"tlsv1.2"],
      cacerts: [der],
      server_name_indication: ~c"localhost"
    ]
  end

  defp open(origin, ssl) do
    assert {:ok, scope} =
             ManagedTransport.open(
               origin: origin,
               connect_address: {127, 0, 0, 1},
               http_version: :http1,
               tls_backend: :ssl,
               max_connections: 2,
               max_requests: 32,
               max_pending: 0,
               ssl: ssl
             )

    on_exit(fn ->
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      _ = ManagedTransport.await_retired(receipt, 3_000)
    end)

    scope
  end

  defp fetch(url, scope, opts \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          transport_scope: scope,
          redirect: :manual,
          stream_response: true,
          decode_body: false,
          timeout: 3_000
        ],
        opts
      )
    )
  end

  defp retire(scope) do
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert :ok = ManagedTransport.await_retired(receipt, 0)
  end

  defp peer(opts \\ []) do
    python = System.find_executable("python3") || raise "python3 is required for independent TLS"

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 65_536},
        args:
          [
            Path.expand("../support/managed_h1_alpn_peer.py", __DIR__),
            Path.join(@fixtures, "localhost.pem"),
            Path.join(@fixtures, "localhost.key")
          ] ++ opts
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    {port, "https://localhost:#{event(port, "ready")["port"]}"}
  end

  defp event(port, name) do
    receive do
      {^port, {:data, {:eol, data}}} ->
        event = JSON.decode!(data)
        assert event["event"] == name
        event

      {^port, {:exit_status, status}} ->
        flunk("TLS peer exited #{status} before #{name}")
    after
      5_000 -> flunk("missing TLS peer event #{name}")
    end
  end

  defp assert_exit(port) do
    assert_receive {^port, {:exit_status, 0}}, 5_000
  end
end
