# Candidate source checkout only; run through ex_ssl_source_smoke.sh.
for fixture <- ["signature_fixtures.ex", "client_auth_fixtures.ex"] do
  Code.require_file(Path.join([System.fetch_env!("EX_SSL_SOURCE_DIR"), "test/support", fixture]))
end

defmodule CandidateMTLSRedirectsTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.ClientAuthFixtures

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "mtls-redirects-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "automatic ex_ssl redirects cannot move a client identity to another origin", %{
    fixtures: f
  } do
    for change <- [:port, :host, :scheme] do
      {source, port} = listener(f)
      {target, target_port} = listener(f)

      destination =
        case change do
          :port -> "https://127.0.0.1:#{target_port}/next"
          :host -> "https://localhost:#{port}/next"
          :scheme -> "http://127.0.0.1:#{port}/next"
        end

      peer = serve(source, f.rsa.der, [redirect(destination)])
      assert {:error, :client_identity_cross_origin_redirect} = fetch(port, f)
      assert :ok = Task.await(peer, 5_000)
      assert {:error, :timeout} = :ssl.transport_accept(target, 0)
      assert {:error, :timeout} = :ssl.transport_accept(source, 0)
      :ssl.close(source)
      :ssl.close(target)
    end
  end

  test "same-origin redirects retain the exact configured client identity", %{fixtures: f} do
    {source, port} = listener(f)
    peer = serve(source, f.rsa.der, [redirect("/next"), ok()])
    response = fetch(port, f)
    assert response.status == 200
    assert response.redirected
    assert HTTP.Response.read_all(response) == "mtls"
    assert :ok = Task.await(peer, 5_000)
  end

  test "DNS host casing does not change client identity origin", %{fixtures: f} do
    {source, port} = listener(f)
    peer = serve(source, f.rsa.der, [redirect("https://LOCALHOST:#{port}/next"), ok()])
    response = fetch_url("https://localhost:#{port}/start", f, [])
    assert response.status == 200
    assert HTTP.Response.read_all(response) == "mtls"
    assert :ok = Task.await(peer, 5_000)
  end

  test "manual redirect lets the caller deliberately reuse an identity in a new request", %{
    fixtures: f
  } do
    {source, port} = listener(f)
    {target, target_port} = listener(f)
    source_peer = serve(source, f.rsa.der, [redirect("https://127.0.0.1:#{target_port}/next")])
    response = fetch(port, f, redirect: :manual)
    assert response.status == 302
    assert :ok = Task.await(source_peer, 5_000)
    assert {:error, :timeout} = :ssl.transport_accept(target, 0)
    target_peer = serve(target, f.rsa.der, [ok()])
    result = fetch(target_port, f)
    assert result.status == 200
    assert HTTP.Response.read_all(result) == "mtls"
    assert :ok = Task.await(target_peer, 5_000)
  end

  test "OTP backend keeps its existing cross-origin client-identity behavior", %{fixtures: f} do
    {source, port} = listener(f)
    {target, target_port} = listener(f)
    source_peer = serve(source, f.rsa.der, [redirect("https://127.0.0.1:#{target_port}/next")])
    target_peer = serve(target, f.rsa.der, [ok()])
    response = fetch(port, f, tls_backend: :ssl)
    assert response.status == 200
    assert HTTP.Response.read_all(response) == "mtls"
    assert :ok = Task.await(source_peer, 5_000)
    assert :ok = Task.await(target_peer, 5_000)
  end

  defp listener(f) do
    {:ok, socket} =
      :ssl.listen(0,
        certfile: f.server.certificate,
        keyfile: f.server.key,
        cacerts: [f.ca.der],
        verify: :verify_peer,
        fail_if_no_peer_cert: true,
        versions: [:"tlsv1.3"],
        active: false,
        mode: :binary,
        reuseaddr: true
      )

    on_exit(fn -> :ssl.close(socket) end)
    {:ok, {_, port}} = :ssl.sockname(socket)
    {socket, port}
  end

  defp serve(listener, expected, responses) do
    task =
      Task.async(fn ->
        Enum.each(responses, fn response ->
          {:ok, transport} = :ssl.transport_accept(listener, 5_000)
          {:ok, socket} = :ssl.handshake(transport, 5_000)

          try do
            assert {:ok, ^expected} = :ssl.peercert(socket)
            headers(socket, <<>>)
            assert :ok = :ssl.send(socket, response)
          after
            :ssl.close(socket)
          end
        end)
      end)

    on_exit(fn -> if Process.alive?(task.pid), do: Process.exit(task.pid, :kill) end)
    task
  end

  defp headers(socket, buffer) do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      assert {:ok, data} = :ssl.recv(socket, 0, 5_000)
      headers(socket, buffer <> data)
    else
      buffer
    end
  end

  defp fetch(port, f, extra \\ []) do
    fetch_url("https://127.0.0.1:#{port}/start", f, extra)
  end

  defp fetch_url(url, f, extra) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          tls_backend: :ex_ssl,
          timeout: 5_000,
          ssl: [
            cacerts: [f.ca.der],
            server_name_indication: ~c"exssl.test",
            certfile: f.rsa.certificate,
            keyfile: f.rsa.key
          ]
        ],
        extra
      )
    )
    |> HTTP.Promise.await(5_000)
  end

  defp redirect(url),
    do: "HTTP/1.1 302 Found\r\nLocation: #{url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

  defp ok, do: "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nmtls"
end
