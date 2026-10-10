defmodule HTTP.ManagedTransportTLSBackingTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "borrowed CA preparation preserves verification, digest, overrides and redaction" do
    {origin, listener} = listener()
    peer = peer(listener)
    {scope, input_bytes, backing_bytes} = borrowed_scope(origin, "localhost-ca.pem")
    assert backing_bytes > input_bytes
    :erlang.garbage_collect(self())
    ca = ca("localhost-ca.pem")
    compact = open(origin, ssl(ca))

    assert {:ok, snapshot} = ManagedTransport.snapshot(scope, 100)
    assert {:ok, compact_snapshot} = ManagedTransport.snapshot(compact, 100)
    assert snapshot.identity == compact_snapshot.identity
    assert snapshot.active_requests == 0
    assert snapshot.connections == 0

    assert Map.keys(snapshot) |> Enum.sort() ==
             Enum.sort([
               :active_requests,
               :pending,
               :preparing_requests,
               :connections,
               :resources,
               :limits,
               :identity,
               :lifecycle
             ])

    assert {:error, :timeout} = :ssl.transport_accept(listener, 0)
    promise = fetch(origin, scope, ssl: ssl(ca))
    assert %Response{status: 200} = response = Promise.await(promise)
    assert Response.read_all(response) == "verified"
    assert :ok = RequestCompletion.await(Promise.completion(promise), 3_000)
    assert {:request, ~c"localhost", head} = Task.await(peer, 3_000)
    assert head =~ "GET /verified HTTP/1.1\r\n"
    assert head =~ "Host: localhost:#{URI.parse(origin).port}\r\n"
    retire(scope)

    assert {:ok, %{lifecycle: :open, active_requests: 0}} =
             ManagedTransport.snapshot(compact, 100)

    retire(compact)
  end

  for {host, ca_file, alert} <- [
        {"localhost", "pinned-ca.pem", :unknown_ca},
        {"wrong.invalid", "localhost-ca.pem", :bad_certificate}
      ] do
    test "borrowed CA keeps #{alert} refusal without HTTP bytes or replay" do
      {origin, listener} = listener(unquote(host))
      peer = peer(listener)
      {scope, input_bytes, backing_bytes} = borrowed_scope(origin, unquote(ca_file))
      assert backing_bytes > input_bytes
      :erlang.garbage_collect(self())
      promise = fetch(origin, scope)
      assert {:error, {:tls_alert, {unquote(alert), _}}} = Promise.await(promise)

      assert {:error, :cleanup_unconfirmed} =
               RequestCompletion.await(Promise.completion(promise), 3_000)

      assert {:handshake_error, _} = Task.await(peer, 3_000)
      assert {:error, :timeout} = :ssl.transport_accept(listener, 100)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 3_000)
      assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 0)
      assert {:error, :transport_scope_retired} = Promise.await(fetch(origin, scope))
    end
  end

  defp borrowed_scope(origin, name) do
    parent = self()

    {helper, monitor} =
      spawn_monitor(fn ->
        der = ca(name)
        backing = der <> :binary.copy(<<0>>, 8 * 1_048_576)
        slice = binary_part(backing, 0, byte_size(der))
        bytes = :binary.referenced_byte_size(slice)
        assert bytes > byte_size(slice)
        send(parent, {:borrowed_ca, self(), slice, bytes})
      end)

    receive do
      {:borrowed_ca, ^helper, der, backing_bytes} ->
        assert_receive {:DOWN, ^monitor, :process, ^helper, :normal}
        # This caller creates and keeps the scope alive; the producer has exited.
        ssl_options =
          if URI.parse(origin).host == "localhost",
            do: ssl(der),
            else: [verify: :verify_peer, cacerts: [der]]

        scope = open(origin, ssl_options)
        {scope, byte_size(der), backing_bytes}
    after
      3_000 -> flunk("missing finite borrowed CA fixture")
    end
  end

  defp ca(name) do
    [{:Certificate, der, :not_encrypted}] =
      @fixtures |> Path.join(name) |> File.read!() |> :public_key.pem_decode()

    der
  end

  defp ssl(der) do
    [
      server_name_indication: ~c"localhost",
      depth: 4,
      versions: [:"tlsv1.3", :"tlsv1.2"],
      verify: :verify_peer,
      cacerts: [der]
    ]
  end

  defp open(origin, ssl) do
    assert {:ok, scope} =
             ManagedTransport.open(
               origin: origin,
               connect_address: {127, 0, 0, 1},
               http_version: :http1,
               max_connections: 2,
               max_requests: 32,
               max_pending: 0,
               idle_timeout: 30_000,
               socket_opts: [
                 buffer: 8_192,
                 recbuf: 8_192,
                 sndbuf: 8_192,
                 send_timeout: 1_000,
                 send_timeout_close: true
               ],
               ssl: ssl
             )

    on_exit(fn ->
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      _ = ManagedTransport.await_retired(receipt, 3_000)
    end)

    scope
  end

  defp listener(host \\ "localhost") do
    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1},
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key")
      )

    on_exit(fn -> :ssl.close(listener) end)
    {:ok, {_, port}} = :ssl.sockname(listener)
    {"https://#{host}:#{port}", listener}
  end

  defp peer(listener) do
    task =
      Task.async(fn ->
        {:ok, accepted} = :ssl.transport_accept(listener, 3_000)

        case :ssl.handshake(accepted, 3_000) do
          {:ok, socket} ->
            {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
            {:ok, head} = :ssl.recv(socket, 0, 3_000)

            :ok =
              :ssl.send(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nverified"
              )

            :ssl.close(socket)
            {:request, info[:sni_hostname], head}

          {:error, reason} ->
            {:handshake_error, reason}
        end
      end)

    on_exit(fn -> if Process.alive?(task.pid), do: Process.exit(task.pid, :kill) end)
    task
  end

  defp fetch(origin, scope, opts \\ []) do
    HTTP.fetch(
      origin <> "/verified",
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
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
  end
end
