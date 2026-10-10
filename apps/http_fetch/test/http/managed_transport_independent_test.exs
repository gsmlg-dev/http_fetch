defmodule HTTP.ManagedTransportIndependentTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @fixtures Path.expand("../../../http_web_socket/test/support/fixtures", __DIR__)

  test "repeated reuse keeps a fixed retained resource ledger" do
    parent = self()
    {origin, listener} = listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        for _ <- 1..21, do: serve(socket, parent, :reuse_request)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 3_000)
        :gen_tcp.close(listener)
      end)

    scope = open(origin)
    assert drain(fetch(origin, scope)) == "ok"
    before = idle_snapshot(scope)
    for _ <- 1..20, do: assert(drain(fetch(origin, scope)) == "ok")
    after_reuse = idle_snapshot(scope)
    assert after_reuse.connections == 1
    assert after_reuse.resources == before.resources
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert :ok = Task.await(peer, 3_000)
  end

  test "a reused socket failure never replays an admitted POST" do
    parent = self()
    {origin, listener} = listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        serve(socket, parent, :primed)

        assert {:ok, "POST /raw?x=1 HTTP/1.1\r\n" <> head} =
                 :gen_tcp.recv(socket, 0, 3_000)

        assert head =~ "Content-Length: 4\r\n"
        :gen_tcp.close(socket)
        send(parent, :post_connection_closed)
        assert {:error, :timeout} = :gen_tcp.accept(listener, 200)
        send(parent, :no_replay_connection)
        :gen_tcp.close(listener)
      end)

    scope = open(origin)
    assert drain(fetch(origin, scope)) == "ok"
    post = fetch(origin, scope, method: :post, body: "once")
    assert {:error, _} = Promise.await(post)
    assert_receive :post_connection_closed
    assert_receive :no_replay_connection, 2_000
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert :ok = Task.await(peer, 3_000)
  end

  test "H2 sibling survives cancellation and drains before whole-scope retirement" do
    parent = self()

    {url, peer} =
      Peer.start(parent, fn socket ->
        {first_id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, first_id, <<0x88>>))
        {second_id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, second_id, <<0x88>>))
        await_reset(socket, first_id)
        send(parent, :managed_reset_observed)

        receive do
          :finish_sibling -> :ok
        after
          5_000 -> flunk("missing sibling completion barrier")
        end

        :ok = :gen_tcp.send(socket, Peer.frame(0, 1, second_id, "survived"))
        assert_closed(socket)
        send(parent, :managed_h2_closed)
      end)

    uri = URI.parse(url)
    origin = "http://localhost:#{uri.port}"
    scope = open(origin, http_version: :h2c, max_connections: 1, max_requests: 2)
    first = fetch(origin, scope)
    assert %Response{} = Promise.await(first)
    second = fetch(origin, scope)
    assert %Response{} = sibling = Promise.await(second)
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(first), 3_000)
    assert_receive :managed_reset_observed
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 0)
    send(peer, :finish_sibling)
    assert Response.read_all(sibling) == "survived"
    assert :ok = RequestCompletion.await(Promise.completion(second), 3_000)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert_receive :managed_h2_closed
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "TLS trust files are frozen before dialing and origin authority is preserved" do
    parent = self()
    ca = Path.join(System.tmp_dir!(), "managed-ca-#{System.unique_integer([:positive])}.pem")
    File.cp!(Path.join(@fixtures, "localhost-ca.pem"), ca)
    on_exit(fn -> File.rm(ca) end)

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
    origin = "https://localhost:#{port}"

    peer =
      Task.async(fn ->
        {:ok, accepted} = :ssl.transport_accept(listener, 3_000)
        {:ok, socket} = :ssl.handshake(accepted, 3_000)
        assert {:ok, head} = :ssl.recv(socket, 0, 3_000)
        assert head =~ "Host: localhost:#{port}\r\n"
        :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        send(parent, :frozen_tls_verified)
        assert {:error, :closed} = :ssl.recv(socket, 0, 3_000)
        :ssl.close(listener)
      end)

    scope = open(origin, ssl: [verify: :verify_peer, cacertfile: ca])
    File.rm!(ca)
    assert drain(fetch(origin, scope)) == "ok"
    assert_receive :frozen_tls_verified
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert :ok = Task.await(peer, 3_000)
  end

  test "old generation retirement closes its idle socket while a new generation serves" do
    parent = self()
    {origin, listener} = listener()

    peer =
      Task.async(fn ->
        {:ok, old} = :gen_tcp.accept(listener, 3_000)
        serve(old, parent, :old_first)
        serve(old, parent, :old_reused)
        {:ok, fresh} = :gen_tcp.accept(listener, 3_000)
        serve(fresh, parent, :new_first)
        assert {:error, :closed} = :gen_tcp.recv(old, 0, 3_000)
        send(parent, :old_closed)
        serve(fresh, parent, :new_survived)
        assert {:error, :closed} = :gen_tcp.recv(fresh, 0, 3_000)
        :gen_tcp.close(listener)
      end)

    old = open(origin)
    fresh = open(origin)
    assert drain(fetch(origin, old)) == "ok"
    assert drain(fetch(origin, old)) == "ok"
    assert drain(fetch(origin, fresh)) == "ok"
    assert_receive :old_first
    assert_receive :old_reused
    assert_receive :new_first
    assert {:ok, receipt} = ManagedTransport.retire(old, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert :ok = ManagedTransport.await_retired(receipt, 0)
    assert_receive :old_closed
    assert drain(fetch(origin, fresh)) == "ok"
    assert_receive :new_survived
    assert {:ok, receipt} = ManagedTransport.retire(fresh, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert :ok = Task.await(peer, 3_000)
  end

  test "request capacity lasts through unread body and graceful timeout remains pending" do
    parent = self()
    {origin, listener} = listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        assert {:ok, _} = :gen_tcp.recv(socket, 0, 3_000)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef")
        send(parent, :body_sent)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 3_000)
        send(parent, :retired_peer_closed)
        :gen_tcp.close(listener)
      end)

    scope = open(origin, max_requests: 1)
    first = fetch(origin, scope)
    assert %Response{} = response = Promise.await(first)
    assert_receive :body_sent

    assert {:error, {:transport_scope_capacity, :requests}} =
             Promise.await(fetch(origin, scope))

    assert {:ok, %{active_requests: 1, pending: 0}} = ManagedTransport.snapshot(scope, 100)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 0)
    assert {:error, :transport_scope_retired} = Promise.await(fetch(origin, scope))
    assert Response.read_all(response) == "abcdef"
    assert :ok = RequestCompletion.await(Promise.completion(first), 3_000)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert_receive :retired_peer_closed
    assert :ok = Task.await(peer, 3_000)
  end

  test "abort retirement settles a stalled raw response and acknowledges peer closure" do
    parent = self()
    {origin, listener} = listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        assert {:ok, _} = :gen_tcp.recv(socket, 0, 3_000)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nraw")
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 3_000)
        send(parent, :abort_peer_closed)
        :gen_tcp.close(listener)
      end)

    scope = open(origin)
    promise = fetch(origin, scope)
    assert %Response{stream: stream} = Promise.await(promise)
    monitor = Process.monitor(stream)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    assert_receive {:DOWN, ^monitor, :process, ^stream, _}
    assert_receive :abort_peer_closed
    assert :ok = Task.await(peer, 3_000)
  end

  defp listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {"http://127.0.0.1:#{port}", listener}
  end

  defp open(origin, extra \\ []) do
    assert {:ok, scope} =
             ManagedTransport.open(
               Keyword.merge(
                 [origin: origin, connect_address: {127, 0, 0, 1}, http_version: :http1],
                 extra
               )
             )

    scope
  end

  defp fetch(origin, scope, extra \\ []) do
    HTTP.fetch(
      origin <> "/raw?x=1",
      Keyword.merge(
        [
          transport_scope: scope,
          redirect: :manual,
          stream_response: true,
          decode_body: false,
          timeout: 5_000
        ],
        extra
      )
    )
  end

  defp drain(promise) do
    assert %Response{} = response = Promise.await(promise)
    bytes = Response.read_all(response)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 3_000)
    bytes
  end

  defp serve(socket, parent, label) do
    assert {:ok, "GET /raw?x=1 HTTP/1.1\r\n" <> _} = :gen_tcp.recv(socket, 0, 3_000)
    :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    send(parent, label)
  end

  defp await_reset(socket, id) do
    case Peer.recv(socket) do
      {3, _, ^id, _} -> :ok
      _ -> await_reset(socket, id)
    end
  end

  defp assert_closed(socket) do
    case :gen_tcp.recv(socket, 0, 3_000) do
      {:ok, _control_frames} -> assert_closed(socket)
      result -> assert result == {:error, :closed}
    end
  end

  defp idle_snapshot(scope, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 3_000
    assert {:ok, snapshot} = ManagedTransport.snapshot(scope, 100)

    if snapshot.active_requests == 0 do
      snapshot
    else
      assert System.monotonic_time(:millisecond) < deadline
      idle_snapshot(scope, deadline)
    end
  end
end
