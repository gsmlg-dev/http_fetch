defmodule HTTP.Runtime.NamedPoolIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias HTTP.{Promise, RequestCompletion, Response}
  alias HTTP.Runtime.Pool
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  test "real H1 reuse routes to isolated families and enforces total idle retention" do
    {url, peer} = h1_peer()
    a = start_supervised!({Pool, name: "h1-a", http1: [max_idle_per_key: 1, max_idle: 1]})
    b = start_supervised!({Pool, name: "h1-b", http1: [max_idle_per_key: 1, max_idle: 1]})
    assert fetch(url, pool: a).body == "1"
    assert fetch(url, pool: a).body == "1"
    assert fetch(url, pool: b).body == "2"
    assert fetch(url, pool: a, http1_scope: "different").body == "3"
    assert {:ok, a_ref} = Pool.reference(a)
    assert {:ok, b_ref} = Pool.reference(b)
    assert {:ok, %{http1: %{idle: 1, max_idle: 1}}} = HTTP.Pool.snapshot(a_ref)
    assert {:ok, %{http1: %{idle: 1, max_idle: 1}}} = HTTP.Pool.snapshot(b_ref)
    assert fetch(url, pool: a).body == "1"
    send(peer, :stop)
  end

  test "real H2 local stream limit queues the second request in the selected family" do
    parent = self()

    {url, peer} =
      Peer.start(parent, fn socket ->
        {first, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, first, <<0x88>>))
        send(parent, :first_headers)

        receive do
          :finish_first -> :ok
        end

        :ok = :gen_tcp.send(socket, Peer.frame(0, 1, first, "one"))
        {second, true} = Peer.request(socket)
        :ok = Peer.response(socket, second, "two")
      end)

    family =
      start_supervised!(
        {Pool,
         http2: [max_connections: 1, max_total_connections: 1, max_streams: 1, max_pending: 1]}
      )

    {:ok, ref} = Pool.reference(family)
    opts = [pool: ref, http_version: :h2c, redirect: :manual, timeout: 3_000]
    first = HTTP.fetch(url, opts)
    first_response = Promise.await(first)
    assert_receive :first_headers
    assert {:ok, %{http2: %{connections: 1, streams: 1}}} = HTTP.Pool.snapshot(ref)
    second = HTTP.fetch(url, opts)
    # Observe the actual queue insertion, not a scheduling delay.
    :sys.get_state(ref.http2)
    assert_pending(ref.http2, second.task.pid)
    assert {:ok, %{http2: %{connections: 1, streams: 1, pending: 1}}} = HTTP.Pool.snapshot(ref)
    send(peer, :finish_first)
    assert Response.read_all(first_response) == "one"
    assert Response.read_all(Promise.await(second)) == "two"
    assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "a family dying after caller preparation fails before any network attempt" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    name = "dies-after-prepare"
    family = start_supervised!({Pool, name: name})

    prepared =
      for protocol <- [:http1, :h2c] do
        request = %HTTP.Request{
          url: URI.parse("http://127.0.0.1:#{port}/"),
          transport_options: [
            pool: family,
            http_version: protocol,
            redirect: :manual,
            timeout: 100
          ]
        }

        {:ok, bound} = Pool.prepare(request, pool: family)
        bound
      end

    :ok = stop_supervised({Pool, name})

    for bound <- prepared do
      assert {:error, :stale_pool} = HTTP.SocketClient.request(bound)
    end

    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  test "a non-reusable identity after preparation cannot bypass an explicitly selected pool" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    family = start_supervised!({Pool, []})

    for protocol <- [:http1, :h2c] do
      request = %HTTP.Request{
        url: URI.parse("http://127.0.0.1:#{port}/"),
        transport_options: [pool: family, http_version: protocol, redirect: :manual, timeout: 100]
      }

      {:ok, bound} = Pool.prepare(request, pool: family)
      opaque = if protocol == :http1, do: :http1_scope, else: :http2_scope
      changed = %{bound | transport_options: Keyword.put(bound.transport_options, opaque, self())}

      assert {:error, {:invalid_pool_option, :identity, :non_reusable}} =
               HTTP.SocketClient.request(changed)
    end

    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  defp assert_pending(pool, worker) do
    monitor = Process.monitor(worker)
    :erlang.trace(pool, true, [:receive])

    try do
      if Enum.sum(for {_, entry} <- HTTP.HTTP2.Pool.stats(pool), do: entry.pending) == 0 do
        receive do
          {:trace, ^pool, :receive, {:"$gen_call", _, {:reserve, _, _}}} ->
            :ok

          {:DOWN, ^monitor, :process, ^worker, reason} ->
            flunk("request ended before queueing: #{inspect(reason)}")
        after
          2_000 -> flunk("request did not enter the selected pool")
        end
      end

      assert Enum.sum(for {_, entry} <- HTTP.HTTP2.Pool.stats(pool), do: entry.pending) == 1
    after
      :erlang.trace(pool, false, [:receive])
      Process.demonitor(monitor, [:flush])
    end
  end

  defp fetch(url, opts) do
    promise = HTTP.fetch(url, Keyword.merge([redirect: :manual, timeout: 2_000], opts))
    assert %Response{} = response = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    response
  end

  defp h1_peer do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    peer = spawn_link(fn -> accept(listener, 1) end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(peer), do: Process.exit(peer, :shutdown)
    end)

    {"http://127.0.0.1:#{port}/", peer}
  end

  defp accept(listener, id) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        worker =
          spawn_link(fn ->
            receive do
              {:socket, owned} -> serve(owned, Integer.to_string(id))
            end
          end)

        :ok = :gen_tcp.controlling_process(socket, worker)
        send(worker, {:socket, socket})
        accept(listener, id + 1)

      {:error, :closed} ->
        :ok
    end
  end

  defp serve(socket, body) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, _} ->
        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(body)}\r\n\r\n#{body}"
          )

        serve(socket, body)

      {:error, _} ->
        :gen_tcp.close(socket)
    end
  end
end
