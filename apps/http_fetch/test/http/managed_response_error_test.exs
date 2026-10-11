defmodule HTTP.ManagedResponseErrorTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @malformed [
    {:chunk_line, :binary.copy("0", 8_193), :line_too_long},
    {:forbidden_trailer, "0\r\nHost: invalid\r\n\r\n", {:forbidden_trailer, "host"}},
    {:excess_trailers, "0\r\n" <> String.duplicate("X: v\r\n", 129) <> "\r\n",
     :trailers_too_large}
  ]

  for {name, bytes, reason} <- @malformed, reader <- [:early, :late] do
    test "H1 #{name} preserves its error for the #{reader} reader" do
      {origin, listener} = listener()
      peer = h1_peer(listener, unquote(bytes))
      scope = open(origin, max_requests: 1)
      promise = fetch(origin, scope)
      completion = Promise.completion(promise)
      assert %Response{body: stream} = Promise.await(promise)

      if unquote(reader) == :early, do: send(stream, {:read_chunk, self(), :ack})
      send(peer.pid, :malformed)
      assert_receive {:peer_closed, pid} when pid == peer.pid, 2_000

      if unquote(reader) == :late do
        assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 30)

        assert {:error, {:transport_scope_capacity, :requests}} =
                 Promise.await(fetch(origin, scope))

        send(stream, {:read_chunk, self(), :ack})
      end

      assert_receive {:stream_error, ^stream, unquote(Macro.escape(reason))}, 2_000
      assert :ok = RequestCompletion.await(completion, 2_000)
      refute_receive {:stream_error, ^stream, _}, 0
      refute_receive {:stream_end, ^stream}, 0
      retire(scope)
      assert :ok = Task.await(peer, 2_000)
    end
  end

  test "abort retirement releases a failed unread H1 response" do
    {origin, listener} = listener()
    peer = h1_peer(listener, :binary.copy("0", 8_193))
    scope = open(origin)
    promise = fetch(origin, scope)
    completion = Promise.completion(promise)
    assert %Response{} = Promise.await(promise)
    send(peer.pid, :malformed)
    assert_receive {:peer_closed, pid} when pid == peer.pid, 2_000
    assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 30)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 2_000)
    assert :ok = RequestCompletion.await(completion, 2_000)
    assert :ok = Task.await(peer, 2_000)
  end

  for reader <- [:early, :late] do
    test "H2 malformed trailers preserve their error for the #{reader} reader" do
      parent = self()

      {url, peer} =
        Peer.start(parent, fn socket ->
          {id, true} = Peer.request(socket)
          :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))

          receive do
            :malformed -> :ok
          after
            2_000 -> flunk("missing malformed-response release")
          end

          # Trailing HEADERS without END_STREAM are rejected by the H2 parser.
          :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0, 1, ?x, 1, ?v>>))
          await_reset(socket, id)
          send(parent, {:peer_reset, self()})
          assert_closed(socket)
        end)

      on_exit(fn -> if Process.alive?(peer), do: Process.exit(peer, :kill) end)
      origin = "http://localhost:#{URI.parse(url).port}"
      scope = open(origin, http_version: :h2c)
      promise = fetch(origin, scope)
      completion = Promise.completion(promise)
      assert %Response{body: stream} = Promise.await(promise)
      if unquote(reader) == :early, do: send(stream, {:read_chunk, self(), :ack})
      send(peer, :malformed)
      assert_receive {:peer_reset, ^peer}, 2_000

      if unquote(reader) == :late do
        assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 30)
        send(stream, {:read_chunk, self(), :ack})
      end

      assert_receive {:stream_error, ^stream, :invalid_headers_transition}, 2_000
      assert :ok = RequestCompletion.await(completion, 2_000)
      refute_receive {:stream_error, ^stream, _}, 0
      refute_receive {:stream_end, ^stream}, 0
      retire(scope)
      assert_receive {:peer_complete, ^peer}, 2_000
      send(peer, :close)
    end
  end

  defp listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {"http://127.0.0.1:#{port}", listener}
  end

  defp h1_peer(listener, malformed) do
    parent = self()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        assert {:ok, _request} = :gen_tcp.recv(socket, 0, 2_000)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
          )

        receive do
          :malformed -> :ok
        after
          2_000 -> flunk("missing malformed-response release")
        end

        :ok = :gen_tcp.send(socket, malformed)
        assert_closed(socket)
        send(parent, {:peer_closed, self()})
        :gen_tcp.close(socket)
      end)

    on_exit(fn -> if Process.alive?(peer.pid), do: Process.exit(peer.pid, :kill) end)
    peer
  end

  defp open(origin, extra \\ []) do
    assert {:ok, scope} =
             ManagedTransport.open(
               Keyword.merge(
                 [origin: origin, connect_address: {127, 0, 0, 1}, http_version: :http1],
                 extra
               )
             )

    on_exit(fn ->
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      ManagedTransport.await_retired(receipt, 2_000)
    end)

    scope
  end

  defp fetch(origin, scope) do
    HTTP.fetch(origin,
      transport_scope: scope,
      redirect: :manual,
      stream_response: true,
      decode_body: false,
      timeout: 5_000
    )
  end

  defp retire(scope) do
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 2_000)
  end

  defp await_reset(socket, id) do
    case Peer.recv(socket) do
      {3, _, ^id, _} -> :ok
      _ -> await_reset(socket, id)
    end
  end

  defp assert_closed(socket) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, _control} -> assert_closed(socket)
      result -> assert result == {:error, :closed}
    end
  end
end
