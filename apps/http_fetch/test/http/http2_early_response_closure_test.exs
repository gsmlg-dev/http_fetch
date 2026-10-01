defmodule HTTP.HTTP2EarlyResponseClosureTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{BodyBridge, ConnectionOwner}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @settings <<4::16, 0::32, 3::16, 1::32>>

  for kind <- [:binary, :stream], status <- [200, 413] do
    test "complete #{status} abandons #{kind} upload before socket reuse" do
      test_pid = self()
      status = unquote(status)

      {url, peer} =
        Peer.start(
          test_pid,
          fn socket ->
            warm_connection(socket, test_pid)
            {id, false} = Peer.request(socket)
            send(test_pid, {:request_headers, self(), id})
            receive do: (:respond -> :ok)
            status_block = if status == 200, do: <<0x88>>, else: <<8, 3, "413">>
            :ok = :gen_tcp.send(socket, Peer.frame(1, 5, id, status_block))
            assert {3, 0, ^id, <<8::32>>} = next_stream_frame(socket)
            send(test_pid, {:request_closed, self()})
            {next_id, true} = Peer.request(socket)
            assert next_id > id
            :ok = :gen_tcp.send(socket, Peer.frame(1, 5, next_id, <<0x88>>))
          end,
          settings: @settings
        )

      body = upload(unquote(kind))
      warm_fetch(url, peer)
      task = Task.async(fn -> fetch(url, method: :post, body: body, duplex: "half") end)
      assert_receive {:request_headers, ^peer, 3}, 5_000
      owner = owner_for(url)
      %{streams: %{3 => %{body_bridge: bridge, pid: coordinator}}} = :sys.get_state(owner)
      coordinator_monitor = Process.monitor(coordinator)

      assert %{end_stream_sent?: false, send_window: 0} =
               :sys.get_state(owner).connection.streams[3]

      send(peer, :respond)
      response = Task.await(task, 5_000)
      assert response.status == status
      assert HTTP.Response.read_all(response) == ""
      assert_receive {:request_closed, ^peer}, 5_000
      assert_receive {:DOWN, ^coordinator_monitor, :process, ^coordinator, :normal}, 5_000
      refute Process.alive?(bridge)

      assert %{active_streams: 0, protocol_streams: 0, pending_upload_bytes: 0} =
               ConnectionOwner.status(owner)

      assert fetch(url).status == 200
      assert_receive {:peer_complete, ^peer}, 5_000
      send(peer, :close)
    end
  end

  for reset? <- [false, true] do
    test "blocked owner chunk stays abandoned through sibling traffic and trailers, peer NO_ERROR=#{reset?}" do
      test_pid = self()

      source =
        spawn(fn ->
          receive do
            {:read_chunk, bridge, :ack} ->
              send(test_pid, {:producer_read, self(), bridge})
              receive do: (:produce -> :ok)
              send(bridge, {:stream_chunk, self(), :binary.copy("u", 16_384), make_ref()})

              receive do
                {:error, reason} -> send(test_pid, {:producer_stopped, self(), reason})
                {:read_chunk, _, :ack} -> send(test_pid, :unexpected_read)
              end

              receive do: (:stop -> :ok)
          end
        end)

      on_exit(fn -> Process.exit(source, :kill) end)

      {url, peer} =
        Peer.start(
          test_pid,
          fn socket ->
            warm_connection(socket, test_pid)
            {id, false} = Peer.request(socket)
            send(test_pid, {:request_headers, self(), id})
            receive do: (:shrink -> :ok)

            :ok =
              :gen_tcp.send(socket, [
                Peer.frame(4, 0, 0, <<4::16, 0::32>>),
                Peer.frame(6, 0, 0, "shrink!!")
              ])

            assert {6, 1, 0, "shrink!!"} = next_observed_frame(socket)
            send(test_pid, {:window_shrunk, self()})
            receive do: (:respond -> :ok)
            :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
            receive do: (:grant -> :ok)

            :ok =
              :gen_tcp.send(socket, [
                Peer.frame(8, 0, id, <<65_535::32>>),
                Peer.frame(6, 0, 0, "barrier!")
              ])

            assert {6, 1, 0, "barrier!"} = next_observed_frame(socket)
            send(test_pid, {:credit_processed, self()})
            {sibling, true} = Peer.request(socket)
            :ok = Peer.response(socket, sibling, "sibling")
            receive do: (:complete -> :ok)

            frames = [
              Peer.frame(0, 0, id, "accepted"),
              Peer.frame(1, 5, id, <<0, 9, "x-trailer", 4, "done">>)
            ]

            frames =
              if unquote(reset?), do: frames ++ [Peer.frame(3, 0, id, <<0::32>>)], else: frames

            :ok = :gen_tcp.send(socket, frames)
            unless unquote(reset?), do: assert({3, 0, ^id, <<8::32>>} = next_stream_frame(socket))
          end,
          settings: <<4::16, 16_384::32, 3::16, 2::32>>
        )

      warm_fetch(url, peer)
      task = Task.async(fn -> fetch(url, method: :post, body: source, duplex: "half") end)
      assert_receive {:request_headers, ^peer, 3}, 5_000
      assert_receive {:producer_read, ^source, bridge}, 5_000
      owner = owner_for(url)
      :erlang.trace(owner, true, [:receive, {:tracer, self()}])
      send(peer, :shrink)
      assert_receive {:window_shrunk, ^peer}, 5_000
      assert :sys.get_state(owner).connection.streams[3].send_window == 0
      send(source, :produce)

      assert_receive {:trace, ^owner, :receive, {:body_chunk, ^bridge, chunk, ack_ref}}, 5_000
      assert :sys.get_state(owner).streams[3].pending_body == {bridge, chunk, ack_ref}
      assert ConnectionOwner.status(owner).pending_upload_bytes == 16_384
      coordinator = :sys.get_state(owner).streams[3].pid
      coordinator_monitor = Process.monitor(coordinator)
      :erlang.trace(owner, false, [:receive])
      send(peer, :respond)
      response = Task.await(task, 5_000)
      assert response.status == 200
      assert_receive {:producer_stopped, ^source, :early_response}, 5_000
      assert %{stopped?: true, buffered_bytes: 0, inflight: nil} = BodyBridge.status(bridge)
      assert %{pending_upload_bytes: 0} = ConnectionOwner.status(owner)
      assert :ok = ConnectionOwner.send_event(owner, {:body_chunk, bridge, chunk, ack_ref})
      assert :ok = ConnectionOwner.send_event(owner, {:body_eof, bridge})
      assert :ok = ConnectionOwner.send_event(owner, {:body_error, bridge, :late_error})
      send(bridge, {:body_ack, ack_ref})
      send(peer, :grant)
      assert_receive {:credit_processed, ^peer}, 5_000
      sibling = fetch(url)
      assert HTTP.Response.read_all(sibling) == "sibling"
      assert owner_for(url) == owner
      send(peer, :complete)
      assert HTTP.Response.read_all(response) == "accepted"
      assert_receive {:peer_complete, ^peer}, 5_000
      assert_receive {:DOWN, ^coordinator_monitor, :process, ^coordinator, :normal}, 5_000

      assert %{active_streams: 0, protocol_streams: 0, pending_upload_bytes: 0} =
               ConnectionOwner.status(owner)

      refute_receive :unexpected_read
      send(source, :stop)
      send(peer, :close)
    end
  end

  test "a completed upload receives no duplicate EOF or reset on final response" do
    test_pid = self()

    {url, peer} =
      Peer.start(test_pid, fn socket ->
        warm_connection(socket, test_pid)
        {id, false} = Peer.request(socket)
        assert Peer.body(socket, id) == "complete"

        :ok =
          :gen_tcp.send(socket, [Peer.frame(1, 5, id, <<0x88>>), Peer.frame(6, 0, 0, "closed!!")])

        assert {6, 1, 0, "closed!!"} = next_observed_frame(socket)
        send(test_pid, {:completed_upload, self()})

        {1, 5, next_id, _headers} = next_stream_frame(socket)

        :ok = Peer.response(socket, next_id, "reused")
      end)

    warm_fetch(url, peer)
    response = fetch(url, method: :post, body: "complete")
    assert HTTP.Response.read_all(response) == ""
    assert_receive {:completed_upload, ^peer}, 5_000
    assert HTTP.Response.read_all(fetch(url)) == "reused"
    assert_receive {:peer_complete, ^peer}, 5_000
    send(peer, :close)
  end

  for stop <- [:early_response, :cancel] do
    test "late body ACK and credit cannot restart a producer after #{stop}" do
      test_pid = self()

      source =
        spawn(fn ->
          receive do
            {:read_chunk, bridge, :ack} ->
              ref = make_ref()
              send(bridge, {:stream_chunk, self(), "pending", ref})
              send(test_pid, {:inflight, bridge, ref})

              receive do
                {:read_chunk, _, :ack} -> send(test_pid, :unexpected_read)
                {:error, _} -> :ok
              end
          end
        end)

      on_exit(fn -> Process.exit(source, :kill) end)
      {:ok, bridge} = BodyBridge.start_link(source, self())
      :ok = BodyBridge.credit(bridge, 7)
      assert_receive {:inflight, ^bridge, ref}, 5_000
      assert_receive {:body_chunk, ^bridge, "pending", ^ref}, 5_000
      :ok = apply(BodyBridge, unquote(stop), [bridge])
      send(bridge, {:body_ack, ref})
      :ok = BodyBridge.credit(bridge, 7)

      assert %{stopped?: true, inflight: nil, buffered_bytes: 0, credit: 0} =
               BodyBridge.status(bridge)

      refute_receive :unexpected_read
    end
  end

  defp upload(:binary), do: :binary.copy("upload", 8_192)

  defp upload(:stream) do
    {:ok, source} = HTTP.Stream.from_enumerable([:binary.copy("upload", 8_192)])
    source
  end

  defp warm_connection(socket, test_pid), do: warm_connection(socket, test_pid, nil, false)

  defp warm_connection(socket, test_pid, id, true) when is_integer(id) do
    send(test_pid, {:warm_headers, self(), id})

    receive do
      :warm_response -> :ok
    after
      5_000 -> flunk("missing warm response barrier")
    end

    :ok = :gen_tcp.send(socket, Peer.frame(1, 5, id, <<0x88>>))
  end

  defp warm_connection(socket, test_pid, id, acknowledged?) do
    case Peer.recv(socket) do
      {1, 5, request_id, _} -> warm_connection(socket, test_pid, request_id, acknowledged?)
      {4, 1, 0, <<>>} -> warm_connection(socket, test_pid, id, true)
      _ -> warm_connection(socket, test_pid, id, acknowledged?)
    end
  end

  defp warm_fetch(url, peer) do
    promise = HTTP.fetch(url, http_version: :h2c, timeout: 10_000)
    assert_receive {:warm_headers, ^peer, 1}, 5_000
    owner = owner_for(url)
    %{streams: %{1 => %{pid: coordinator}}} = :sys.get_state(owner)
    monitor = Process.monitor(coordinator)
    send(peer, :warm_response)
    assert HTTP.Promise.await(promise).status == 200

    # Response delivery precedes cleanup. The exact coordinator exits only after
    # releasing its pool reservation, so the next request can reuse stream slot 1.
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, :normal}, 5_000

    assert %{active_streams: 0, protocol_streams: 0, pending_upload_bytes: 0} =
             ConnectionOwner.status(owner)
  end

  defp fetch(url, opts \\ []) do
    HTTP.fetch(url, Keyword.merge([http_version: :h2c, timeout: 10_000], opts))
    |> HTTP.Promise.await()
  end

  defp owner_for(url) do
    port = URI.parse(url).port

    :http_fetch_http2_pool
    |> :sys.get_state()
    |> Map.fetch!(:entries)
    |> Enum.find_value(fn {key, entry} ->
      if key.port == port, do: entry.connections |> Map.keys() |> List.first()
    end)
  end

  defp next_stream_frame(socket) do
    case Peer.recv(socket) do
      {type, _, id, _} = frame when type in [0, 1, 3] and id > 0 -> frame
      _ -> next_stream_frame(socket)
    end
  end

  defp next_observed_frame(socket) do
    case Peer.recv(socket) do
      {type, _, _, _} = frame when type in [0, 1, 3, 6] -> frame
      _ -> next_observed_frame(socket)
    end
  end
end
