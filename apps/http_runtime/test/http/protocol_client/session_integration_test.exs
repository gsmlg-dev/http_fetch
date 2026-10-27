defmodule HTTP.ProtocolClient.SessionIntegrationTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  Code.require_file("../../support/protocol_client_peer.ex", __DIR__)
  alias HTTP.ProtocolClient, as: Client

  test "HTTP/1 responses are fully consumed on one retained TCP connection" do
    {peer, url} = peer(:http1)
    {:ok, client} = Client.connect(url, protocol: :http1)
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert {:ok, identity} = Client.connection_info(client)

    for path <- ["/first", "/second"] do
      assert {:ok, ref} = Client.request(client, :get, path)
      events = until_terminal(client, ref)
      assert {:headers, ref, 200, [{"Content-Length", "2"}]} in events
      assert {:data, ref, "ok"} in events
      assert {:done, ref} in events
      assert {:ok, ^identity} = Client.connection_info(client)
    end

    assert_receive {:peer_request, ^peer, 1, _}
    assert_receive {:peer_request, ^peer, 2, _}
    assert :ok = Client.close(client)
    assert_receive {:peer_closed, ^peer, 2}
  end

  test "HTTP/2 stream reset preserves the exact connection for a health request" do
    {peer, url} = peer(:http2)
    {:ok, client} = Client.connect(url)
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert {:ok, identity} = Client.connection_info(client)
    assert {:ok, ref} = Client.request(client, :get, "/reset")
    assert_receive {:peer_request, ^peer, 1, "/reset"}
    assert :ok = Client.cancel(client, ref)
    assert_receive {:peer_frame, ^peer, %{type: :rst_stream, stream_id: 1, payload: <<8::32>>}}
    assert {:ok, health} = Client.request(client, :get, "/health")
    assert {:data, health, "ok"} in until_terminal(client, health)
    assert_receive {:peer_request, ^peer, 3, "/health"}
    assert {:ok, ^identity} = Client.connection_info(client)
    assert :ok = Client.close(client)
    assert_receive {:peer_closed, ^peer, :http2}
  end

  test "withheld stream credit expires a blocked response, then live settings preserve health" do
    {peer, url} = peer(:http2)
    {:ok, client} = Client.connect(url, settings: [initial_window_size: 1])
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert_receive {:peer_settings, ^peer, [{:enable_push, 0}, {:initial_window_size, 1}]}
    assert {:ok, identity} = Client.connection_info(client)
    assert {:ok, ref} = Client.request(client, :get, "/expire")
    assert_receive {:peer_blocked, ^peer, 1}
    events = until_terminal(client, ref)
    assert {:data, ref, "x"} in events
    assert {:error, ref, {:reset, 8}} in events
    assert_no_stream_credit_until_expiry(peer, 1)
    assert :ok = Client.put_settings(client, initial_window_size: 65_535)
    assert_receive {:peer_settings, ^peer, [{:enable_push, 0}, {:initial_window_size, 65_535}]}
    assert {:ok, health} = Client.request(client, :get, "/health")
    assert {:data, health, "ok"} in until_terminal(client, health)
    assert_receive {:peer_request, ^peer, 3, "/health"}
    assert {:ok, ^identity} = Client.connection_info(client)
    assert :ok = Client.close(client)
    assert_receive {:peer_closed, ^peer, :http2}
  end

  test "live initial-window settings restore credit of an already blocked stream" do
    {peer, url} = peer(:http2)
    {:ok, client} = Client.connect(url, settings: [{4, 1}])
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert {:ok, ref} = Client.request(client, :get, "/restore")
    assert_receive {:peer_blocked, ^peer, 1}
    assert :ok = Client.put_settings(client, initial_window_size: 65_535)
    events = until_terminal(client, ref)
    assert {:data, ref, "x"} in events
    assert {:data, ref, "y"} in events
    assert {:done, ref} in events
    assert :ok = Client.close(client)
    assert_receive {:peer_closed, ^peer, :http2}
  end

  test "creating process exit closes the actual HTTP/2 peer and session" do
    parent = self()
    {peer, url} = peer(:http2)

    {:ok, creator} =
      Agent.start(fn ->
        {:ok, client} = Client.connect(url)
        send(parent, {:client, client})
        client
      end)

    on_exit(fn ->
      if Process.alive?(creator), do: Agent.stop(creator, :normal, 1_000)
    end)

    assert_receive {:client, client}
    monitor = Process.monitor(client.pid)
    assert_receive {:peer_accepted, ^peer}
    assert_receive {:peer_settings, ^peer, _}
    assert :ok = Agent.stop(creator, :normal, 1_000)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}
    assert_receive {:peer_closed, ^peer, :http2}
    assert {:error, :closed} = Client.connection_info(client)
  end

  test "close joins a stalled HTTP/2 owner and closes its actual socket" do
    {peer, url} = peer(:http2)
    {:ok, client} = Client.connect(url)
    assert_receive {:peer_accepted, ^peer}
    owner = :sys.get_state(client.pid).owner
    owner_monitor = Process.monitor(owner)
    session_monitor = Process.monitor(client.pid)
    assert_receive {:peer_settings, ^peer, _}
    test = self()

    spawn(fn ->
      try do
        :sys.replace_state(owner, fn state ->
          send(test, {:owner_blocked, owner})

          receive do
            :resume_owner -> state
          end
        end)
      catch
        :exit, _ -> :ok
      end
    end)

    assert_receive {:owner_blocked, ^owner}

    on_exit(fn ->
      if Process.alive?(owner), do: Process.exit(owner, :kill)
      Client.close(client)
    end)

    assert :ok = Client.close(client, 1_000)
    assert_received {:DOWN, ^owner_monitor, :process, ^owner, _}
    assert_receive {:DOWN, ^session_monitor, :process, _, :normal}
    assert_receive {:peer_closed, ^peer, :http2}
  end

  test "receive timeouts remain finite without cancelling the connection" do
    {peer, url} = peer(:http2)
    {:ok, client} = Client.connect(url)
    assert_receive {:peer_accepted, ^peer}
    assert {:error, :timeout} = Client.recv(client, 0)
    assert {:error, :timeout} = Client.recv(client, 10)
    assert {:ok, ref} = Client.request(client, :get, "/health")
    assert {:done, ref} in until_terminal(client, ref)
    assert :ok = Client.close(client)
    assert_receive {:peer_closed, ^peer, :http2}
  end

  test "acknowledgement returns stream credit only after explicit consumption" do
    {peer, url} = peer(:http2)
    {:ok, client} = Client.connect(url, settings: [initial_window_size: 1])
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert {:ok, ref} = Client.request(client, :get, "/ack")
    events = until_data(client, ref)
    assert {:data, ref, "x"} in events
    refute_received {:peer_frame, ^peer, %{type: :window_update, stream_id: 1}}
    assert :ok = Client.acknowledge(client, ref)
    assert_receive {:peer_frame, ^peer, %{type: :window_update, stream_id: 1, payload: <<1::32>>}}
    assert {:data, ref, "y"} in until_terminal(client, ref)
    assert :ok = Client.close(client)
    assert_receive {:peer_closed, ^peer, :http2}
  end

  test "HTTP/1 cancellation closes the in-flight socket without replacement" do
    {peer, url} = peer(:http1)
    {:ok, client} = Client.connect(url, protocol: :http1)
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert {:ok, ref} = Client.request(client, :get, "/hang")
    assert_receive {:peer_request, ^peer, 1, _}
    assert {:error, :request_in_progress} = Client.request(client, :get, "/health")
    assert :ok = Client.cancel(client, ref)
    assert_receive {:peer_closed, ^peer, 1}
    assert {:error, :closed} = Client.request(client, :get, "/health")
    assert :ok = Client.close(client)
  end

  test "unconsumed response bytes exhaust a finite buffer and close the real peer" do
    {peer, url} = peer(:http1)
    {:ok, client} = Client.connect(url, protocol: :http1)
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert {:ok, _ref} = Client.request(client, :get, "/oversize")
    assert_receive {:peer_closed, ^peer, 1}, 2_000
    assert {:ok, %{closed?: true}} = Client.connection_info(client)
    assert {:ok, [{:closed, :event_buffer_full}]} = Client.recv(client, 0)
    monitor = Process.monitor(client.pid)
    assert :ok = Client.close(client)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}
  end

  test "HTTP/1 Connection close is consumed and retires the retained socket" do
    {peer, url} = peer(:http1)
    {:ok, client} = Client.connect(url, protocol: :http1)
    on_exit(fn -> Client.close(client) end)
    assert_receive {:peer_accepted, ^peer}
    assert {:ok, ref} = Client.request(client, :get, "/close")
    assert {:done, ref} in until_terminal(client, ref)
    assert_receive {:peer_closed, ^peer, 1}
    assert {:error, :closed} = Client.request(client, :get, "/health")
    assert :ok = Client.close(client)
  end

  defp assert_no_stream_credit_until_expiry(peer, id) do
    receive do
      {:peer_frame, ^peer, %{type: :window_update, stream_id: ^id}} ->
        flunk("stream credit was replenished before the blocked response expired")

      {:peer_frame, ^peer, _frame} ->
        assert_no_stream_credit_until_expiry(peer, id)

      {:peer_expired, ^peer, ^id} ->
        :ok
    after
      2_000 -> flunk("peer did not confirm its blocked response expiry")
    end
  end

  defp until_data(client, ref, events \\ []) do
    assert {:ok, batch} = Client.recv(client, 2_000)
    events = events ++ batch

    if Enum.any?(batch, &match?({:data, ^ref, _}, &1)),
      do: events,
      else: until_data(client, ref, events)
  end

  defp peer(protocol) do
    {pid, url, listener} = HTTP.ProtocolClientPeer.start(protocol, self())

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(pid), do: Process.exit(pid, :kill)
    end)

    {pid, url}
  end

  defp until_terminal(client, ref, events \\ []) do
    assert {:ok, batch} = Client.recv(client, 2_000)
    events = events ++ batch

    if Enum.any?(batch, fn
         {:done, ^ref} -> true
         {:error, ^ref, _} -> true
         _ -> false
       end),
       do: events,
       else: until_terminal(client, ref, events)
  end
end
