defmodule HTTP.HTTP2UnprocessedRetryTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @refused_stream 7

  describe "wire peer" do
    test "a stream above the GOAWAY last-stream-id is replayed on a fresh connection" do
      url =
        start_peer(fn
          1, socket, id, _end_stream? ->
            send_goaway(socket, id - 1)

          2, socket, id, end_stream? ->
            body = if end_stream?, do: "", else: Peer.body(socket, id)
            :ok = Peer.response(socket, id, "replayed:" <> body)
        end)

      response = fetch(url, method: :post, body: "payload")

      assert response.status == 200
      assert HTTP.Response.text(response) == "replayed:payload"
      assert_receive {:request, 1, 1, _}
      assert_receive {:request, 2, 2, _}
      refute_receive {:request, _, _, _}, 100
    end

    test "REFUSED_STREAM is retried and a later success is returned" do
      url =
        start_peer(fn
          1, socket, id, _end_stream? ->
            send_reset(socket, id, @refused_stream)

          _n, socket, id, _end_stream? ->
            :ok = Peer.response(socket, id, "ok")
        end)

      response = fetch(url)
      assert response.status == 200
      assert HTTP.Response.text(response) == "ok"
      assert_receive {:request, 1, _, _}
      assert_receive {:request, 2, _, _}
      refute_receive {:request, _, _, _}, 100
    end

    test "retries stop after three owner attempts" do
      url = start_peer(fn _n, socket, id, _end_stream? -> send_reset(socket, id, 7) end)

      assert {:error, {:stream_reset, :refused_stream}} = fetch(url)

      for n <- 1..3, do: assert_receive({:request, ^n, _, _})
      refute_receive {:request, _, _, _}, 200
    end

    test "a processed-stream reset is not retried" do
      url = start_peer(fn _n, socket, id, _end_stream? -> send_reset(socket, id, 2) end)

      assert {:error, {:stream_reset, :internal_error}} = fetch(url)
      assert_receive {:request, 1, _, _}
      refute_receive {:request, _, _, _}, 200
    end

    test "a stream at or below the GOAWAY last-stream-id is not retried" do
      url =
        start_peer(fn _n, socket, id, _end_stream? ->
          send_goaway(socket, id)
          send_reset(socket, id, 2)
        end)

      assert {:error, {:stream_reset, :internal_error}} = fetch(url)
      assert_receive {:request, 1, _, _}
      refute_receive {:request, _, _, _}, 200
    end

    test "a streamed upload is never replayed" do
      url =
        start_peer(fn _n, socket, id, _end_stream? ->
          send_reset(socket, id, @refused_stream)
        end)

      {:ok, upload} = HTTP.Stream.start_link(0)

      assert {:error, {:stream_reset, :refused_stream}} =
               fetch(url, method: :post, body: upload, duplex: :half)

      assert_receive {:request, 1, _, _}
      refute_receive {:request, _, _, _}, 200
    end
  end

  describe "pooled owner refusal before opening" do
    defmodule RefusingOwner do
      use GenServer, restart: :temporary

      def start_link(reply), do: GenServer.start_link(__MODULE__, reply)
      def init(reply), do: {:ok, reply}

      def handle_call({:open_stream, _headers, options}, _from, :refuse) do
        send(Keyword.fetch!(options, :subscriber), {:refused_by, self()})
        {:reply, {:error, :draining}, :refuse}
      end

      def handle_call({:open_stream, _headers, options}, _from, :complete) do
        subscriber = Keyword.fetch!(options, :subscriber)
        send(subscriber, {:http2, 1, {:http2, :headers, [{":status", "200"}], 4}})
        send(subscriber, {:http2, 1, {:http2, :data, "ok", 1}})
        {:reply, {:ok, %{id: 1, ref: make_ref()}}, :complete}
      end

      def handle_call({:release_stream, _id}, _from, state), do: {:reply, :ok, state}
      def handle_call({:acknowledge, _id}, _from, state), do: {:reply, :ok, state}
      def handle_call({:cancel, _id}, _from, state), do: {:reply, :ok, state}
    end

    defmodule FakePool do
      use GenServer

      def start_link(owners), do: GenServer.start_link(__MODULE__, owners)
      def init(owners), do: {:ok, %{owners: owners, events: []}}

      def handle_call({:try_reserve, _key, _deadline}, _from, %{owners: [owner | rest]} = state),
        do: {:reply, {:ok, owner, make_ref()}, %{state | owners: rest}}

      def handle_call({:mark_draining, _key, owner}, _from, state),
        do: {:reply, :ok, %{state | events: [{:draining, owner} | state.events]}}

      def handle_call({:release, _key, _reservation}, _from, state), do: {:reply, :ok, state}
      def handle_call(:events, _from, state), do: {:reply, Enum.reverse(state.events), state}
    end

    test "a draining refusal marks the owner and moves to another owner" do
      refusing = start_supervised!({RefusingOwner, :refuse}, id: :refusing)
      serving = start_supervised!({RefusingOwner, :complete}, id: :serving)
      pool = start_supervised!({FakePool, [refusing, serving]})

      response =
        HTTP.SocketClient.request(%HTTP.Request{
          url: URI.parse("http://example.test/refused"),
          transport_options: [http_version: :h2c, http2_pool: pool, timeout: 1_000]
        })

      assert %HTTP.Response{status: 200} = response
      assert HTTP.Response.read_all(response) == "ok"
      assert GenServer.call(pool, :events) == [{:draining, refusing}]
    end

    test "the refusal is returned once the attempts are exhausted" do
      owners =
        for n <- 1..3, do: start_supervised!({RefusingOwner, :refuse}, id: {:refusing, n})

      pool = start_supervised!({FakePool, owners})

      assert {:error, :draining} =
               HTTP.SocketClient.request(%HTTP.Request{
                 url: URI.parse("http://example.test/refused"),
                 transport_options: [http_version: :h2c, http2_pool: pool, timeout: 1_000]
               })

      assert GenServer.call(pool, :events) == Enum.map(owners, &{:draining, &1})
    end
  end

  defp fetch(url, opts \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge([http_version: :h2c, http2_profile: :native_v1, timeout: 3_000], opts)
    )
    |> HTTP.Promise.await()
  end

  defp send_goaway(socket, last),
    do: :ok = :gen_tcp.send(socket, Peer.frame(7, 0, 0, <<0::1, last::31, 0::32>>))

  defp send_reset(socket, id, code),
    do: :ok = :gen_tcp.send(socket, Peer.frame(3, 0, id, <<code::32>>))

  # Accepts any number of connections. `action` receives the request number
  # across all connections, the socket, the stream id and END_STREAM.
  defp start_peer(action) do
    test = self()
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    acceptor =
      spawn_link(fn ->
        accept_loop(listener, 1, fn connection, socket ->
          serve(socket, fn id, end_stream? ->
            n = Agent.get_and_update(counter, &{&1 + 1, &1 + 1})
            send(test, {:request, n, connection, id})
            action.(n, socket, id, end_stream?)
          end)
        end)
      end)

    on_exit(fn ->
      Process.exit(acceptor, :kill)
      :gen_tcp.close(listener)
    end)

    "http://127.0.0.1:#{port}/retry"
  end

  defp accept_loop(listener, connection, handler) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        pid =
          spawn_link(fn ->
            {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)
            :ok = :gen_tcp.send(socket, Peer.frame(4, 0, 0, <<>>))
            handler.(connection, socket)
          end)

        :ok = :gen_tcp.controlling_process(socket, pid)
        accept_loop(listener, connection + 1, handler)

      {:error, _} ->
        :ok
    end
  end

  defp serve(socket, on_request) do
    case :gen_tcp.recv(socket, 9, 5_000) do
      {:ok, <<length::24, type, flags, _::1, id::31>>} ->
        if length > 0, do: {:ok, _} = :gen_tcp.recv(socket, length, 5_000)
        if type == 1, do: on_request.(id, Bitwise.band(flags, 1) == 1)
        serve(socket, on_request)

      {:error, _} ->
        :ok
    end
  end
end
