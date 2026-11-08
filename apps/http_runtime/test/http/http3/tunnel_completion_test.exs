defmodule HTTP.HTTP3.TunnelCompletionTest do
  use ExUnit.Case, async: true
  alias HTTP.ClientCompletion
  alias HTTP.HTTP3.Stream
  alias HTTP.RequestLifecycle

  # Acts as both the pool and the shared connection owner for one tunnel.
  defmodule Owner do
    use GenServer
    def start_link({parent, mode}), do: GenServer.start_link(__MODULE__, {parent, mode})
    def init({parent, mode}), do: {:ok, %{parent: parent, mode: mode}}
    def handle_call({:reserve, _, _}, _, state), do: {:reply, {:ok, self(), make_ref()}, state}
    def handle_call({:release, _}, _, state), do: {:reply, :ok, state}

    def handle_call({:open, _, :stream, subscriber, generation, _}, _, state) do
      ref = make_ref()
      {:reply, {:ok, ref}, state, {:continue, {:headers, subscriber, generation, ref}}}
    end

    def handle_call({:cancel, _}, _, state), do: {:reply, :ok, state}

    def handle_call({:settle, subscriber, refs}, _, state) do
      send(state.parent, {:settle, subscriber, refs})

      case state.mode do
        :settled -> {:reply, :settled, state}
        :pending -> {:reply, {:pending, refs}, state}
      end
    end

    def handle_continue({:headers, subscriber, generation, ref}, state) do
      send(subscriber, {:http3, generation, ref, {:headers, 200, []}})
      {:noreply, state}
    end

    def handle_cast(_, state), do: {:noreply, state}
  end

  defp request do
    %HTTP.Request{
      method: :connect,
      url: URI.parse("https://example.test/ws"),
      transport_options: [
        ssl: [
          cacertfile: Path.expand("../../../../elixir_quic/test/fixtures/tls/root.pem", __DIR__)
        ]
      ]
    }
  end

  defp start(owner, receipt, opts \\ []) do
    tracker = ClientCompletion.tracker(receipt)
    :ok = RequestLifecycle.enter(tracker, :owner)

    {:ok, relay, generation} =
      Stream.start(
        request(),
        self(),
        [
          pool: owner,
          purpose: :extended_connect,
          protocol: "websocket",
          request_lifecycle: tracker
        ] ++ opts
      )

    assert_receive {:http_runtime, ^generation, ^relay, {:opened, %{ref: ref}}}, 1_000
    assert_receive {:http_runtime, ^generation, ^relay, {:headers, [{":status", "200"}], []}}
    RequestLifecycle.retire_owner(tracker)
    {relay, ref}
  end

  test "receipt is confirmed only after the owner reports the tunnel settled" do
    owner = start_supervised!({Owner, {self(), :settled}})
    receipt = ClientCompletion.new()
    {relay, ref} = start(owner, receipt)
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 20)
    Stream.close(relay)
    assert_receive {:settle, ^relay, [^ref]}, 1_000
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "an owner that never confirms settlement yields an unconfirmed receipt" do
    owner = start_supervised!({Owner, {self(), :pending}})
    receipt = ClientCompletion.new()
    {relay, _ref} = start(owner, receipt, settle_timeout: 50)
    Stream.close(relay)
    assert_receive {:settle, ^relay, _}, 1_000
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
  end

  test "observed owner death settles the tunnel stream" do
    {:ok, owner} = GenServer.start(Owner, {self(), :pending})
    receipt = ClientCompletion.new()
    {relay, _ref} = start(owner, receipt)
    monitor = Process.monitor(relay)
    Process.exit(owner, :kill)
    assert_receive {:http_runtime, _, ^relay, {:error, {:owner_down, :killed}}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^relay, :normal}, 1_000
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "relay death before proof is never confirmed" do
    owner = start_supervised!({Owner, {self(), :settled}})
    receipt = ClientCompletion.new()
    {relay, _ref} = start(owner, receipt)
    Process.exit(relay, :kill)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
    refute_received {:settle, _, _}
  end

  test "tracker cancellation is graceful and still requires owner settlement" do
    owner = start_supervised!({Owner, {self(), :settled}})
    receipt = ClientCompletion.new()
    {relay, ref} = start(owner, receipt)
    RequestLifecycle.abort(ClientCompletion.tracker(receipt))
    assert_receive {:settle, ^relay, [^ref]}, 1_000
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "untracked tunnels keep their original relay behaviour" do
    owner = start_supervised!({Owner, {self(), :settled}})

    {:ok, relay, generation} =
      Stream.start(request(), self(),
        pool: owner,
        purpose: :extended_connect,
        protocol: "websocket"
      )

    monitor = Process.monitor(relay)
    assert_receive {:http_runtime, ^generation, ^relay, {:opened, _}}, 1_000
    Stream.close(relay)
    assert_receive {:DOWN, ^monitor, :process, ^relay, :normal}, 1_000
    refute_received {:settle, _, _}
  end
end
