defmodule HTTP.HTTP3.CleanupRetirementTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP3.{ConnectionOwner, Pool, PoolKey}

  @ca Base.decode64!(
        "MIIBmjCCAUGgAwIBAgIUeXfhY6ZUMqCuvrwtlfH/ZFVxCUUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQZXhfc3NsIFRlc3QgUm9vdDAeFw0yNjA5MTEwMTUzNDNaFw0zNjA5MDgwMTUzNDNaMBsxGTAXBgNVBAMMEGV4X3NzbCBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARrY2UL9vcYj5VbD82Uta/tk8opG1+QRiW5XBLoLlh5DMTQ6565wPtTgC6wfG0jK6CrzxrnyF6KCLOCEZx3r/MLo2MwYTAdBgNVHQ4EFgQUYEumPMaTN4hYMjeSsxUt+rXfv/cwHwYDVR0jBBgwFoAUYEumPMaTN4hYMjeSsxUt+rXfv/cwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDRwAwRAIgfpxhC/sYqFK15XU0rcD+7pyvUbAnWhzpHZnJD47G9LACIEMfb7W4Wfu8jdr0mrc5e3fIMAx3EzDTUeSJbj/A+90B"
      )

  defmodule ProbeTransport do
    def connect(_, _, opts) do
      send(opts[:observer], {:connect_effect, self(), opts})
      {:ok, %{endpoint: self()}}
    end

    def ready(_, _), do: :pending
    def abort(_, _), do: :ok
  end

  test "explicit nonreuse policy is carried separately from the opaque pool key" do
    request = %HTTP.Request{
      url: URI.parse("https://example.test/"),
      transport_options: [ssl: [cacerts: [@ca]]]
    }

    assert {:ok, _, shared} = PoolKey.build(request)
    assert shared[:exclusive?] == false
    assert {:ok, _, exclusive} = PoolKey.build(request, http3_reuse: false)
    assert exclusive[:exclusive?] == true
  end

  test "exclusive release fences only its exact owner and duplicate release is harmless" do
    pool = start_supervised!({Pool, []})
    owner = owner_probe()
    {:connect, token} = Pool.reserve(pool, :opaque_key, exclusive?: true)
    assert :ok = Pool.register(pool, :opaque_key, owner, token, 32)
    assert :ok = Pool.release(pool, token)
    assert_receive {:owner_message, ^owner, {:http3_retire, ^pool, ^token}}
    {:connect, replacement} = Pool.reserve(pool, :opaque_key, exclusive?: true)
    next = owner_probe()
    assert :ok = Pool.register(pool, :opaque_key, next, replacement, 32)
    assert :ok = Pool.release(pool, token)
    refute_receive {:owner_message, ^next, {:http3_retire, _, _}}, 20
    assert :ok = Pool.release(pool, replacement)
    assert_receive {:owner_message, ^next, {:http3_retire, ^pool, ^replacement}}
  end

  test "exclusive lessee loss retires its owner without waiting for idle expiry" do
    pool = start_supervised!({Pool, []})
    owner = owner_probe()
    parent = self()

    caller =
      spawn(fn ->
        {:connect, token} = Pool.reserve(pool, :one, exclusive?: true)
        :ok = Pool.register(pool, :one, owner, token)
        send(parent, {:registered, token})
        receive do: (:finish -> :ok)
      end)

    assert_receive {:registered, token}
    send(caller, :finish)
    assert_receive {:owner_message, ^owner, {:http3_retire, ^pool, ^token}}, 1_000
  end

  test "a unique shaped shared key does not acquire exclusive retirement" do
    pool = start_supervised!({Pool, []})
    owner = owner_probe()
    key = {:opaque, make_ref()}
    {:connect, token} = Pool.reserve(pool, key, exclusive?: false)
    :ok = Pool.register(pool, key, owner, token)
    assert :ok = Pool.release(pool, token)
    refute_receive {:owner_message, ^owner, {:http3_retire, _, _}}, 20
    assert {:ok, ^owner, second} = Pool.reserve(pool, key)
    assert :ok = Pool.release(pool, second)
  end

  test "an inert owner cannot connect before its exact activation token" do
    activation = make_ref()

    {:ok, owner} =
      ConnectionOwner.start_link(
        host: "example.test",
        port: 443,
        observer: self(),
        inert: true,
        activation: activation,
        session_options: [transport: ProbeTransport]
      )

    on_exit(fn -> stop(owner) end)
    refute_receive {:connect_effect, ^owner, _}, 30
    assert {:error, :invalid_activation} = ConnectionOwner.activate(owner, make_ref())
    refute_receive {:connect_effect, ^owner, _}, 20
    assert :ok = ConnectionOwner.activate(owner, activation)
    assert_receive {:connect_effect, ^owner, _}
  end

  defmodule Tracker do
    use GenServer
    def init(test), do: {:ok, test}

    def handle_call({:register_worker, worker, kind, _deadline}, _from, test) do
      send(test, {:retained_worker, worker, kind})
      {:reply, :ok, test}
    end

    def handle_call({:register, worker, kind}, _from, test) do
      send(test, {:retained_worker, worker, kind})
      {:reply, :ok, test}
    end

    def handle_cast(_, test), do: {:noreply, test}
  end

  test "expired pool admission creates no lease" do
    pool = start_supervised!({Pool, []})
    assert {:error, :pool_timeout} = Pool.reserve(pool, :expired, deadline_at: now() - 1)
    assert %{owners: 0, leases: 0, pending: 0} = Pool.status(pool)
  end

  test "inert activation preserves original deadlines and expiry prevents connect" do
    activation = make_ref()
    opening = now() + 1_000
    request_deadline = opening + 1_000

    {:ok, owner} =
      ConnectionOwner.start_link(
        host: "example.test",
        port: 443,
        observer: self(),
        inert: true,
        activation: activation,
        opening_deadline_at: opening,
        deadline_at: request_deadline,
        session_options: [transport: ProbeTransport]
      )

    on_exit(fn -> stop(owner) end)
    assert :ok = ConnectionOwner.activate(owner, activation)
    assert_receive {:connect_effect, ^owner, opts}
    assert opts[:deadline] == {:abs_ms, opening}

    assert %{opening_deadline: ^opening, request_deadline: ^request_deadline} =
             ConnectionOwner.status(owner)

    {:ok, expired} =
      ConnectionOwner.start_link(
        host: "example.test",
        port: 443,
        observer: self(),
        inert: true,
        activation: activation,
        opening_deadline_at: now() - 1,
        session_options: [transport: ProbeTransport]
      )

    monitor = Process.monitor(expired)
    assert {:error, :opening_timeout} = ConnectionOwner.activate(expired, activation)
    assert_receive {:DOWN, ^monitor, :process, ^expired, :normal}
    refute_receive {:connect_effect, ^expired, _}, 20
  end

  test "creator loss retires an inert owner before any native effect" do
    test = self()

    creator =
      spawn(fn ->
        {:ok, owner} =
          ConnectionOwner.start_link(
            host: "example.test",
            port: 443,
            observer: test,
            inert: true,
            activation: make_ref(),
            session_options: [transport: ProbeTransport]
          )

        Process.unlink(owner)
        send(test, {:inert_owner, owner})
      end)

    creator_monitor = Process.monitor(creator)
    assert_receive {:inert_owner, owner}
    owner_monitor = Process.monitor(owner)
    assert_receive {:DOWN, ^creator_monitor, :process, ^creator, _}
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _}
    refute_receive {:connect_effect, ^owner, _}, 20
  end

  for cause <- [:close, :tracker_loss, :deadline] do
    @cause cause
    test "retained callback workers join on #{@cause} without opening native owner" do
      {:ok, tracker} = GenServer.start_link(Tracker, self())
      Process.unlink(tracker)
      on_exit(fn -> stop(tracker) end)
      pool = start_supervised!({Pool, []})
      test = self()

      request = %HTTP.Request{
        url: URI.parse("https://example.test/"),
        transport_options: [ssl: [cacerts: [@ca]], http3_reuse: false]
      }

      assert {:ok, _, _} = PoolKey.build(request)
      assert {:ok, _, _} = HTTP.HTTP2.request_headers(request, :native_v1, order?: false)
      opening = now() + if(@cause == :deadline, do: 100, else: 1_000)

      callback = fn deadline ->
        send(test, {:callback_entered, self(), deadline})
        receive do: (:never -> :ok)
      end

      assert {:ok, relay, _} =
               HTTP.HTTP3.Stream.start(request, self(),
                 pool: pool,
                 request_lifecycle: tracker,
                 quic_cleanup: callback,
                 opening_deadline_at: opening
               )

      relay_monitor = Process.monitor(relay)
      assert_receive {:retained_worker, ^relay, :http3_relay}, 1_000
      assert_receive {:retained_worker, guard, :http3_connector_watchdog}, 1_000
      assert_receive {:retained_worker, connector, :http3_connector}, 1_000
      assert_receive {:callback_entered, ^connector, ^opening}, 1_000
      connector_monitor = Process.monitor(connector)
      guard_monitor = Process.monitor(guard)

      case @cause do
        :close -> HTTP.HTTP3.Stream.close(relay)
        :tracker_loss -> Process.exit(tracker, :kill)
        :deadline -> :ok
      end

      assert_receive {:DOWN, ^connector_monitor, :process, ^connector, _}, 1_000
      assert_receive {:DOWN, ^guard_monitor, :process, ^guard, _}, 1_000
      assert_receive {:DOWN, ^relay_monitor, :process, ^relay, _}, 1_000
      assert %{owners: 0, leases: 0, pending: 0} = Pool.status(pool)
      refute_receive {:retained_worker, _, :http3_owner}, 0
    end
  end

  @tag :readiness_control
  test "retained shared owners cannot be borrowed before authenticated readiness" do
    pool = start_supervised!({Pool, [max_connections: 1]})
    owner = owner_probe()
    {:connect, lease} = Pool.reserve(pool, :opening)
    :ok = Pool.register(pool, :opening, owner, lease, 32, ready?: false)
    request = :gen_server.send_request(pool, {:reserve, :opening, [timeout: 1_000]})
    assert %{owners: 1, leases: 1, pending: 1} = Pool.status(pool)
    assert :ok = GenServer.call(pool, {:ready, owner, lease})
    assert {:reply, {:ok, ^owner, next}} = :gen_server.receive_response(request, 1_000)
    :ok = Pool.release(pool, next)
    :ok = Pool.release(pool, lease)
    refute_receive {:owner_message, ^owner, {:http3_retire, _, _}}, 20
  end

  defp now, do: System.monotonic_time(:millisecond)

  defp owner_probe do
    parent = self()
    owner = spawn(fn -> probe_loop(parent) end)
    on_exit(fn -> send(owner, :stop) end)
    owner
  end

  defp probe_loop(parent) do
    receive do
      :stop ->
        :ok

      message ->
        send(parent, {:owner_message, self(), message})
        probe_loop(parent)
    end
  end

  defp stop(owner) do
    if Process.alive?(owner), do: GenServer.stop(owner)
  catch
    :exit, _ -> :ok
  end
end
