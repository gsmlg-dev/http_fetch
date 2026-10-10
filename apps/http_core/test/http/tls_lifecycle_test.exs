defmodule HTTP.TLSLifecycleTest do
  use ExUnit.Case, async: true

  alias HTTP.RequestLifecycle
  alias HTTP.Transport.SSL, as: Transport

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)

  for entry <- [:connect, :connect_default, :upgrade, :upgrade_default] do
    test "#{entry} registers the actual verified OTP receiver and sender" do
      {peer, listener, port} = peer()
      {tracker, _latch} = RequestLifecycle.start()
      :ok = RequestLifecycle.register(tracker, self(), :owner)

      opts = [
        request_lifecycle: tracker,
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
      ]

      socket = connect(unquote(entry), port, opts)

      on_exit(fn ->
        abort_socket(socket)
        :ssl.close(listener)
        if Process.alive?(peer.pid), do: Process.exit(peer.pid, :kill)
        await_tracker(tracker)
      end)

      ssl = unwrap(socket)
      assert {:ok, info} = :ssl.connection_information(ssl, [:protocol])
      assert info[:protocol] == :"tlsv1.3"
      assert :ok = Transport.send(socket, "ping")
      assert {:ok, "pong"} = Transport.recv(socket, 4, 5_000)
      processes = tls_processes(ssl)
      assert Enum.all?(processes, &Process.alive?/1)

      tracked = :sys.get_state(tracker).resources |> Map.values()
      assert Enum.all?(processes, &({&1, :tls} in tracked))
      assert Enum.any?(tracked, fn {resource, kind} -> is_port(resource) and kind == :socket end)
      abort_socket(socket)
      assert :ok = Task.await(peer, 5_000)
      RequestLifecycle.complete(tracker)
    end
  end

  test "raw abort remains pending until the actual suspended sender goes DOWN" do
    {tracker, latch, owner} = lifecycle()
    {socket, peer} = tracked_connection(tracker)
    processes = tls_processes(unwrap(socket))
    sender = List.last(processes)
    monitors = Enum.map(processes, &{&1, Process.monitor(&1)})
    tracker_monitor = Process.monitor(tracker)
    :erlang.suspend_process(sender)

    try do
      RequestLifecycle.abort(tracker)
      assert :ok = Task.await(peer, 5_000)
      finish_owner(owner, tracker)
      assert :atomics.get(latch, 1) == 1
      assert Process.alive?(sender)
      assert {sender, :tls} in Map.values(:sys.get_state(tracker).resources)
    after
      if Process.alive?(sender), do: :erlang.resume_process(sender)
    end

    for {pid, ref} <- monitors do
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 5_000
    end

    assert_receive {:DOWN, ^tracker_monitor, :process, ^tracker, :normal}, 5_000
    assert :atomics.get(latch, 1) == 2
  end

  for handoff <- [:socket, :connection] do
    test "#{handoff} handoff releases only that connection and checkout restores its TLS monitors" do
      {tracker, _latch, _owner} = lifecycle()
      {first, first_peer} = tracked_connection(tracker)
      {second, second_peer} = tracked_connection(tracker)
      first_tls = tls_processes(unwrap(first))
      second_tls = tls_processes(unwrap(second))

      result =
        case unquote(handoff) do
          :socket -> RequestLifecycle.handoff_socket(tracker, first)
          :connection -> RequestLifecycle.handoff_connection(tracker, first, self())
        end

      assert :ok = result

      tracked = Map.values(:sys.get_state(tracker).resources)
      refute Enum.any?(first_tls, &({&1, :tls} in tracked))
      assert Enum.all?(second_tls, &({&1, :tls} in tracked))
      assert Enum.all?(first_tls ++ second_tls, &Process.alive?/1)
      assert ^first = RequestLifecycle.track_socket([request_lifecycle: tracker], first)
      assert ^first = RequestLifecycle.track_socket([request_lifecycle: tracker], first)
      tracked = Map.values(:sys.get_state(tracker).resources)
      assert Enum.all?(first_tls ++ second_tls, &({&1, :tls} in tracked))
      assert Enum.count(tracked, fn {_, kind} -> kind == :tls end) == 4
      abort_socket(first)
      abort_socket(second)
      assert :ok = Task.await(first_peer, 5_000)
      assert :ok = Task.await(second_peer, 5_000)
    end
  end

  test "legacy OTP process list retains both resources and exact handoff" do
    {tracker, _latch, _owner} = lifecycle()
    {:ok, tcp} = :gen_tcp.listen(0, [:binary, active: false])
    receiver = spawn(fn -> receive do: (:finish -> :ok) end)
    sender = spawn(fn -> receive do: (:finish -> :ok) end)

    on_exit(fn ->
      :gen_tcp.close(tcp)
      send(receiver, :finish)
      send(sender, :finish)
    end)

    socket = {:sslsocket, {:gen_tcp, tcp, :tls_connection, :undefined}, [receiver, sender]}
    assert :ok = RequestLifecycle.track_tls([request_lifecycle: tracker], socket)
    tracked = Map.values(:sys.get_state(tracker).resources)
    assert {tcp, :socket} in tracked
    assert {receiver, :tls} in tracked
    assert {sender, :tls} in tracked
    assert :ok = RequestLifecycle.handoff_socket(tracker, socket)
    tracked = Map.values(:sys.get_state(tracker).resources)
    refute {tcp, :socket} in tracked
    refute {receiver, :tls} in tracked
    refute {sender, :tls} in tracked
  end

  test "unsupported TLS evidence poisons request and bound scope and refuses handoff" do
    {tracker, _latch, _owner} = lifecycle()
    scope = start_supervised!({__MODULE__.ScopeRecorder, self()})
    deadline = System.monotonic_time(:millisecond) + 5_000
    assert :ok = RequestLifecycle.bind_scope(tracker, scope, deadline)
    socket = {:sslsocket, :unknown}
    assert :ok = RequestLifecycle.track_tls([], socket)

    assert {:error, :unsupported_tls_socket_representation} =
             RequestLifecycle.track_tls([request_lifecycle: tracker], socket)

    assert :sys.get_state(tracker).uncertain?
    assert_receive :scope_unconfirmed, 1_000

    assert {:error, :unsupported_tls_socket_representation} =
             RequestLifecycle.handoff_socket(tracker, socket)

    assert_receive :scope_unconfirmed, 1_000
  end

  test "ordinary request uncertainty does not poison the managed scope" do
    {tracker, _latch, _owner} = lifecycle()
    scope = start_supervised!({__MODULE__.ScopeRecorder, self()})

    assert :ok =
             RequestLifecycle.bind_scope(
               tracker,
               scope,
               System.monotonic_time(:millisecond) + 5_000
             )

    RequestLifecycle.unconfirmed(tracker)
    assert :sys.get_state(tracker).uncertain?
    assert :ok = GenServer.call(scope, :barrier)
    refute_receive :scope_unconfirmed, 0
  end

  test "handoff keeps independently scoped TLS resources" do
    {tracker, _latch, _owner} = lifecycle()
    scope = start_supervised!({__MODULE__.ScopeRecorder, self()})
    deadline = System.monotonic_time(:millisecond) + 5_000
    token = make_ref()
    assert :ok = RequestLifecycle.bind_scope(tracker, scope, deadline)
    assert :ok = RequestLifecycle.bind_connector(tracker, token, deadline)
    {socket, peer} = tracked_connection(tracker)

    for pid <- tls_processes(unwrap(socket)) do
      assert_receive {:scope_tracked, ^pid, :tls, ^token}, 1_000
    end

    assert :ok = RequestLifecycle.handoff_socket(tracker, socket)
    assert :ok = GenServer.call(scope, :barrier)
    refute_receive :scope_unconfirmed, 0
    abort_socket(socket)
    assert :ok = Task.await(peer, 5_000)
  end

  for entry <- [:connect, :upgrade] do
    test "managed #{entry} handshake failure keeps its missing TLS evidence unconfirmed" do
      {tracker, latch, owner} = lifecycle()
      scope = start_supervised!({__MODULE__.ScopeRecorder, self()})
      deadline = System.monotonic_time(:millisecond) + 5_000
      assert :ok = RequestLifecycle.bind_scope(tracker, scope, deadline)
      {:ok, listener} = tls_listener()
      {:ok, {_, port}} = :ssl.sockname(listener)
      on_exit(fn -> :ssl.close(listener) end)

      peer =
        Task.async(fn ->
          {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
          assert {:error, _} = :ssl.handshake(tcp, 5_000)
          :ssl.close(tcp)
        end)

      opts = [
        request_lifecycle: tracker,
        managed_coordinator: scope,
        ssl: [
          cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
          server_name_indication: ~c"wrong.example"
        ]
      ]

      assert {:error, _} = failed_connect(unquote(entry), port, opts)
      assert :sys.get_state(tracker).uncertain?
      assert_receive :scope_unconfirmed, 1_000
      assert :ok = Task.await(peer, 5_000)
      monitor = Process.monitor(tracker)
      finish_owner(owner, tracker)
      assert_receive {:DOWN, ^monitor, :process, ^tracker, :normal}, 1_000
      assert :atomics.get(latch, 1) == 3
    end
  end

  defmodule ScopeRecorder do
    use GenServer
    def start_link(parent), do: GenServer.start_link(__MODULE__, parent)
    @impl true
    def init(parent), do: {:ok, parent}
    @impl true
    def handle_call({:track, pid, kind, token}, _from, parent) do
      send(parent, {:scope_tracked, pid, kind, token})
      {:reply, :ok, parent}
    end

    def handle_call(:barrier, _from, parent), do: {:reply, :ok, parent}
    @impl true
    def handle_cast(:unconfirmed, parent) do
      send(parent, :scope_unconfirmed)
      {:noreply, parent}
    end
  end

  defp lifecycle do
    {tracker, latch} = RequestLifecycle.start()

    owner =
      spawn(fn ->
        receive do
          {:finish, tracker} -> RequestLifecycle.complete(tracker)
        end
      end)

    RequestLifecycle.register(tracker, owner, :owner)

    on_exit(fn ->
      if Process.alive?(owner), do: Process.exit(owner, :kill)
      await_tracker(tracker)
    end)

    {tracker, latch, owner}
  end

  defp await_tracker(tracker) do
    monitor = Process.monitor(tracker)
    assert_receive {:DOWN, ^monitor, :process, ^tracker, _}, 5_000
  end

  defp finish_owner(owner, tracker) do
    monitor = Process.monitor(owner)
    send(owner, {:finish, tracker})
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
  end

  defp tracked_connection(tracker) do
    {peer, listener, port} = peer()

    opts = [
      request_lifecycle: tracker,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
    ]

    {:ok, socket} = Transport.connect_cancellable("localhost", port, opts, 5_000)

    on_exit(fn ->
      abort_socket(socket)
      :ssl.close(listener)
      if Process.alive?(peer.pid), do: Process.exit(peer.pid, :kill)
    end)

    assert :ok = Transport.send(socket, "ping")
    assert {:ok, "pong"} = Transport.recv(socket, 4, 5_000)
    {socket, peer}
  end

  defp unwrap({:cancellable_ssl, socket, _tcp}), do: socket
  defp unwrap(socket), do: socket
  defp abort_socket({:cancellable_ssl, _, _} = socket), do: Transport.abort(socket)
  defp abort_socket(socket), do: :ssl.close(socket, 1_000)

  defp connect(entry, port, opts) do
    {:ok, socket} =
      case entry do
        :connect ->
          Transport.connect_cancellable("localhost", port, opts, 5_000)

        :connect_default ->
          Transport.connect("localhost", port, opts, 5_000)

        upgrade when upgrade in [:upgrade, :upgrade_default] ->
          {:ok, tcp} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false], 5_000)

          Transport.upgrade(
            tcp,
            "localhost",
            Keyword.put(opts, :cancellable, upgrade == :upgrade),
            5_000
          )
      end

    socket
  end

  defp failed_connect(:connect, port, opts),
    do: Transport.connect_cancellable("localhost", port, opts, 5_000)

  defp failed_connect(:upgrade, port, opts) do
    {:ok, tcp} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false], 5_000)
    Transport.upgrade(tcp, "localhost", opts, 5_000)
  end

  defp tls_processes({:sslsocket, _, processes}) when is_list(processes),
    do: Enum.filter(processes, &is_pid/1)

  defp tls_processes({:sslsocket, _, receiver, sender, _, _, _, _})
       when is_pid(receiver) and is_pid(sender),
       do: [receiver, sender]

  defp peer do
    {:ok, listener} = tls_listener()
    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
        {:ok, socket} = :ssl.handshake(tcp, 5_000)
        assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
        :ok = :ssl.send(socket, "pong")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ssl.close(socket)
      end)

    {task, listener, port}
  end

  defp tls_listener do
    :ssl.listen(0, [
      :binary,
      active: false,
      ip: {127, 0, 0, 1},
      certfile: Path.join(@fixtures, "localhost.pem"),
      keyfile: Path.join(@fixtures, "localhost.key"),
      versions: [:"tlsv1.3"]
    ])
  end
end
