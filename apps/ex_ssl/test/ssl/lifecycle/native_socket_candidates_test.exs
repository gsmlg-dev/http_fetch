defmodule SSL.Lifecycle.NativeSocketCandidatesTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias SSL.Lifecycle.{Observer, Reader, Receipt}

  test "candidate rollover waits for original DOWN and enrolls its replacement" do
    a = attempt()

    assert {:error, :candidate_close_not_permitted} =
             Observer.begin_candidate_close(a.receipt, a.socket, deadline())

    assert {:ok, nonce} =
             invoke(a, fn s ->
               {Observer.begin_candidate_close(s.receipt, s.socket, deadline()), s}
             end)

    assert {:error, :unauthorized_candidate_close} =
             Observer.finish_candidate_close(a.receipt, nonce, deadline())

    assert {:error, :candidate_close_not_permitted} =
             invoke(a, fn s ->
               {Observer.begin_candidate_close(s.receipt, s.socket, deadline()), s}
             end)

    assert :ok = invoke(a, fn s -> {:socket.close(s.socket), s} end)
    assert_down(a.socket_monitor, a.socket)
    assert {:error, :closed} = :gen_tcp.recv(a.peer, 0, 1_000)

    assert {:ok, token} =
             invoke(a, fn s ->
               {Observer.finish_candidate_close(s.receipt, nonce, deadline()), s}
             end)

    assert {:ok, %{roles: 17, observed_down: 0, allocations: 16}} =
             Observer.snapshot(a.receipt, deadline())

    assert {:error, :unauthorized_candidate_close} =
             invoke(a, fn s ->
               {Observer.finish_candidate_close(s.receipt, nonce, deadline()), s}
             end)

    assert {:ok, socket} =
             invoke(a, fn s ->
               {:ok, socket} = :socket.open(:inet, :stream, :tcp)
               :use = Observer.enroll_socket(s.receipt, token, socket, deadline())

               :ok =
                 :socket.connect(
                   socket,
                   %{family: :inet, addr: {127, 0, 0, 1}, port: a.port},
                   1_000
                 )

               {{:ok, socket}, %{s | socket: socket}}
             end)

    socket_monitor = :socket.monitor(socket)
    {:ok, peer} = :gen_tcp.accept(a.listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)

    assert {:ok, %{roles: 17, observed_down: 0, allocations: 0}} =
             Observer.snapshot(a.receipt, deadline())

    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    assert_down(socket_monitor, socket)
    assert {:error, :closed} = :gen_tcp.recv(peer, 0, 1_000)
    assert_confirmed(a)
  end

  test "cancel during candidate close defers owner kill but fences every later reserve" do
    a = attempt()

    assert {:ok, nonce} =
             invoke(a, fn s ->
               {Observer.begin_candidate_close(s.receipt, s.socket, deadline()), s}
             end)

    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    assert Process.alive?(a.owner)

    assert {:ok, %{admission: :closed, allocations: 0, observed_down: 0}} =
             Observer.snapshot(a.receipt, deadline())

    assert {:error, :admission_closed} =
             invoke(a, fn s -> {Observer.reserve_child(s.receipt, :tcp, deadline()), s} end)

    assert :ok = invoke(a, fn s -> {:socket.close(s.socket), s} end)
    assert_down(a.socket_monitor, a.socket)

    send(
      a.owner,
      {:invoke, self(), make_ref(),
       fn s -> {Observer.finish_candidate_close(s.receipt, nonce, deadline()), s} end}
    )

    assert {:error, :closed} = :gen_tcp.recv(a.peer, 0, 1_000)
    assert_confirmed(a)
  end

  test "owner loss with an unresolved replacement permit stays unconfirmed" do
    a = attempt()

    assert {:ok, nonce} =
             invoke(a, fn s ->
               {Observer.begin_candidate_close(s.receipt, s.socket, deadline()), s}
             end)

    assert :ok = invoke(a, fn s -> {:socket.close(s.socket), s} end)
    assert_down(a.socket_monitor, a.socket)

    assert {:ok, _token} =
             invoke(a, fn s ->
               {Observer.finish_candidate_close(s.receipt, nonce, deadline()), s}
             end)

    Process.exit(a.owner, :kill)
    assert {:unconfirmed, _} = Reader.await(a.receipt, deadline(2_000))
    assert {:error, :closed} = :gen_tcp.recv(a.peer, 0, 1_000)
  end

  test "stalled candidate close is bounded by existing observer cleanup grace" do
    a = attempt()

    assert {:ok, _nonce} =
             invoke(a, fn s ->
               {Observer.begin_candidate_close(s.receipt, s.socket, deadline()), s}
             end)

    started = System.monotonic_time(:millisecond)
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    owner = a.owner
    monitor = a.owner_monitor
    assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}, 1_500
    assert System.monotonic_time(:millisecond) - started < 1_500
    assert_down(a.socket_monitor, a.socket)
    assert {:error, :closed} = :gen_tcp.recv(a.peer, 0, 1_000)
    # The observer does not wait past grace or infer proof from the owner's exit.
    assert {:unconfirmed, _} = Reader.await(a.receipt, deadline())
  end

  test "isolated resolver preserves authenticated fallback and final raw errors" do
    {:ok, interfaces} = :inet.getifaddrs()

    addresses =
      for {_name, options} <- interfaces,
          {:addr, {a, b, c, d}} <- options,
          a != 127 and a != 0,
          do: {a, b, c, d}

    assert addresses != [], "BLOCKED_ENV: no assigned non-loopback IPv4 for isolated DNS fixture"
    first = hd(addresses)

    directory =
      Path.join(System.tmp_dir!(), "exssl-candidates-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    inetrc = Path.join(directory, "inetrc")
    ip = first |> Tuple.to_list() |> Enum.join(",")

    File.write!(
      inetrc,
      "{lookup, [file]}.\n{host, {#{ip}}, [\"r45-multi.test\"]}.\n{host, {127,0,0,1}, [\"r45-multi.test\"]}.\n"
    )

    paths = Enum.flat_map(:code.get_path(), fn path -> ["-pa", List.to_string(path)] end)

    {output, code} =
      System.cmd(System.find_executable("elixir"), paths ++ ["-e", dns_script(first)],
        env: [{"ERL_INETRC", inetrc}],
        stderr_to_stdout: true
      )

    assert code == 0, output
    assert output =~ "CANDIDATE_PARITY_CONFIRMED"
  end

  defp dns_script(first) do
    """
    alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
    alias SSL.Lifecycle
    {:ok, _} = Application.ensure_all_started(:ex_ssl)
    {:ok, _} = Application.ensure_all_started(:ssl)
    host = ~c"r45-multi.test"
    {:ok, [#{inspect(first)}, {127,0,0,1}]} = :inet.getaddrs(host, :inet)
    certs = Peer.certificates()
    {:ok, listener} = :ssl.listen(0, [:binary, active: false, ip: {127,0,0,1},
      certfile: String.to_charlist(certs.certfile), keyfile: String.to_charlist(certs.keyfile),
      versions: [:"tlsv1.3"], reuseaddr: true])
    {:ok, {_, port}} = :ssl.sockname(listener)
    {:error, :econnrefused} = :gen_tcp.connect(#{inspect(first)}, port, [:binary, active: false], 500)
    peer = Task.async(fn ->
      for _ <- 1..3 do
        {:ok, tcp} = :ssl.transport_accept(listener, 3_000)
        {:ok, tls} = :ssl.handshake(tcp, 3_000)
        {:ok, "ping"} = :ssl.recv(tls, 4, 2_000)
        :ok = :ssl.send(tls, "pong")
        :ssl.close(tls)
      end
    end)
    options = Peer.client_options()
    for module <- [SSL, :ssl] do
      {:ok, socket} = module.connect(host, port, options, 3_000)
      :ok = module.send(socket, "ping")
      {:ok, "pong"} = module.recv(socket, 4, 2_000)
      module.close(socket)
    end
    now = fn -> System.monotonic_time(:millisecond) end
    original = now.() + 3_000
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: {:abs_ms, original})
    {:ok, socket} = SSL.connect(host, port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], original - now.())
    true = now.() < original
    :ok = SSL.send(socket, "ping")
    {:ok, "pong"} = SSL.recv(socket, 4, 2_000)
    :ok = SSL.close(socket)
    {:ok, %{cleanup: :confirmed, roles: 31, observed_down: 31, losses: 0}} = Lifecycle.await(handle, {:abs_ms, now.()+2_000})
    Task.await(peer, 3_000)
    :ssl.close(listener)
    {:error, :econnrefused} = :ssl.connect(host, port, options, 1_000)
    {:error, :econnrefused} = SSL.connect(host, port, options, 1_000)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: {:abs_ms, now.()+1_000})
    {:error, :econnrefused} = SSL.connect(host, port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], 1_000)
    {:ok, %{cleanup: :confirmed, roles: 31, observed_down: 31, losses: 0}} = Lifecycle.await(handle, {:abs_ms, now.()+2_000})
    # A full first-address accept queue supplies a real native connect timeout;
    # the reachable second listener must receive no fallback connection.
    {:ok, second} = :gen_tcp.listen(0, [:binary, active: false, ip: {127,0,0,1}])
    {:ok, {_, blocked_port}} = :inet.sockname(second)
    {:ok, blocked} = :gen_tcp.listen(blocked_port, [:binary, active: false, ip: #{inspect(first)}, backlog: 1])
    {fillers, saturated} = Enum.reduce_while(1..16, {[], false}, fn _, {sockets, _} ->
      case :gen_tcp.connect(#{inspect(first)}, blocked_port, [:binary, active: false], 50) do
        {:ok, socket} -> {:cont, {[socket | sockets], false}}
        {:error, :timeout} -> {:halt, {sockets, true}}
        error -> raise "BLOCKED_ENV: cannot saturate assigned local listener: " <> inspect(error)
      end
    end)
    if not saturated, do: raise("BLOCKED_ENV: local accept queue did not saturate")
    for module <- [SSL, :ssl] do
      {:error, :timeout} = module.connect(host, blocked_port, options, 150)
      {:error, :timeout} = :gen_tcp.accept(second, 0)
    end
    started = now.()
    original = started + 150
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: {:abs_ms, original})
    {:error, :timeout} = SSL.connect(host, blocked_port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], original - now.())
    true = now.() - started < 500
    {:error, :timeout} = :gen_tcp.accept(second, 0)
    {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, {:abs_ms, now.()+2_000})
    Enum.each(fillers, &:gen_tcp.close/1)
    :gen_tcp.close(blocked)
    :gen_tcp.close(second)

    {:error, :einval} = :inet.getaddrs(~c"bad host name.invalid", :inet)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: {:abs_ms, now.()+1_000})
    {:error, :einval} = SSL.connect("bad host name.invalid", port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], 1_000)
    {:ok, %{cleanup: :confirmed, roles: 15, observed_down: 15}} = Lifecycle.await(handle, {:abs_ms, now.()+2_000})
    IO.puts("CANDIDATE_PARITY_CONFIRMED")
    """
  end

  defp attempt do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    :ok = Observer.bind(receipt, lease, deadline(5_000))
    {:ok, permit} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    parent = self()

    {owner, owner_monitor} =
      spawn_monitor(fn ->
        :use = Observer.enroll_self(receipt, :allocator, permit, deadline())
        {:ok, token} = Observer.reserve_child(receipt, :tcp, deadline())
        {:ok, socket} = :socket.open(:inet, :stream, :tcp)
        :use = Observer.enroll_socket(receipt, token, socket, deadline())
        :ok = :socket.connect(socket, %{family: :inet, addr: {127, 0, 0, 1}, port: port}, 1_000)
        send(parent, {:ready, self(), socket})
        owner_loop(%{receipt: receipt, socket: socket})
      end)

    socket =
      receive do
        {:ready, ^owner, socket} -> socket
      after
        1_000 -> flunk("allocation timeout")
      end

    socket_monitor = :socket.monitor(socket)
    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    :ok = :socket.send(socket, "probe", 1_000)
    {:ok, "probe"} = :gen_tcp.recv(peer, 5, 1_000)
    observer = Receipt.observer(receipt)

    on_exit(fn ->
      Process.exit(owner, :kill)
      Process.exit(observer, :kill)
      :gen_tcp.close(peer)
      :gen_tcp.close(listener)
    end)

    %{
      receipt: receipt,
      lease: lease,
      owner: owner,
      owner_monitor: owner_monitor,
      socket: socket,
      socket_monitor: socket_monitor,
      peer: peer,
      port: port,
      listener: listener
    }
  end

  defp owner_loop(state) do
    receive do
      {:invoke, from, ref, fun} ->
        {result, state} = fun.(state)
        send(from, {:result, ref, result})
        owner_loop(state)
    end
  end

  defp invoke(a, fun) do
    ref = make_ref()
    send(a.owner, {:invoke, self(), ref, fun})

    receive do
      {:result, ^ref, result} -> result
    after
      1_000 -> flunk("owner call timeout")
    end
  end

  defp assert_down(ref, socket),
    do: assert_receive({:DOWN, ^ref, :socket, ^socket, :closed}, 1_000)

  defp assert_confirmed(a) do
    owner = a.owner
    monitor = a.owner_monitor
    assert_receive {:DOWN, ^monitor, :process, ^owner, _}, 1_000

    assert {:ok, %{cleanup: :confirmed, roles: 17, observed_down: 17, losses: 0}} =
             Reader.await(a.receipt, deadline(2_000))
  end

  defp deadline(ms \\ 1_000), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end
