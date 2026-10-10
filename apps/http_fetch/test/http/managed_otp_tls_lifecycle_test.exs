defmodule HTTP.ManagedOTPTLSLifecycleTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Frames

  @fixtures Path.expand("../support/fixtures", __DIR__)

  for protocol <- [:http1, :http2] do
    test "#{protocol} idle handoff completes requests but retirement waits for TLS sender DOWN" do
      protocol = unquote(protocol)
      {origin, listener} = listener()
      peer = peer(listener, protocol, :reuse)
      scope = open(origin, protocol)

      for _ <- 1..2 do
        promise = fetch(origin, scope)
        assert Response.read_all(Promise.await(promise, 3_000)) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(promise), 3_000)
      end

      {sender, receiver, _tcp} = resources(scope)
      assert Process.alive?(receiver)
      monitor = Process.monitor(sender)
      :erlang.suspend_process(sender)

      try do
        assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
        assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 50)
        assert Process.alive?(sender)
      after
        :erlang.resume_process(sender)
      end

      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert :ok = ManagedTransport.await_retired(receipt, 3_000)
      assert :ok = ManagedTransport.await_retired(receipt, 0)
      assert_receive {:DOWN, ^monitor, :process, ^sender, _}, 3_000
      assert :ok = Task.await(peer, 3_000)
    end

    test "#{protocol} raw abort retains TLS resources until delayed sender termination" do
      protocol = unquote(protocol)
      {origin, listener} = listener()
      peer = peer(listener, protocol, :held)
      scope = open(origin, protocol)
      promise = fetch(origin, scope)
      assert %Response{} = Promise.await(promise, 3_000)
      {sender, _receiver, tcp} = resources(scope)
      :erlang.suspend_process(sender)

      try do
        assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
        wait_until(fn -> :erlang.port_info(tcp) == :undefined end)
        assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 50)
        assert Process.alive?(sender)
      after
        :erlang.resume_process(sender)
      end

      expected = abort_result(protocol)
      assert expected == RequestCompletion.await(Promise.completion(promise), 3_000)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert :ok = ManagedTransport.await_retired(receipt, 3_000)
      assert :ok = Task.await(peer, 3_000)
    end

    test "#{protocol} closed TCP cannot recycle capacity while TLS sender is alive" do
      protocol = unquote(protocol)
      {origin, listener} = listener()
      peer = peer(listener, protocol, :capacity)
      scope = open(origin, protocol)
      promise = fetch(origin, scope)
      assert %Response{} = Promise.await(promise, 3_000)
      await_draining(protocol)
      {sender, receiver, tcp} = resources(scope)
      monitor = Process.monitor(receiver)
      :erlang.suspend_process(sender)

      try do
        :ok = :gen_tcp.close(tcp)
        RequestCompletion.abort_and_await(Promise.completion(promise), 0)
        assert_receive {:DOWN, ^monitor, :process, ^receiver, _}, 3_000

        wait_until(fn ->
          state = :sys.get_state(scope.coordinator)
          Enum.all?(state.resources, fn {_, {_, kind, _}} -> kind != :socket end)
        end)

        assert {:ok, %{connections: 1}} = ManagedTransport.snapshot(scope, 100)
        rejected = fetch(origin, scope)

        assert {:error, {:transport_scope_capacity, :connections}} =
                 Promise.await(rejected, 3_000)

        assert :ok = RequestCompletion.await(Promise.completion(rejected), 3_000)
        assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
      after
        :erlang.resume_process(sender)
      end

      wait_until(fn ->
        match?({:ok, %{connections: 0}}, ManagedTransport.snapshot(scope, 100))
      end)

      replacement = fetch(origin, scope)
      assert Response.read_all(Promise.await(replacement, 3_000)) == "ok"
      assert :ok = RequestCompletion.await(Promise.completion(replacement), 3_000)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert :ok = ManagedTransport.await_retired(receipt, 3_000)
      assert :ok = Task.await(peer, 3_000)
    end
  end

  for protocol <- [:http1, :http2] do
    test "#{protocol} cancellation during TLS setup retires missing resource evidence conservatively" do
      {origin, listener} = listener()
      scope = open(origin, unquote(protocol))
      parent = self()

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 3_000)
          assert {:ok, _hello} = :gen_tcp.recv(tcp, 0, 3_000)
          send(parent, :client_hello)
          assert {:error, :closed} = :gen_tcp.recv(tcp, 0, 3_000)
          :ok
        end)

      promise = fetch(origin, scope)
      assert_receive :client_hello, 3_000

      assert {:error, :cleanup_unconfirmed} =
               RequestCompletion.abort_and_await(Promise.completion(promise), 3_000)

      assert {:error, _} = Promise.await(promise, 3_000)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 3_000)
      assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 0)
      assert {:error, :transport_scope_retired} = Promise.await(fetch(origin, scope), 3_000)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
      assert :ok = Task.await(peer, 3_000)
    end
  end

  defp abort_result(:http1), do: :ok
  defp abort_result(:http2), do: {:error, :cleanup_unconfirmed}
  defp await_draining(:http1), do: :ok
  defp await_draining(:http2), do: assert_receive(:draining, 3_000)

  defp resources(scope) do
    state = :sys.get_state(scope.coordinator)
    tls = for {_, {pid, :tls, _}} <- state.resources, do: pid
    assert length(tls) == 2

    sender =
      Enum.find(tls, fn pid ->
        case Process.info(pid, :dictionary) do
          {:dictionary, dictionary} ->
            Keyword.get(dictionary, :"$initial_call") == {:tls_sender, :init, 1}

          _ ->
            false
        end
      end)

    assert is_pid(sender)
    receiver = Enum.find(tls, &(&1 != sender))

    tcp =
      Enum.find_value(state.resources, fn {_, {resource, kind, _}} ->
        if kind == :socket, do: resource
      end)

    assert is_port(tcp)
    {sender, receiver, tcp}
  end

  defp listener do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    {"https://localhost:#{port}", listener}
  end

  defp peer(listener, protocol, mode) do
    parent = self()

    Task.async(fn ->
      socket = accept(listener, protocol)

      if mode == :held do
        id = request(socket, protocol)
        respond(socket, protocol, id, false)
        closed(socket)
      else
        if mode == :capacity and protocol == :http2 do
          id = request(socket, protocol)

          :ok =
            :ssl.send(socket, [
              Frames.frame(1, 4, id, <<0x88>>),
              Frames.frame(7, 0, 0, <<0::1, id::31, 0::32>>),
              Frames.frame(6, 0, 0, "tlsbound")
            ])

          ping_ack(socket)
          send(parent, :draining)

          closed(socket)
        else
          serve(socket, protocol)
        end

        timeout = if mode == :capacity, do: 3_000, else: 100

        case :gen_tcp.accept(listener, timeout) do
          {:ok, tcp} -> serve(handshake(tcp, protocol), protocol)
          {:error, :timeout} -> :ok
        end
      end

      :ok
    end)
  end

  defp accept(listener, protocol) do
    {:ok, tcp} = :gen_tcp.accept(listener, 3_000)
    handshake(tcp, protocol)
  end

  defp handshake(tcp, protocol) do
    {:ok, socket} =
      :ssl.handshake(
        tcp,
        [
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          alpn_preferred_protocols: [if(protocol == :http2, do: "h2", else: "http/1.1")],
          active: false
        ],
        3_000
      )

    if protocol == :http2 do
      assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(socket, 24, 3_000)
      :ok = :ssl.send(socket, Frames.frame(4, 0, 0, <<>>))
    end

    socket
  end

  defp serve(socket, protocol) do
    case request(socket, protocol) do
      :closed ->
        :ok

      id ->
        respond(socket, protocol, id, true)
        serve(socket, protocol)
    end
  end

  defp request(socket, :http1) do
    case :ssl.recv(socket, 0, 3_000) do
      {:ok, head} ->
        assert head =~ "GET /tls"
        0

      {:error, :closed} ->
        :closed
    end
  end

  defp request(socket, :http2) do
    case :ssl.recv(socket, 9, 3_000) do
      {:ok, <<length::24, type, _flags, _::1, id::31>>} ->
        if length > 0, do: assert(match?({:ok, _}, :ssl.recv(socket, length, 3_000)))
        if type == 1, do: id, else: request(socket, :http2)

      {:error, :closed} ->
        :closed
    end
  end

  defp ping_ack(socket) do
    {:ok, <<length::24, type, flags, _::1, _id::31>>} = :ssl.recv(socket, 9, 3_000)
    payload = if length > 0, do: elem(:ssl.recv(socket, length, 3_000), 1), else: <<>>
    unless type == 6 and flags == 1 and payload == "tlsbound", do: ping_ack(socket)
  end

  defp respond(socket, :http1, _, finished) do
    :ok =
      :ssl.send(
        socket,
        if(finished,
          do: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
          else: "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"
        )
      )
  end

  defp respond(socket, :http2, id, finished) do
    :ok =
      :ssl.send(socket, [
        Frames.frame(1, 4, id, <<0x88>>),
        if(finished, do: Frames.frame(0, 1, id, "ok"), else: <<>>)
      ])
  end

  defp closed(socket) do
    case :ssl.recv(socket, 0, 3_000) do
      {:error, :closed} -> :ok
      {:ok, _} -> closed(socket)
    end
  end

  defp open(origin, protocol) do
    assert {:ok, scope} =
             ManagedTransport.open(
               origin: origin,
               connect_address: {127, 0, 0, 1},
               http_version: protocol,
               max_connections: 1,
               max_requests: 8,
               max_pending: 0,
               ssl: [verify: :verify_peer, cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
             )

    on_exit(fn ->
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      ManagedTransport.await_retired(receipt, 3_000)
    end)

    scope
  end

  defp fetch(origin, scope),
    do:
      HTTP.fetch(origin <> "/tls",
        transport_scope: scope,
        stream_response: true,
        decode_body: false,
        redirect: :manual,
        timeout: 5_000
      )

  defp wait_until(fun, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 3_000

    unless fun.() do
      assert System.monotonic_time(:millisecond) < deadline
      :erlang.yield()
      wait_until(fun, deadline)
    end
  end
end
