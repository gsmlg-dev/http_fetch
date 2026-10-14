defmodule HTTP.Runtime.DialerTest do
  use ExUnit.Case, async: true

  defmodule ControlledTransport do
    def connect(observer, port, _opts, timeout) do
      send(observer, {:connecting, self()})

      receive do
        :raise ->
          raise "private connection credentials"

        :exit ->
          exit({:private, "connection credentials"})

        :normal ->
          exit(:normal)

        :error ->
          {:error, :econnrefused}

        :connect ->
          {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], timeout)
          Process.put(:dial_observer, observer)
          {:ok, socket}
      end
    end

    def controlling_process(socket, owner) do
      observer = Process.get(:dial_observer)
      :ok = :gen_tcp.controlling_process(socket, owner)
      send(observer, {:transferred, self(), socket, owner})

      receive do
        :complete -> :ok
        :raise -> raise "private handoff credentials"
      end
    end

    def close(socket), do: :gen_tcp.close(socket)
  end

  for failure <- [:raise, :exit, :normal] do
    test "#{failure} without a result settles before the connect deadline" do
      {caller, worker, monitor} = start_connect(0, connect_failure_token: make_ref())
      send(worker, unquote(failure))
      assert_receive {:DOWN, ^monitor, :process, ^worker, _}, 1_000
      assert_result(caller, {:error, :connect_worker_down})
    end
  end

  for {signal, reason} <- [abort: :aborted, deadline: :request_timeout] do
    test "#{signal} drains a result queued during handoff" do
      {listener, port} = listener()
      {caller, worker, monitor} = start_connect(port)
      send(worker, :connect)
      {:ok, peer} = :gen_tcp.accept(listener, 1_000)
      assert_receive {:transferred, ^worker, socket, ^caller}, 1_000
      :erlang.suspend_process(caller)
      send(caller, unquote(signal))
      send(worker, :complete)
      assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 1_000

      assert {:messages, [unquote(signal), {:connect_result, _, {:ok, ^socket}} | _]} =
               Process.info(caller, :messages)

      :erlang.resume_process(caller)
      assert_result(caller, {:error, unquote(reason)})
      assert :gen_tcp.recv(peer, 0, 1_000) == {:error, :closed}
      assert :erlang.port_info(socket) == :undefined
      :gen_tcp.close(peer)
    end
  end

  test "tracked cancellation rejects a cooperative worker's late result" do
    {listener, port} = listener()
    {caller, worker, monitor} = start_connect(port, lifecycle: true)
    send(worker, :connect)
    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    assert_receive {:transferred, ^worker, socket, ^caller}, 1_000
    send(caller, :abort)
    assert_result(caller, {:error, :aborted})
    assert Process.alive?(worker)
    send(worker, :complete)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 1_000
    assert_clean(caller)
    assert :gen_tcp.recv(peer, 0, 1_000) == {:error, :closed}
    assert :erlang.port_info(socket) == :undefined
    :gen_tcp.close(peer)
  end

  test "a crash after socket transfer closes the caller-owned socket" do
    {listener, port} = listener()
    {caller, worker, monitor} = start_connect(port)
    send(worker, :connect)
    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    assert_receive {:transferred, ^worker, socket, ^caller}, 1_000
    assert :erlang.port_info(socket, :connected) == {:connected, caller}
    send(worker, :raise)
    assert_receive {:DOWN, ^monitor, :process, ^worker, _}, 1_000
    assert_result(caller, {:error, :connect_worker_down})
    assert :gen_tcp.recv(peer, 0, 1_000) == {:error, :closed}
    assert :erlang.port_info(socket) == :undefined
    :gen_tcp.close(peer)
  end

  test "successful result wins over normal worker exit and retains the socket" do
    {listener, port} = listener()
    {caller, worker, monitor} = start_connect(port)
    send(worker, :connect)
    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    assert_receive {:transferred, ^worker, socket, ^caller}, 1_000
    send(worker, :complete)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 1_000
    assert_result(caller, {:ok, socket})
    assert :erlang.port_info(socket, :connected) == {:connected, caller}
    :gen_tcp.close(socket)
    :gen_tcp.close(peer)
  end

  test "ordinary connect errors keep their reason" do
    {caller, worker, monitor} = start_connect()
    send(worker, :error)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 1_000
    assert_result(caller, {:error, :econnrefused})
  end

  for {signal, reason} <- [abort: :aborted, deadline: :request_timeout] do
    test "#{signal} during handoff closes the socket and cleans the monitor" do
      {listener, port} = listener()
      {caller, worker, monitor} = start_connect(port)
      send(worker, :connect)
      {:ok, peer} = :gen_tcp.accept(listener, 1_000)
      assert_receive {:transferred, ^worker, socket, ^caller}, 1_000
      send(caller, unquote(signal))
      assert_result(caller, {:error, unquote(reason)})
      assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 1_000
      assert_clean(caller)
      assert :gen_tcp.recv(peer, 0, 1_000) == {:error, :closed}
      assert :erlang.port_info(socket) == :undefined
      :gen_tcp.close(peer)
    end
  end

  test "subscriber death keeps its distinct cancellation result" do
    subscriber =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    {caller, worker, monitor} = start_connect(0, subscriber: subscriber)
    send(subscriber, :stop)
    assert_result(caller, {:error, :subscriber_down})
    assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 1_000
    assert_clean(caller)
  end

  test "a live stalled worker still reaches the connect deadline" do
    {caller, worker, monitor} = start_connect(0, timeout: 100)
    assert_result(caller, {:error, :connect_timeout})
    assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 1_000
    assert_clean(caller)
  end

  defp start_connect(port \\ 0, opts \\ []) do
    observer = self()
    timeout = Keyword.get(opts, :timeout, 30_000)

    caller =
      spawn(fn ->
        cancel_monitor = if opts[:subscriber], do: Process.monitor(opts[:subscriber])

        tracker =
          if opts[:lifecycle] do
            {tracker, _latch} = HTTP.RequestLifecycle.start()
            Process.put(HTTP.RequestLifecycle, tracker)
            send(observer, {:tracker, self(), tracker})
            tracker
          end

        request = %HTTP.Request{
          url: URI.parse("http://localhost"),
          transport_options: [
            connect_timeout: timeout,
            request_lifecycle: tracker,
            connect_failure_token: opts[:connect_failure_token]
          ]
        }

        result =
          HTTP.Runtime.Dialer.connect(
            ControlledTransport,
            observer,
            port,
            request,
            %{mode: :http1, alpn_protocols: []},
            timeout,
            cancel_monitor
          )

        send(observer, {:result, self(), result})
        caller_loop(observer)
      end)

    on_exit(fn -> Process.exit(caller, :kill) end)

    if opts[:lifecycle] do
      assert_receive {:tracker, ^caller, tracker}, 1_000
      on_exit(fn -> Process.exit(tracker, :kill) end)
    end

    assert_receive {:connecting, worker}, 1_000
    on_exit(fn -> Process.exit(worker, :kill) end)
    {caller, worker, Process.monitor(worker)}
  end

  defp caller_loop(observer) do
    receive do
      :inspect ->
        send(
          observer,
          {:clean, self(), Process.info(self(), :monitors), Process.info(self(), :messages)}
        )

        caller_loop(observer)
    end
  end

  defp assert_result(caller, result) do
    assert_receive {:result, ^caller, ^result}, 1_000
    assert_clean(caller)
  end

  defp assert_clean(caller) do
    send(caller, :inspect)
    assert_receive {:clean, ^caller, {:monitors, []}, {:messages, []}}, 1_000
  end

  defp listener do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {listener, port}
  end
end
