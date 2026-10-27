defmodule SSL.Lifecycle.PolicyHTTPCloseTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias SSL.Lifecycle.{Observer, Reader}
  alias SSL.PolicyIO

  for mode <- [:observer, :private] do
    test "#{mode} retirement protects only the granted closer until native DOWN and finish" do
      a = attempt(unquote(mode))
      assert {:ok, nonce, bound} = invoke(a, &begin_close/1)
      assert bound <= a.expiry
      send(a.actor, {:ping, self()})
      assert_receive {:pong, actor} when actor == a.actor
      retire(a)
      assert is_integer(retirement(a))
      assert invoke(a, fn _ -> :still_alive end) == :still_alive
      assert Process.alive?(a.actor)
      assert :socket.info(a.socket).owner == a.actor
      assert_siblings_down(a)

      # Both public peer closure and exact monitor evidence must follow real close.
      assert :ok = invoke(a, fn state -> :socket.close(state.socket) end)
      assert_socket_down(a)
      assert {:error, :closed} = :gen_tcp.recv(a.peer, 0, 1_000)
      assert Process.alive?(a.actor)
      send(a.actor, {:invoke, self(), make_ref(), &finish_close(&1, nonce)})
      assert_closed(a, :confirmed)
    end

    test "#{mode} stalled closer is killed at the original grace without sealing" do
      a = attempt(unquote(mode))
      assert {:ok, _nonce, _bound} = invoke(a, &begin_close/1)
      started = PolicyIO.now()
      retire(a)
      assert invoke(a, fn _ -> :alive end) == :alive
      grace = retirement(a)
      assert is_integer(grace) and grace <= started + 1_050
      repeat_retirement(a)
      assert retirement(a) == grace
      assert_closed(a, :unconfirmed)
      assert PolicyIO.now() <= grace + 500
    end

    test "#{mode} cleanup finish remains valid after setup expiry without new admission" do
      a = attempt(unquote(mode), 250)
      assert {:ok, nonce, _} = invoke(a, &begin_close/1)
      # A timer notification to the test is only an arrival gate; receiver-side
      # expiry on the RPC below establishes retirement before the assertion.
      reference = make_ref()
      Process.send_after(self(), reference, max(0, a.expiry - PolicyIO.now()) + 1)
      assert_receive ^reference, 1_000
      assert {:error, :admission_closed} = invoke(a, &PolicyIO.call(cleanup_context(&1), :http))
      assert PolicyIO.now() >= a.expiry
      assert :ok = invoke(a, fn state -> :socket.close(state.socket) end)
      assert_socket_down(a)
      send(a.actor, {:invoke, self(), make_ref(), &finish_close(&1, nonce)})
      assert_closed(a, :confirmed)
    end

    test "#{mode} retirement before a grant kills the owner and retains exact evidence" do
      a = attempt(unquote(mode))
      retire(a)
      assert_closed(a, :confirmed)
    end
  end

  test "close grants authenticate capability, caller, generation, native identity and nonce" do
    a = attempt(:private)
    wrong = %{a.context | capability: make_ref()}

    assert {:error, :unauthorized_policy} =
             PolicyIO.call(wrong, {:http_close_begin, a.generation, a.socket, a.expiry})

    assert {:error, :unauthorized_policy} =
             PolicyIO.call(a.context, {:http_close_begin, a.generation, a.socket, a.expiry})

    assert {:error, :http_close_not_permitted} =
             invoke(a, fn state ->
               PolicyIO.call(
                 state.context,
                 {:http_close_begin, state.generation + 1, state.socket, a.expiry}
               )
             end)

    assert {:error, :http_close_not_permitted} =
             invoke(a, fn state ->
               PolicyIO.call(
                 state.context,
                 {:http_close_begin, state.generation, make_ref(), a.expiry}
               )
             end)

    assert {:error, :http_close_not_permitted} =
             invoke(a, fn state ->
               PolicyIO.call(
                 state.context,
                 {:http_close_begin, state.generation, state.socket, PolicyIO.now()}
               )
             end)

    assert {:ok, nonce, _} = invoke(a, &begin_close/1)
    assert {:error, :http_close_not_permitted} = invoke(a, &begin_close/1)
    assert {:error, :http_close_not_permitted} = invoke(a, &finish_close(&1, make_ref()))
    assert :ok = invoke(a, fn state -> :socket.close(state.socket) end)
    assert_socket_down(a)
    assert :ok = invoke(a, &finish_close(&1, nonce))
    assert {:error, :http_close_not_permitted} = invoke(a, &finish_close(&1, nonce))
    retire(a)
    assert_closed(a, :confirmed)
  end

  for mode <- [:observer, :private] do
    test "#{mode} finish before exact DOWN cannot release the close owner" do
      a = attempt(unquote(mode))
      assert {:ok, nonce, _} = invoke(a, &begin_close/1)
      reference = make_ref()
      send(a.actor, {:invoke, self(), reference, &finish_close(&1, nonce)})
      await_finish(a, PolicyIO.now() + 1_000)
      refute_receive {^reference, _}, 100
      retire(a)
      assert is_integer(retirement(a))
      assert Process.alive?(a.actor)
      assert :ok = :socket.close(a.socket)
      assert_closed(a, :confirmed)
    end
  end

  test "a stale close timer cannot retire a completed generation" do
    a = attempt(:private)
    assert {:ok, nonce, _} = invoke(a, &begin_close/1)
    closing = :sys.get_state(a.observer).policy.http_close
    assert :ok = invoke(a, fn state -> :socket.close(state.socket) end)
    assert_socket_down(a)
    assert :ok = invoke(a, &finish_close(&1, nonce))
    send(a.observer, {:timeout, closing.timer, {:policy_http_close, closing.nonce}})

    assert invoke(a, fn state -> PolicyIO.call(state.context, {:settled, state.generation}) end) ==
             :ok

    assert retirement(a) == nil
    retire(a)
    assert_closed(a, :confirmed)
  end

  defp attempt(mode, milliseconds \\ 5_000) do
    parent = self()
    expiry = PolicyIO.now() + milliseconds
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {receipt, lease, setup, connection_token} = observer_setup(mode, expiry)

    {actor, actor_monitor} =
      spawn_monitor(fn ->
        {context, writer} = actor_context(mode, parent, expiry, receipt, connection_token)
        {:ok, generation, token} = PolicyIO.call(context, :http)
        {:ok, socket} = :socket.open(:inet, :stream, :tcp)
        :use = PolicyIO.call(context, {:http_enroll, generation, token, socket})
        :ok = :socket.connect(socket, %{family: :inet, addr: {127, 0, 0, 1}, port: port}, 1_000)
        send(parent, {:ready, self(), context, generation, socket, writer})
        actor_loop(%{context: context, generation: generation, socket: socket})
      end)

    on_exit(fn -> if Process.alive?(actor), do: Process.exit(actor, :kill) end)
    assert_receive {:ready, ^actor, context, generation, socket, writer}, 1_000
    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    observer = context.observer
    observer_monitor = Process.monitor(observer)
    on_exit(fn -> if Process.alive?(observer), do: Process.exit(observer, :kill) end)
    siblings = for pid <- [setup, writer], pid != nil, do: {pid, Process.monitor(pid)}

    %{
      mode: mode,
      actor: actor,
      actor_monitor: actor_monitor,
      observer: observer,
      observer_monitor: observer_monitor,
      context: context,
      generation: generation,
      socket: socket,
      socket_monitor: :socket.monitor(socket),
      peer: peer,
      expiry: expiry,
      receipt: receipt,
      lease: lease,
      siblings: siblings
    }
  end

  defp observer_setup(:private, _), do: {nil, nil, nil, nil}

  defp observer_setup(:observer, expiry) do
    {:ok, receipt, lease} = Observer.start(self(), {:abs_ms, expiry})
    assert :ok = Observer.bind(receipt, lease, deadline())
    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    parent = self()

    setup =
      spawn(fn ->
        :use = Observer.enroll_self(receipt, :setup, token, deadline())
        {:ok, child} = Observer.reserve_child(receipt, :connection, deadline())
        send(parent, {:connection_token, child})
        receive do: (:stop -> :ok)
      end)

    on_exit(fn -> if Process.alive?(setup), do: Process.exit(setup, :kill) end)
    assert_receive {:connection_token, child}, 1_000
    {receipt, lease, setup, child}
  end

  defp actor_context(:private, parent, expiry, _, _) do
    {:ok, context} = PolicyIO.install(nil, parent, expiry)
    {context, nil}
  end

  defp actor_context(:observer, _, _, receipt, token) do
    :use = Observer.enroll_self(receipt, :connection, token, deadline())
    {:ok, writer_token} = Observer.reserve_child(receipt, :writer, deadline())
    parent = self()

    writer =
      spawn(fn ->
        :use = Observer.enroll_self(receipt, :writer, writer_token, deadline())
        send(parent, :writer_ready)
        receive do: (:stop -> :ok)
      end)

    receive do: (:writer_ready -> :ok)
    {:ok, context} = GenServer.call(receipt.observer, {:policy_context, deadline()})
    {context, writer}
  end

  defp actor_loop(state) do
    receive do
      {:invoke, parent, ref, fun} ->
        send(parent, {ref, fun.(state)})
        actor_loop(state)

      {:ping, parent} ->
        send(parent, {:pong, self()})
        actor_loop(state)
    end
  end

  defp invoke(a, fun) do
    ref = make_ref()
    send(a.actor, {:invoke, self(), ref, fun})
    assert_receive {^ref, result}, 1_000
    result
  end

  defp begin_close(state) do
    PolicyIO.call(
      state.context,
      {:http_close_begin, state.generation, state.socket, PolicyIO.now() + 1_000}
    )
  end

  defp finish_close(state, nonce) do
    PolicyIO.call(cleanup_context(state), {:http_close_finish, state.generation, nonce})
  end

  defp cleanup_context(state), do: %{state.context | deadline: PolicyIO.now() + 1_000}
  defp deadline, do: {:abs_ms, PolicyIO.now() + 1_000}

  defp await_finish(a, cutoff) do
    case :sys.get_state(a.observer).policy.http_close do
      %{finished: true} ->
        :ok

      _ ->
        assert PolicyIO.now() < cutoff
        await_finish(a, cutoff)
    end
  end

  defp retire(%{mode: :observer} = a),
    do: assert(:ok == Observer.cancel(a.receipt, a.lease, deadline()))

  defp retire(%{mode: :private} = a) do
    send(a.observer, :deadline)
    :ok
  end

  defp repeat_retirement(%{mode: :observer} = a), do: retire(a)

  defp repeat_retirement(%{mode: :private} = a) do
    send(a.observer, :deadline)
    :sys.get_state(a.observer)
  end

  defp retirement(%{mode: :observer} = a), do: :sys.get_state(a.observer).grace
  defp retirement(%{mode: :private} = a), do: :sys.get_state(a.observer).policy.retirement

  defp assert_siblings_down(a) do
    for {pid, ref} <- a.siblings do
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 500
    end
  end

  defp assert_socket_down(a) do
    %{socket: socket, socket_monitor: monitor} = a
    assert_receive {:DOWN, ^monitor, :socket, ^socket, _}, 1_000
  end

  defp assert_closed(a, proof) do
    %{actor: actor, actor_monitor: actor_ref, observer: observer, observer_monitor: observer_ref} =
      a

    assert_receive {:DOWN, ^actor_ref, :process, ^actor, _}, 1_500
    assert_receive {:DOWN, ^observer_ref, :process, ^observer, :normal}, 1_500

    if a.mode == :observer do
      case proof do
        :confirmed ->
          assert {:ok,
                  %{
                    version: 2,
                    cleanup: :confirmed,
                    roles: 14,
                    observed_down: 14,
                    losses: 0,
                    auxiliary: %{roles: 1, observed_down: 1, losses: 0}
                  }} =
                   Reader.await(a.receipt, deadline())

        :unconfirmed ->
          assert {:unconfirmed, :observer_unsealed} = Reader.await(a.receipt, deadline())
      end
    end
  end
end
