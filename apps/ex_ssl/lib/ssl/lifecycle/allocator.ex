defmodule SSL.Lifecycle.Allocator do
  @moduledoc false
  use GenServer, restart: :temporary
  alias SSL.Lifecycle.{NativeTCP, Observer, Receipt}

  # Private trusted context: valid opaque Receipt and deadline already clipped to
  # setup. Startup acknowledges an inert process, never allocation or readiness.
  @type context :: %{
          receipt: Receipt.t(),
          permit: reference(),
          ip: :inet.ip4_address(),
          port: 1..65_535,
          deadline: {:abs_ms, integer()},
          recipient: pid(),
          nonce: reference()
        }
  @spec start(context()) :: GenServer.on_start()
  def start(
        %{
          receipt: receipt,
          permit: permit,
          ip: {_, _, _, _} = ip,
          port: port,
          deadline: {:abs_ms, deadline},
          recipient: recipient,
          nonce: nonce
        } = context
      )
      when is_reference(permit) and is_pid(recipient) and is_reference(nonce) and
             is_integer(port) and port in 1..65_535 and is_integer(deadline) do
    observer = Receipt.observer(receipt)

    with true <- node(observer) == node() and node(recipient) == node(),
         true <- Enum.all?(Tuple.to_list(ip), &(is_integer(&1) and &1 in 0..255)),
         remaining when remaining > 0 <- deadline - now() do
      GenServer.start(__MODULE__, {context, self(), observer},
        timeout: min(remaining, 0xFFFFFFFF)
      )
    else
      false -> {:error, :invalid_lifecycle_context}
      _ -> {:error, :deadline_exceeded}
    end
  end

  def start(_), do: {:error, :invalid_lifecycle_context}

  @spec handoff(pid(), reference(), {pid(), reference(), reference()}, {:abs_ms, integer()}) ::
          :ok | {:error, atom()}
  def handoff(allocator, nonce, target, {:abs_ms, deadline})
      when is_pid(allocator) and node(allocator) == node() and is_integer(deadline) do
    try do
      GenServer.call(
        allocator,
        {:handoff, nonce, target, deadline},
        min(max(1, deadline - now()), 0xFFFFFFFF)
      )
    catch
      :exit, _reason -> {:error, :acceptance_unconfirmed}
    end
  end

  def handoff(_allocator, _nonce, _target, _deadline),
    do: {:error, :invalid_handoff_context}

  @impl true
  def init({context, parent, observer}) do
    monitors =
      Map.new([parent, context.recipient, observer], fn pid -> {Process.monitor(pid), pid} end)

    timer = :erlang.start_timer(elem(context.deadline, 1), self(), :expiry, abs: true)

    state = %{
      context: context,
      parent: parent,
      observer: observer,
      monitors: monitors,
      timer: timer,
      tcp: nil,
      transfer: %{from: nil, connection: nil, request: nil, deadline: context.deadline}
    }

    {:ok, state, {:continue, :enroll}}
  end

  @impl true
  def handle_continue(:enroll, state) do
    context = state.context
    # Already-born actors attempt accounting even after parent/recipient loss.
    with :use <-
           Observer.enroll_self(context.receipt, :allocator, context.permit, context.deadline),
         true <- live?(state) do
      native_result(
        NativeTCP.connect(context.receipt, context.ip, context.port, context.deadline),
        state
      )
    else
      :stop -> {:stop, :normal, state}
      false -> {:stop, :normal, state}
      {:error, _reason} -> {:stop, :normal, state}
    end
  end

  defp native_result({:ok, tcp}, state), do: allocated(%{state | tcp: tcp})

  defp native_result({:error, reason}, state)
       when reason in [:econnrefused, :enetunreach, :ehostunreach] do
    record_connect_failure(state.context, reason)
    {:stop, :normal, state}
  end

  defp native_result({:error, _reason}, state), do: {:stop, :normal, state}

  defp record_connect_failure(context, reason) do
    _ = Observer.record_connect_failure(context.receipt, reason, context.deadline)
    :ok
  catch
    _kind, _reason -> :ok
  end

  defp allocated(state) do
    if live?(state) do
      send(
        state.context.recipient,
        {:lifecycle_allocated, self(), state.context.nonce, state.observer, state.tcp}
      )

      {:noreply, state}
    else
      {:stop, :normal, state}
    end
  end

  @impl true
  def handle_call({:handoff, nonce, target, deadline}, from, state) do
    cond do
      elem(from, 0) != state.context.recipient or nonce != state.context.nonce ->
        {:reply, {:error, :unauthorized_handoff}, state}

      state.transfer.from != nil ->
        {:reply, {:error, :handoff_spent}, state}

      not valid_target?(target, deadline) ->
        {:reply, {:error, :invalid_handoff_context}, state}

      true ->
        begin_handoff(from, target, deadline, state)
    end
  end

  @impl true
  def handle_info({:timeout, timer, :expiry}, %{timer: timer} = state),
    do: stop_handoff(state)

  def handle_info({:DOWN, ref, :process, pid, _reason} = message, state) do
    if Map.fetch(state.monitors, ref) == {:ok, pid},
      do: stop_handoff(state),
      else: response(message, state)
  end

  def handle_info(message, state), do: response(message, state)

  @impl true
  def terminate(_reason, %{tcp: tcp}) when is_port(tcp) do
    if Port.info(tcp, :connected) == {:connected, self()}, do: :gen_tcp.close(tcp)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp valid_target?({connection, socket_ref, ready_nonce}, deadline),
    do:
      is_pid(connection) and node(connection) == node() and
        is_reference(socket_ref) and is_reference(ready_nonce) and is_integer(deadline)

  defp valid_target?(_target, _deadline), do: false

  defp begin_handoff(from, {connection, socket_ref, ready_nonce}, requested, state) do
    deadline = min(requested, elem(state.context.deadline, 1))
    transfer = %{from: from, connection: connection, request: nil, deadline: {:abs_ms, deadline}}
    admitted = arm_handoff(%{state | transfer: transfer}, deadline)
    prepare_transfer(socket_ref, ready_nonce, admitted)
  end

  defp prepare_transfer(socket_ref, ready_nonce, state) do
    with true <- handoff_live?(state),
         {:ok, grant, {:abs_ms, bound}} <-
           Observer.prepare_handoff_bounded(
             state.context.receipt,
             state.tcp,
             state.transfer.connection,
             state.transfer.deadline
           ) do
      deadline = min(elem(state.transfer.deadline, 1), bound)
      offer_transfer(socket_ref, ready_nonce, grant, arm_handoff(state, deadline))
    else
      _ -> stop_handoff(state)
    end
  end

  defp offer_transfer(socket_ref, ready_nonce, grant, state) do
    connection = state.transfer.connection

    with true <- handoff_live?(state),
         {:connected, owner} when owner == self() <- Port.info(state.tcp, :connected),
         :ok <- :gen_tcp.controlling_process(state.tcp, connection),
         true <- handoff_live?(state),
         {:connected, ^connection} <- Port.info(state.tcp, :connected) do
      offer =
        {socket_ref,
         {:commit_handoff, self(), state.context.recipient, ready_nonce, state.observer,
          state.tcp, grant, state.transfer.deadline}}

      request = :gen_statem.send_request(connection, offer)
      {:noreply, %{state | transfer: %{state.transfer | request: request}}}
    else
      _ -> stop_handoff(state)
    end
  end

  defp arm_handoff(state, deadline) do
    _ = Process.cancel_timer(state.timer)
    transfer = %{state.transfer | deadline: {:abs_ms, deadline}}
    timer = :erlang.start_timer(deadline, self(), :expiry, abs: true)
    %{state | timer: timer, transfer: transfer}
  end

  defp handoff_live?(state),
    do:
      live?(state) and now() < elem(state.transfer.deadline, 1) and
        Process.alive?(state.transfer.connection)

  defp response(message, %{transfer: %{request: request}} = state) when request != nil do
    case :gen_statem.check_response(message, request) do
      {:reply, :ok} -> complete_handoff(state)
      :no_reply -> {:noreply, state}
      _ -> stop_handoff(state)
    end
  end

  defp response(_message, state), do: {:noreply, state}

  defp complete_handoff(state) do
    with true <- transferred_live?(state),
         :ok <- Observer.helper_done(state.context.receipt, state.transfer.deadline),
         true <- transferred_live?(state) do
      GenServer.reply(state.transfer.from, :ok)
      {:stop, :normal, state}
    else
      _ -> stop_handoff(state)
    end
  end

  defp transferred_live?(state),
    do:
      handoff_live?(state) and
        Port.info(state.tcp, :connected) == {:connected, state.transfer.connection}

  # Unknown control acceptance never authorizes rollback or foreign-owner close.
  defp stop_handoff(state) do
    if state.transfer.from != nil,
      do: GenServer.reply(state.transfer.from, {:error, :acceptance_unconfirmed})

    {:stop, :normal, state}
  end

  defp live?(state) do
    now() < elem(state.context.deadline, 1) and
      Enum.all?([state.parent, state.context.recipient, state.observer], &Process.alive?/1)
  end

  defp now, do: System.monotonic_time(:millisecond)
end
