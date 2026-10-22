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
      tcp: nil
    }

    {:ok, state, {:continue, :enroll}}
  end

  @impl true
  def handle_continue(:enroll, state) do
    context = state.context
    # Already-born actors attempt accounting even after parent/recipient loss.
    with :use <-
           Observer.enroll_self(context.receipt, :allocator, context.permit, context.deadline),
         true <- live?(state),
         {:ok, tcp} <-
           NativeTCP.connect(context.receipt, context.ip, context.port, context.deadline) do
      allocated(%{state | tcp: tcp})
    else
      :stop -> {:stop, :normal, state}
      false -> {:stop, :normal, state}
      {:error, _reason} -> {:stop, :normal, state}
    end
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
  def handle_info({:timeout, timer, :expiry}, %{timer: timer} = state),
    do: {:stop, :normal, state}

  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    if Map.fetch(state.monitors, ref) == {:ok, pid},
      do: {:stop, :normal, state},
      else: {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{tcp: tcp}) when is_port(tcp), do: :gen_tcp.close(tcp)
  def terminate(_reason, _state), do: :ok

  defp live?(state) do
    now() < elem(state.context.deadline, 1) and
      Enum.all?([state.parent, state.context.recipient, state.observer], &Process.alive?/1)
  end

  defp now, do: System.monotonic_time(:millisecond)
end
