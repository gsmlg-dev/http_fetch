defmodule SSL.Lifecycle.Setup do
  @moduledoc false
  use GenServer, restart: :temporary
  alias SSL.{Connection, Options, Socket}
  alias SSL.Lifecycle.{Allocator, Observer, Receipt}

  # Serializes actual births and control replies while the original authority owns cleanup.
  defmodule State do
    @moduledoc false
    @derive {Inspect, only: [:phase]}
    defstruct [
      :context,
      :owner,
      :observer,
      :timer,
      :socket,
      :connection,
      :allocator,
      :ready_nonce,
      :allocation_nonce,
      :tcp,
      :request,
      phase: :enrolling,
      monitors: %{},
      connection_ready: false,
      allocator_down: false,
      handoff_ack: false
    ]
  end

  @type context :: %{
          receipt: Receipt.t(),
          permit: reference(),
          allocator_permit: reference(),
          endpoint: {:inet.ip4_address(), 1..65_535},
          classic:
            {pid(), reference(), :atomics.atomics_ref(), Options.t(), integer() | :infinity},
          control_deadline: {:abs_ms, integer()},
          ready: {pid(), reference()}
        }
  @spec start(context()) :: GenServer.on_start()
  def start(
        %{
          receipt: %Receipt{observer: observer, cell: cell},
          permit: permit,
          allocator_permit: allocation,
          endpoint: {{_, _, _, _}, port},
          classic: {owner, ref, status, %Options{}, original},
          control_deadline: {:abs_ms, control},
          ready: {recipient, nonce}
        } = context
      )
      when map_size(context) == 7 and is_pid(observer) and
             is_reference(cell) and is_reference(permit) and is_reference(allocation) and
             is_reference(ref) and is_reference(status) and is_reference(nonce) and
             is_integer(control) and (is_integer(original) or original == :infinity) and
             is_integer(port) do
    admit(context, observer, owner, recipient)
  end

  def start(_), do: {:error, :invalid_lifecycle_context}

  defp admit(context, observer, owner, recipient) do
    {ip, port} = context.endpoint

    valid? =
      node(observer) == node() and owner == self() and recipient == self() and
        port in 1..65_535 and
        Enum.all?(Tuple.to_list(ip), &(is_integer(&1) and &1 in 0..255))

    if valid?,
      do: start_before_deadline(context, observer),
      else: {:error, :invalid_lifecycle_context}
  end

  defp start_before_deadline(context, observer) do
    {_owner, _ref, _status, _options, original} = context.classic
    {:abs_ms, control} = context.control_deadline
    deadline = if original == :infinity, do: control, else: min(control, original)
    remaining = deadline - now()

    if remaining > 0 do
      start_actor(%{context | control_deadline: {:abs_ms, deadline}}, observer, remaining)
    else
      {:error, :deadline_exceeded}
    end
  end

  defp start_actor(context, observer, remaining) do
    case GenServer.start(__MODULE__, {context, self(), observer},
           timeout: min(remaining, 0xFFFFFFFF)
         ) do
      {:ok, pid} -> {:ok, pid}
      _ -> {:error, :acceptance_unconfirmed}
    end
  catch
    _kind, _reason -> {:error, :acceptance_unconfirmed}
  end

  @impl true
  def init({context, owner, observer}) do
    Process.flag(:sensitive, true)

    monitors = %{
      Process.monitor(owner) => {:owner, :process, owner},
      Process.monitor(observer) => {:observer, :process, observer}
    }

    timer = :erlang.start_timer(elem(context.control_deadline, 1), self(), :expiry, abs: true)

    state = %State{
      context: context,
      owner: owner,
      observer: observer,
      timer: timer,
      monitors: monitors,
      ready_nonce: make_ref(),
      allocation_nonce: make_ref()
    }

    {:ok, state, {:continue, :enroll}}
  end

  @impl true
  def handle_continue(:enroll, state) do
    # Account this already-born actor before testing original parent liveness.
    case Observer.enroll_self(state.context.receipt, :setup, state.context.permit, budget(state)) do
      :use -> reserve_connection(state)
      :stop -> {:stop, :normal, state}
      {:error, _} -> uncertain(state)
    end
  end

  @impl true
  def handle_call(_request, _from, state), do: {:reply, {:error, :closed}, state}

  @impl true
  def handle_info({:timeout, timer, :expiry}, %State{timer: timer} = state),
    do: {:stop, :normal, state}

  def handle_info(
        {:lifecycle_ready, connection, nonce},
        %State{phase: :births, connection: connection, ready_nonce: nonce} = state
      ),
      do: prepare_if_ready(%{state | connection_ready: true})

  def handle_info(
        {:lifecycle_allocated, allocator, nonce, observer, tcp},
        %State{
          phase: :births,
          allocator: allocator,
          allocation_nonce: nonce,
          observer: observer,
          tcp: nil
        } = state
      )
      when is_port(tcp) do
    if Port.info(tcp, :connected) == {:connected, allocator},
      do: prepare_if_ready(watch_port(%{state | tcp: tcp}, tcp)),
      else: {:noreply, state}
  end

  def handle_info({:DOWN, ref, type, object, reason} = message, state) do
    case Map.fetch(state.monitors, ref) do
      {:ok, {:allocator, :process, ^object}} when type == :process and reason == :normal ->
        native_if_complete(%{state | allocator_down: true})

      {:ok, {_role, ^type, ^object}} ->
        {:stop, :normal, state}

      _ ->
        response(message, state)
    end
  end

  def handle_info(message, state), do: response(message, state)

  @impl true
  def format_status(status),
    do: Map.merge(status, %{state: :redacted, message: :redacted, reason: :redacted, log: []})

  defp reserve_connection(state) do
    if live?(state) do
      case Observer.reserve_child(state.context.receipt, :connection, budget(state)) do
        {:ok, permit} -> start_connection(permit, state)
        {:error, _} -> uncertain(state)
      end
    else
      {:stop, :normal, state}
    end
  end

  defp start_connection(permit, state) do
    context = %{
      receipt: state.context.receipt,
      permit: permit,
      control_deadline: budget(state),
      ready: {self(), state.ready_nonce}
    }

    if live?(state) do
      case Connection.start_inert({:inert, state.context.classic, context}) do
        {:ok, connection} -> connection_started(connection, state)
        _ -> uncertain(state)
      end
    else
      {:stop, :normal, state}
    end
  end

  defp connection_started(connection, state) do
    {_owner, ref, status, _options, _deadline} = state.context.classic
    socket = %Socket{pid: connection, ref: ref, status: status}
    state = watch(%{state | connection: connection, socket: socket}, :connection, connection)
    # Retain a late birth identity before the next deadline/liveness gate.
    if live?(state), do: start_allocator(state), else: {:stop, :normal, state}
  end

  defp start_allocator(state) do
    {ip, port} = state.context.endpoint

    context = %{
      receipt: state.context.receipt,
      permit: state.context.allocator_permit,
      ip: ip,
      port: port,
      deadline: budget(state),
      recipient: self(),
      nonce: state.allocation_nonce
    }

    case allocator_birth(context) do
      {:ok, allocator} ->
        state = watch(%{state | allocator: allocator, phase: :births}, :allocator, allocator)
        if live?(state), do: {:noreply, state}, else: {:stop, :normal, state}

      _ ->
        uncertain(state)
    end
  end

  defp allocator_birth(context) do
    Allocator.start(context)
  catch
    _kind, _reason -> {:error, :acceptance_unconfirmed}
  end

  defp prepare_if_ready(
         %State{phase: :births, connection_ready: true, tcp: tcp, socket: %Socket{ref: ref}} =
           state
       )
       when is_port(tcp) do
    if live?(state) and Process.alive?(state.connection) and Process.alive?(state.allocator) do
      request =
        :gen_statem.send_request(
          state.connection,
          {ref, {:prepare_handoff, state.ready_nonce, budget(state)}}
        )

      {:noreply, %{state | phase: :preparing, request: request}}
    else
      {:stop, :normal, state}
    end
  end

  defp prepare_if_ready(state), do: {:noreply, state}

  defp response(message, %State{phase: :preparing, request: request} = state) do
    case :gen_statem.check_response(message, request) do
      {:reply, :ok} -> request_handoff(state)
      :no_reply -> {:noreply, state}
      _ -> uncertain(state)
    end
  end

  defp response(message, %State{phase: :handing_off, request: request} = state) do
    case :gen_server.check_response(message, request) do
      {:reply, :ok} ->
        native_if_complete(%{
          state
          | phase: :await_allocator_down,
            handoff_ack: true,
            request: nil
        })

      :no_reply ->
        {:noreply, state}

      _ ->
        uncertain(state)
    end
  end

  defp response(_message, state), do: {:noreply, state}

  defp request_handoff(%State{socket: %Socket{ref: ref}} = state) do
    if live?(state) and Process.alive?(state.connection) and Process.alive?(state.allocator) do
      request =
        :gen_server.send_request(
          state.allocator,
          {:handoff, state.allocation_nonce, {state.connection, ref, state.ready_nonce},
           elem(budget(state), 1)}
        )

      {:noreply, %{state | phase: :handing_off, request: request}}
    else
      {:stop, :normal, state}
    end
  end

  defp native_if_complete(
         %State{
           phase: :await_allocator_down,
           handoff_ack: true,
           allocator_down: true,
           socket: %Socket{} = socket,
           tcp: tcp
         } = state
       )
       when is_port(tcp) do
    if live?(state) and Process.alive?(state.connection) and
         Port.info(tcp, :connected) == {:connected, state.connection} do
      {recipient, nonce} = state.context.ready
      send(recipient, {:lifecycle_native_owned, self(), nonce, state.observer, socket, tcp})
      # Native ownership is not TLS/setup success. Keep the ORIGINAL pending timer.
      {:noreply, %{state | phase: :native_owned}}
    else
      uncertain(state)
    end
  end

  defp native_if_complete(state), do: {:noreply, state}

  # Unknown acceptance cannot authorize cancellation, retry, rollback or a TCP close.
  defp uncertain(state), do: {:noreply, %{state | phase: :uncertain, request: nil}}

  defp watch(state, role, pid) do
    monitor = Process.monitor(pid)
    %{state | monitors: Map.put(state.monitors, monitor, {role, :process, pid})}
  end

  defp watch_port(state, tcp) do
    monitor = :erlang.monitor(:port, tcp)
    %{state | monitors: Map.put(state.monitors, monitor, {:tcp, :port, tcp})}
  end

  defp budget(state), do: state.context.control_deadline

  defp live?(state),
    do:
      now() < elem(budget(state), 1) and
        Process.alive?(state.owner) and Process.alive?(state.observer)

  defp now, do: System.monotonic_time(:millisecond)
end
