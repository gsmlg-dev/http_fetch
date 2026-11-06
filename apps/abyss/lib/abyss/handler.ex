defmodule Abyss.Handler do
  @moduledoc """
  `Abyss.Handler` defines the behaviour required of the application layer of an Abyss server.

  # Example

  A server that echoes back all data sent to it:

  ```elixir
  defmodule Echo do
    use Abyss.Handler

    @impl Abyss.Handler
    def handle_data({ip, port, data}, state) do
      Abyss.Transport.UDP.send(state.socket, ip, port, data)
      {:continue, state}
    end
  end
  ```

  Each incoming UDP packet spawns a handler process; the packet is delivered
  to `c:handle_data/2` as `{ip, port, data}`. Responses are sent through the
  shared listener socket available as `state.socket` (ownership of that
  socket stays with the listener).

  # Handler Lifecycle

  1. The listener receives a packet and starts your handler under the
     server's connection supervisor
  2. The handler process receives the packet and invokes `c:handle_data/2`
  3. The return value determines what happens next (see `c:handle_data/2`):
     continue waiting for messages/timeouts, close, or error out
  4. On termination one of `c:handle_close/1`, `c:handle_error/2`,
     `c:handle_shutdown/1`, or `c:handle_timeout/1` is invoked

  Legacy broadcast mode processes one packet and then terminates with the
  callback's returned state and error/cleanup contract.

  Memory sampling uses the byte count reported by `Process.info/2`. It is
  a per-process safety check, not a strict total-memory bound: blocked
  callbacks delay checks, and shared/off-heap binaries are not fully covered.

  # State

  The handler state is a map seeded by Abyss with (at least) `:socket`, the
  shared listener socket; `:server_config`, the `Abyss.ServerConfig` (whose
  `handler_options` field carries the options you passed to
  `Abyss.start_link/1`); and `:read_timeout`. Any additional keys you add in
  `c:handle_data/2` are preserved across callbacks.

  # Asynchronous Messages

  The handler process is a regular `GenServer`, so you can send it messages
  and define `handle_info/2` clauses alongside the Abyss callbacks. You can
  pass options to the underlying `GenServer` via the `genserver_options` key
  of `Abyss.start_link/1`. Do not pass the `name` option; if you need to
  register handler processes, do so from within `c:handle_data/2`.

  # Custom handler modules

  Any module implementing `start_link/1` and accepting a
  `{:new_connection, socket, recv_data}` message may be used as a
  `handler_module` instead of `use Abyss.Handler`. Note that the
  `:connection` telemetry span events are emitted by the generated
  implementation; admission and termination counters are owned by the
  listener's process monitors for generated and custom handlers alike.
  Handler processes should use a `:temporary` restart strategy so crashed
  handlers are not restarted.
  """

  @typedoc "The possible ways to indicate a timeout when returning values to Abyss"
  @type timeout_options :: timeout() | {:persistent, timeout()}

  @typedoc "The result returned by `c:handle_data/2`"
  @type handler_result ::
          {:continue, state :: term()}
          | {:continue, state :: term(), timeout_options()}
          | {:close, state :: term()}
          | {:error, term(), state :: term()}

  @doc """
  Processes one datagram `{peer_address, peer_port, payload}` (including an
  empty payload). `{:continue, state}` preserves the process and returned
  state, but does not route subsequent packets from that sender to it.
  Persistent routing requires the optional datagram dispatcher.

  An explicit `timeout` applies until the next `handle_data` result; a
  `{:persistent, timeout}` also changes the default for later results.
  `:infinity` deliberately disables idle expiry. Only application datagram
  processing resets the idle deadline; memory checks, status calls, stale
  timer events, and arbitrary local messages do not extend it. Application
  `handle_info/2` callbacks may explicitly use `manage_idle_timer/1` on a
  `{:noreply, state, timeout}` return value to reset idle expiry.

  `{:close, state}` finishes and invokes `handle_close/1`; `{:error, reason,
  state}` finishes and invokes the error callback (`:timeout` invokes the
  timeout callback). No result closes the shared listener socket.

  Legacy broadcast processing is one-shot: a continued result finishes with
  its returned state and invokes close cleanup; errors keep their reason and
  invoke the applicable cleanup. Delivery mode never discards callback state.
  """
  @callback handle_data(data :: Abyss.Transport.recv_data(), state :: term()) :: handler_result()

  @doc "Cleanup when the application finishes a datagram; the shared socket stays open."
  @callback handle_close(state :: term()) :: term()

  @doc "Cleanup on callback or infrastructure error; the shared socket remains listener-owned."
  @callback handle_error(reason :: any(), state :: term()) :: term()

  @doc """
  Cleanup on orderly process shutdown. As with `c:GenServer.terminate/2`,
  forced `:kill` can bypass application cleanup. Listener-owned monitors
  release admission/accounting even when this callback cannot run.
  """
  @callback handle_shutdown(state :: term()) :: term()

  @doc "Cleanup after the managed application idle deadline expires."
  @callback handle_timeout(state :: term()) :: term()

  @optional_callbacks handle_data: 2,
                      handle_error: 2,
                      handle_close: 1,
                      handle_shutdown: 1,
                      handle_timeout: 1

  @spec __using__(any) :: Macro.t()
  defmacro __using__(_opts) do
    quote location: :keep do
      @behaviour Abyss.Handler

      use GenServer, restart: :temporary

      def start_link(args) do
        GenServer.start_link(__MODULE__, args)
      end

      unquote(genserver_impl())
      unquote(handler_impl())
    end
  end

  @doc false
  defmacro add_handle_info_fallback(_module) do
    quote do
      def handle_info({msg, _raw_ip, _port, _data}, _state) when msg in [:udp] do
        raise """
          The callback's `state` doesn't match the expected `{socket, state}` form.
          Please ensure that you are returning a `{socket, state}` tuple from any
          `GenServer.handle_*` callbacks you have implemented
        """
      end

      def handle_info(_message, state), do: {:noreply, state}
    end
  end

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def genserver_impl do
    quote do
      @impl GenServer
      def init({connection_span, server_config, listener_pid, listener_socket}) do
        Process.flag(:trap_exit, true)

        Process.put(
          :abyss_endpoint_id,
          Map.get(connection_span.start_metadata, :server_pid, :unscoped)
        )

        memory_token = make_ref()

        memory_timer =
          Process.send_after(
            self(),
            {:abyss_memory_check, memory_token},
            server_config.handler_memory_check_interval
          )

        {:ok,
         %{
           connection_span: connection_span,
           server_config: server_config,
           listener: listener_pid,
           broadcast: server_config.broadcast,
           socket: listener_socket,
           read_timeout: server_config.read_timeout,
           # Track last 10 processing times for adaptive timeout
           processing_times: [],
           adaptive_timeout: server_config.read_timeout,
           memory_check_interval: server_config.handler_memory_check_interval,
           memory_token: memory_token,
           memory_timer: memory_timer,
           idle_token: nil,
           idle_timer: nil,
           idle_deadline: :infinity
         }}
      end

      @impl GenServer
      def handle_info(
            {:new_connection, listener_socket, recv_data},
            %{broadcast: false} = state
          ) do
        Abyss.Telemetry.span_event(state.connection_span, :ready)
        {:noreply, state, {:continue, {:handle_data, recv_data}}}
      catch
        {:stop, _, _} = stop -> stop
      end

      def handle_info(
            {:new_connection, listener_socket, recv_data},
            %{broadcast: true} = state
          ) do
        {:noreply, state, {:continue, {:handle_broadcast_data, recv_data}}}
      catch
        {:stop, _, _} = stop -> stop
      end

      def handle_info({:abyss_idle_timeout, token}, %{idle_token: token} = state),
        do: Abyss.Handler.expire_idle_timer(state)

      def handle_info({:abyss_idle_timeout, _stale_token}, state), do: {:noreply, state}

      def handle_info({:abyss_memory_check, token}, %{memory_token: token} = state) do
        Abyss.Handler.check_memory(state)
      end

      def handle_info({:abyss_memory_check, _stale_token}, state), do: {:noreply, state}
      def handle_info(:memory_check, state), do: Abyss.Handler.check_memory(state)
      def handle_info(:timeout, state), do: {:noreply, state}

      @before_compile {Abyss.Handler, :add_handle_info_fallback}

      # Use a continue pattern here so that we have committed the socket
      # to state in case the `c:handle_connection/2` callback raises an error.
      # This ensures that the `c:terminate/2` calls below are able to properly
      # close down the process
      @impl true
      def handle_continue({:handle_data, recv_data}, %{processing_times: times} = state) do
        start_time = System.monotonic_time()

        result = __MODULE__.handle_data(recv_data, state)
        processing_time = System.monotonic_time() - start_time

        # Keep last 10 processing times for adaptive timeout calculation
        new_times = [processing_time | Enum.take(times, 9)]

        # Calculate adaptive timeout based on processing history. The
        # bookkeeping is merged into the state returned by the callback so
        # that handler state changes are preserved.
        adaptive_timeout = Abyss.Handler.calculate_adaptive_timeout(state.read_timeout, new_times)

        result
        |> Abyss.Handler.handle_continuation(%{
          processing_times: new_times,
          adaptive_timeout: adaptive_timeout
        })
        |> Abyss.Handler.manage_idle_timer()
      end

      def handle_continue({:handle_broadcast_data, recv_data}, state) do
        case Abyss.Handler.handle_continuation(__MODULE__.handle_data(recv_data, state)) do
          {:noreply, returned_state, _timeout} ->
            {:stop, {:shutdown, :local_closed}, returned_state}

          stop ->
            stop
        end
      end

      # Called by GenServer if we hit our read_timeout. Socket is still open
      def terminate({:shutdown, :timeout}, state) do
        out = __MODULE__.handle_timeout(state)
        terminate_cleanup(state, :timeout)
        out
      end

      # Called if we're being shutdown in an orderly manner. Socket is still open
      def terminate(:shutdown, state) do
        out = __MODULE__.handle_shutdown(state)
        terminate_cleanup(state, :shutdown)
        out
      end

      # Called if the socket encountered an error and we are configured to shutdown silently.
      # Socket is closed
      def terminate({:shutdown, {:silent_termination, reason}}, state) do
        out = __MODULE__.handle_error(reason, state)
        terminate_cleanup(state, reason)
        out
      end

      # Called if the remote end shut down the connection, or if the local end closed the
      # connection by returning a `{:close,...}` tuple (in which case the socket will be open)
      def terminate({:shutdown, reason}, state) do
        out = __MODULE__.handle_close(state)
        terminate_cleanup(state, reason)
        out
      end

      # This clause could happen if we do not have a socket defined in state (either because the
      # process crashed before setting it up, or because the user sent an invalid state)
      @impl GenServer
      def terminate(:normal, state) do
        out = __MODULE__.handle_shutdown(state)
        terminate_cleanup(state, :normal)
        out
      end

      def terminate(reason, state) do
        out = __MODULE__.handle_error(reason, state)
        terminate_cleanup(state, reason)
        out
      end

      defoverridable terminate: 2

      defp terminate_cleanup(%{connection_span: span} = state, reason) do
        Abyss.Handler.cancel_timers(state)
        Abyss.Telemetry.stop_span(span, %{}, %{reason: reason})
      end
    end
  end

  def handler_impl do
    quote do
      # @impl true
      # def handle_data(_data, state), do: {:close, state}

      @impl true
      def handle_close(_state), do: :ok

      @impl true
      def handle_error(_error, _state), do: :ok

      @impl true
      def handle_shutdown(_state), do: :ok

      @impl true
      def handle_timeout(_state), do: :ok

      defoverridable Abyss.Handler
    end
  end

  @doc false
  # Translates a `handler_result()` into a GenServer return value. The state
  # carried in the continuation tuple (as returned by the handler callback) is
  # preserved; `bookkeeping` holds internal updates (processing times, adaptive
  # timeout) that are merged on top of it.
  def handle_continuation(continuation, bookkeeping \\ %{}) do
    case continuation do
      {:continue, state} ->
        # Use adaptive timeout instead of fixed read_timeout
        state = merge_bookkeeping(state, bookkeeping)
        {:noreply, state, continue_timeout(state, bookkeeping)}

      {:continue, state, {:persistent, timeout}} ->
        state =
          state
          |> merge_bookkeeping(bookkeeping)
          |> persist_timeout(timeout)

        {:noreply, state, timeout}

      {:continue, state, timeout} ->
        # One-shot timeout for the next message only
        {:noreply, merge_bookkeeping(state, bookkeeping), timeout}

      {:close, state} ->
        {:stop, {:shutdown, :local_closed}, state}

      {:error, :timeout, state} ->
        {:stop, {:shutdown, :timeout}, state}

      {:error, reason, state} ->
        if silent_terminate_on_error?(state, bookkeeping) do
          {:stop, {:shutdown, {:silent_termination, reason}}, state}
        else
          {:stop, reason, state}
        end
    end
  end

  defp merge_bookkeeping(state, bookkeeping) when is_map(state),
    do: Map.merge(state, bookkeeping)

  defp merge_bookkeeping(state, _bookkeeping), do: state

  defp persist_timeout(state, timeout) when is_map(state) do
    state
    |> Map.put(:read_timeout, timeout)
    |> Map.put(:adaptive_timeout, timeout)
  end

  defp persist_timeout(state, _timeout), do: state

  defp continue_timeout(state, bookkeeping) do
    source = if is_map(state), do: state, else: bookkeeping
    Map.get(source, :adaptive_timeout) || Map.get(source, :read_timeout)
  end

  defp silent_terminate_on_error?(%{server_config: config}, _bookkeeping),
    do: config.silent_terminate_on_error

  defp silent_terminate_on_error?(_state, %{server_config: config}),
    do: config.silent_terminate_on_error

  defp silent_terminate_on_error?(_state, _bookkeeping), do: false

  @doc false
  def manage_idle_timer({:noreply, state, timeout}) do
    _ = if timer = Map.get(state, :idle_timer), do: Process.cancel_timer(timer)
    token = make_ref()

    {timer, deadline} =
      case timeout do
        :infinity ->
          {nil, :infinity}

        timeout when is_integer(timeout) and timeout >= 0 ->
          deadline = System.monotonic_time(:millisecond) + timeout

          timer =
            Process.send_after(
              self(),
              {:abyss_idle_timeout, token},
              max(deadline - System.monotonic_time(:millisecond), 0)
            )

          {timer, deadline}
      end

    {:noreply, Map.merge(state, %{idle_timer: timer, idle_token: token, idle_deadline: deadline})}
  end

  def manage_idle_timer(stop), do: stop

  @doc false
  def expire_idle_timer(%{idle_deadline: :infinity} = state), do: {:noreply, state}

  def expire_idle_timer(state) do
    remaining = state.idle_deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      {:stop, {:shutdown, :timeout}, state}
    else
      _ = if timer = state.idle_timer, do: Process.cancel_timer(timer)
      timer = Process.send_after(self(), {:abyss_idle_timeout, state.idle_token}, remaining)
      {:noreply, %{state | idle_timer: timer}}
    end
  end

  @doc false
  def memory_megabytes(memory_bytes), do: memory_bytes / (1024 * 1024)

  @doc false
  def check_memory(state) do
    _ = if timer = Map.get(state, :memory_timer), do: Process.cancel_timer(timer)
    {:memory, bytes} = Process.info(self(), :memory)
    memory_mb = memory_megabytes(bytes)
    config = state.server_config

    if memory_mb > config.handler_memory_warning_threshold do
      :telemetry.execute([:abyss, :handler, :memory_warning], %{memory_mb: memory_mb}, %{
        handler_pid: self(),
        threshold: config.handler_memory_warning_threshold
      })

      :erlang.garbage_collect(self())
    end

    {:memory, bytes} = Process.info(self(), :memory)

    if memory_megabytes(bytes) > config.handler_memory_hard_limit do
      {:stop, {:shutdown, {:silent_termination, :memory_limit_exceeded}}, state}
    else
      token = make_ref()

      timer =
        Process.send_after(self(), {:abyss_memory_check, token}, state.memory_check_interval)

      {:noreply, Map.merge(state, %{memory_timer: timer, memory_token: token})}
    end
  end

  @doc false
  def cancel_timers(state) do
    for key <- [:idle_timer, :memory_timer], timer = Map.get(state, key), timer != nil do
      _ = Process.cancel_timer(timer)
    end

    :ok
  end

  @doc false
  # Add adaptive timeout calculation helper function
  # Returns timeout in milliseconds
  def calculate_adaptive_timeout(:infinity, _processing_times), do: :infinity

  def calculate_adaptive_timeout(base_timeout, processing_times) do
    case processing_times do
      [] ->
        base_timeout

      times ->
        # Calculate average processing time in native time units
        avg_time_native = Enum.sum(times) / length(times)

        # Convert to milliseconds for calculation
        avg_time_ms = System.convert_time_unit(round(avg_time_native), :native, :millisecond)

        # Set timeout to 3x average processing time
        timeout_ms = round(avg_time_ms * 3)

        # Ensure timeout is between 50% and 200% of base timeout (all in milliseconds)
        min_timeout_ms = div(base_timeout, 2)
        max_timeout_ms = base_timeout * 2

        # Apply bounds and return timeout in milliseconds
        timeout_ms
        |> max(min_timeout_ms)
        |> min(max_timeout_ms)
    end
  end
end
