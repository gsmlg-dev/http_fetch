defmodule SSL.Connection do
  @moduledoc false
  @behaviour :gen_statem
  alias SSL.ClientHello.Materializer
  alias SSL.{ConnectionWriter, Diagnostics, IodataCursor, Options, Socket, TCPOptions}
  alias SSL.Lifecycle.{NativeSocket, Observer, Receipt}
  alias SSL.Protocol.{HandshakeMachine, RecordFramer}

  @max_plaintext 1_048_576
  @max_pending_input 1_048_576
  @max_pending_output 1_048_576
  @rearm_reserve 65_536
  @shutdown_timeout 250
  @alert_codes %{
    unexpected_message: 10,
    bad_record_mac: 20,
    record_overflow: 22,
    handshake_failure: 40,
    bad_certificate: 42,
    certificate_expired: 45,
    certificate_unknown: 46,
    illegal_parameter: 47,
    unknown_ca: 48,
    decode_error: 50,
    decrypt_error: 51,
    protocol_version: 70,
    internal_error: 80,
    missing_extension: 109,
    unsupported_extension: 110,
    certificate_required: 116
  }

  defmodule State do
    @moduledoc false
    @derive {Inspect, only: [:socket, :armed, :size, :closed]}
    defstruct [
      :socket,
      :tcp,
      :owner,
      :owner_monitor,
      :options,
      :deadline,
      :machine,
      :ticket_key,
      :connect_from,
      :recv,
      :write,
      :writer,
      :writer_monitor,
      :lifecycle,
      :policy_context,
      :handshake_timer,
      :active,
      :send_timeout,
      :send_timeout_close,
      :negotiated_protocol,
      :native_read,
      :output,
      :pending_control,
      :closing,
      records: nil,
      input: :queue.new(),
      input_size: 0,
      input_terminal: false,
      buffer: :queue.new(),
      size: 0,
      armed: false,
      closed: false,
      write_abandoned?: false,
      duplex_reads?: false,
      active_terminal: false,
      terminal_notified: false
    ]
  end

  def child_spec(args),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [args]}, restart: :temporary}

  @typep classic_init ::
           {pid(), reference(), :atomics.atomics_ref(), Options.t(), integer() | :infinity}
  @typep inert_context :: %{
           required(:receipt) => Receipt.t(),
           required(:permit) => reference(),
           required(:control_deadline) => {:abs_ms, integer()},
           required(:ready) => {pid(), reference()},
           optional(:public) => boolean(),
           optional(:attempt) => reference() | nil
         }

  # Private unlinked birth only; every post-entry failure keeps allocation unknown.
  @spec start_inert({:inert, classic_init(), inert_context()}) ::
          {:ok, pid()} | {:error, term()}
  def start_inert(
        {:inert, {owner, ref, status, %Options{}, setup},
         %{
           receipt: receipt,
           permit: permit,
           control_deadline: {:abs_ms, control},
           ready: {recipient, nonce}
         }} = args
      )
      when is_pid(owner) and is_reference(ref) and
             is_reference(status) and is_reference(permit) and is_integer(control) and
             is_pid(recipient) and is_reference(nonce) and
             (is_integer(setup) or setup == :infinity) do
    if Receipt.valid?(receipt),
      do: admit_inert(args, owner, Receipt.observer(receipt), recipient, setup, control),
      else: {:error, :invalid_lifecycle_context}
  end

  def start_inert(_), do: {:error, :invalid_lifecycle_context}

  defp admit_inert(args, owner, observer, recipient, setup, control) do
    if node(owner) == node() and node(observer) == node() and node(recipient) == node(),
      do: start_inert_before_deadline(args, setup, control),
      else: {:error, :invalid_lifecycle_context}
  end

  defp start_inert_before_deadline(args, setup, control) do
    deadline = if setup == :infinity, do: control, else: min(control, setup)
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining > 0 do
      case :gen_statem.start(__MODULE__, args, timeout: min(remaining, 0xFFFFFFFF)) do
        {:ok, pid} -> {:ok, pid}
        _ -> {:error, :acceptance_unconfirmed}
      end
    else
      {:error, :deadline_exceeded}
    end
  catch
    _kind, _reason -> {:error, :acceptance_unconfirmed}
  end

  @spec start_link(classic_init() | {:inert, classic_init(), inert_context()}) ::
          {:ok, pid()} | :ignore | {:error, term()}
  # This audited rejection branch precedes process creation. Other constructor
  # errors must still be treated as unknown births, never inferred resource absence.
  def start_link(
        {:inert, _classic,
         %{
           receipt: receipt,
           permit: permit,
           control_deadline: {:abs_ms, control},
           ready: {recipient, nonce}
         }} = args
      )
      when is_reference(permit) and is_integer(control) and is_pid(recipient) and
             is_reference(nonce) do
    if Receipt.valid?(receipt),
      do: :gen_statem.start_link(__MODULE__, args, []),
      else: {:error, :invalid_lifecycle_context}
  end

  def start_link({:inert, _classic, _context}), do: {:error, :invalid_lifecycle_context}
  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init({:inert, {owner, ref, status, options, deadline}, context}) do
    Process.flag(:sensitive, true)

    case context do
      %{
        receipt: receipt,
        permit: permit,
        control_deadline: {:abs_ms, control},
        ready: {recipient, nonce}
      }
      when is_reference(permit) and is_integer(control) and is_pid(recipient) and
             is_reference(nonce) ->
        observer = Receipt.observer(receipt)
        # One absolute admission deadline covers even a suspended Observer call.
        # Keep the original setup deadline separately for the later handshake timer.
        control = if deadline == :infinity, do: control, else: min(control, deadline)

        state = %State{
          socket: %Socket{pid: self(), ref: ref, status: status},
          owner: owner,
          owner_monitor: Process.monitor(owner),
          options: options,
          deadline: deadline,
          active: options.active,
          send_timeout: options.send_timeout,
          send_timeout_close: options.send_timeout_close,
          lifecycle: %{
            receipt: receipt,
            permit: permit,
            observer: observer,
            observer_monitor: Process.monitor(observer),
            control_deadline: {:abs_ms, control},
            ready: {recipient, nonce},
            public: Map.get(context, :public, false),
            attempt: Map.get(context, :attempt),
            activated: false,
            epoch: 0,
            writer_nonce: make_ref()
          }
        }

        # Returning first breaks the ConnectionSupervisor -> init -> Observer cycle.
        # No writer, timer, record/TLS state or port exists at this boundary.
        {:ok, :inert_enrolling, state, [{:next_event, :internal, :lifecycle_enroll}]}

      _ ->
        {:stop, :invalid_lifecycle_context}
    end
  end

  def init({owner, ref, status, options, deadline}) do
    Process.flag(:sensitive, true)
    {writer, writer_monitor} = ConnectionWriter.start(self())

    state = %State{
      socket: %Socket{pid: self(), ref: ref, status: status},
      owner: owner,
      owner_monitor: Process.monitor(owner),
      options: options,
      deadline: deadline,
      active: options.active,
      send_timeout: options.send_timeout,
      send_timeout_close: options.send_timeout_close,
      writer: writer,
      writer_monitor: writer_monitor,
      active_terminal: options.active == :once,
      records: RecordFramer.new(),
      handshake_timer: timer(deadline, :handshake_timeout)
    }

    {:ok, :handoff, state}
  end

  @impl true
  def handle_event(:internal, :lifecycle_enroll, :inert_enrolling, state) do
    lifecycle = state.lifecycle

    # Account this already-born process even after parent loss. No-resource
    # settlement is never valid here. An absent observer cannot account a birth.
    with true <- Process.alive?(lifecycle.observer),
         :use <-
           Observer.enroll_self(
             lifecycle.receipt,
             :connection,
             lifecycle.permit,
             lifecycle.control_deadline
           ),
         true <- birth_live?(state) and birth_remaining(state) > 0,
         {:ok, permit} <-
           Observer.reserve_child(lifecycle.receipt, :writer, lifecycle.control_deadline) do
      context = %{
        receipt: lifecycle.receipt,
        permit: permit,
        control_deadline: lifecycle.control_deadline,
        setup_deadline: state.deadline,
        nonce: lifecycle.writer_nonce
      }

      {writer, monitor} = ConnectionWriter.start(self(), context)

      state = %{
        state
        | writer: writer,
          writer_monitor: monitor,
          lifecycle: %{lifecycle | permit: nil}
      }

      {:next_state, :inert_writer, state,
       [{:state_timeout, birth_remaining(state), :birth_expired}]}
    else
      _ -> {:stop, :normal, state}
    end
  end

  def handle_event(:state_timeout, :birth_expired, :inert_writer, state),
    do: {:stop, :normal, state}

  def handle_event(
        :info,
        {:lifecycle_writer_ready, writer, nonce, observer},
        :inert_writer,
        %{writer: writer, lifecycle: %{writer_nonce: nonce, observer: observer}} = state
      ) do
    if birth_live?(state) and Process.alive?(writer) and birth_remaining(state) > 0 do
      send(writer, {:lifecycle_writer_release, self(), nonce, observer})
      {recipient, ready_nonce} = state.lifecycle.ready
      state = %{state | handshake_timer: timer(state.deadline, :handshake_timeout)}
      send(recipient, {:lifecycle_ready, self(), ready_nonce})
      {:next_state, :inert_ready, state}
    else
      {:stop, :normal, state}
    end
  end

  def handle_event(
        :info,
        {:DOWN, ref, :process, observer, _reason},
        _phase,
        %{lifecycle: %{observer: observer, observer_monitor: ref}} = state
      ),
      do: {:stop, :normal, state}

  def handle_event({:call, from}, {ref, _request}, _phase, %{socket: %{ref: actual}})
      when ref != actual,
      do: {:keep_state_and_data, [{:reply, from, {:error, :badarg}}]}

  # Explicit opt-in after birth; the first admitted operation spends this phase.
  def handle_event(
        {:call, from},
        {_ref, {:prepare_handoff, nonce, {:abs_ms, deadline}}},
        phase,
        %{lifecycle: %{ready: {recipient, expected}}} = state
      )
      when is_integer(deadline) do
    cond do
      elem(from, 0) != recipient or nonce != expected ->
        reply(from, {:error, :unauthorized_handoff})

      phase != :inert_ready ->
        reply(from, {:error, :handoff_spent})

      true ->
        prepare_handoff(from, deadline, state)
    end
  end

  def handle_event(
        :state_timeout,
        {:handoff_expired, request},
        :inert_preparing,
        %{lifecycle: %{preparation: %{request: request}}} = state
      ),
      do: stop_preparation(state)

  def handle_event(
        :info,
        {:lifecycle_handoff_ready, writer, nonce, observer, request, result},
        :inert_preparing,
        %{
          writer: writer,
          lifecycle: %{
            writer_nonce: nonce,
            observer: observer,
            preparation: %{request: request} = preparation
          }
        } = state
      ) do
    with {:ok, challenge} when is_reference(challenge) <- result,
         true <- preparation_live?(state),
         :ok <-
           Observer.connection_ready(state.lifecycle.receipt, challenge, preparation.deadline),
         true <- preparation_live?(state) do
      lifecycle = %{state.lifecycle | preparation: %{preparation | from: nil}}

      {:next_state, :inert_prepared, %{state | lifecycle: lifecycle},
       [{:reply, preparation.from, :ok}]}
    else
      false -> stop_preparation(state)
      {:error, _reason} -> stop_preparation(state)
    end
  end

  def handle_event(
        {:call, from},
        {_ref,
         {:commit_handoff, allocator, recipient, nonce, observer, tcp, grant, {:abs_ms, deadline}}},
        phase,
        %{lifecycle: %{ready: {expected_recipient, expected_nonce}}} = state
      )
      when is_pid(allocator) and node(allocator) == node() and
             is_reference(grant) and is_integer(deadline) do
    cond do
      elem(from, 0) != allocator or recipient != expected_recipient or
        nonce != expected_nonce or observer != state.lifecycle.observer ->
        reply(from, {:error, :unauthorized_handoff})

      phase != :inert_prepared ->
        reply(from, {:error, :handoff_spent})

      true ->
        commit_handoff(from, allocator, tcp, grant, deadline, state)
    end
  end

  def handle_event(
        {:call, from},
        {_ref, {:lifecycle_attach, nonce, observer, attach, {:abs_ms, requested}}},
        phase,
        %{lifecycle: %{ready: {setup, expected}, observer: original}} = state
      )
      when is_reference(attach) and is_integer(requested) do
    cond do
      elem(from, 0) != setup or nonce != expected or observer != original ->
        reply(from, {:error, :unauthorized_attach})

      phase != :inert_owned ->
        reply(from, {:error, :attach_spent})

      not state.lifecycle.public and not is_port(state.tcp) and state.send_timeout == :infinity ->
        reply(from, {:error, :private_infinite_send_timeout_not_supported})

      not state.lifecycle.public and state.options.active != false ->
        reply(from, {:error, :private_active_mode_not_supported})

      true ->
        start_private_tls(from, attach, requested, state)
    end
  end

  def handle_event(
        {:call, from},
        {_ref, {:lifecycle_adopt, nonce, observer, tcp, deadline}},
        :inert_prepared,
        %{lifecycle: %{public: true, ready: {setup, nonce}, observer: observer}} = state
      ) do
    if elem(from, 0) == setup and is_port(tcp) and
         Port.info(tcp, :connected) == {:connected, self()} and
         Options.remaining(deadline) > 0 do
      case Observer.commit_upgrade(state.lifecycle.receipt, tcp, {:abs_ms, deadline}) do
        :ok -> {:next_state, :inert_owned, %{state | tcp: tcp}, [{:reply, from, :ok}]}
        error -> reply(from, error)
      end
    else
      reply(from, {:error, :unauthorized_attach})
    end
  end

  def handle_event(
        {:call, from},
        {_ref, {:lifecycle_activate, nonce, observer}},
        :connected,
        %{
          lifecycle: %{
            public: true,
            ready: {setup, nonce},
            observer: observer,
            tls: %{outcome_pending: false}
          }
        } = state
      ) do
    if elem(from, 0) == setup do
      state = %{
        state
        | lifecycle: %{state.lifecycle | activated: true},
          active_terminal: state.active == :once
      }

      continue(:connected, deliver(state, true), [{:reply, from, :ok}])
    else
      reply(from, {:error, :unauthorized_attach})
    end
  end

  def handle_event(
        {:call, from},
        {:lifecycle_owner_transfer, observer, attempt, epoch, nonce, owner, deadline},
        :connected,
        %{
          lifecycle: %{
            public: true,
            activated: true,
            observer: observer,
            attempt: attempt,
            epoch: epoch
          }
        } = state
      ) do
    receipt = state.lifecycle.receipt

    cond do
      elem(from, 0) != observer or not is_reference(attempt) or not is_reference(nonce) ->
        reply(from, {:error, :unauthorized_transfer})

      Options.remaining(deadline) == 0 ->
        reply(from, {:error, :deadline_exceeded})

      state.closed ->
        reply(from, {:error, :closed})

      Enum.any?([state.write, state.recv, state.output, state.pending_control], &(&1 != nil)) ->
        reply(from, {:error, :busy})

      not is_pid(owner) or node(owner) != node() or not Process.alive?(owner) ->
        reply(from, {:error, :noproc})

      Receipt.observer(receipt) != observer ->
        reply(from, {:error, :unauthorized_transfer})

      true ->
        monitor = Process.monitor(owner)
        accepted_at = System.monotonic_time(:millisecond)

        if accepted_at < deadline do
          Process.demonitor(state.owner_monitor, [:flush])

          next = %{
            state
            | owner: owner,
              owner_monitor: monitor,
              lifecycle: %{state.lifecycle | epoch: epoch + 1}
          }

          {:keep_state, next, [{:reply, from, {:ok, nonce, owner, accepted_at}}]}
        else
          Process.demonitor(monitor, [:flush])
          reply(from, {:error, :deadline_exceeded})
        end
    end
  end

  # Private readiness alone cannot authorize transport attachment. A future driver
  # must authenticate the exact TCP identity/ownership ACK before enabling TLS.
  def handle_event({:call, from}, {_ref, {:attach, _tcp}}, _phase, %{lifecycle: lifecycle})
      when not is_nil(lifecycle),
      do: reply(from, {:error, :lifecycle_attach_not_implemented})

  # This internal envelope exercises the adopted raw transport without enabling
  # ordinary SSL facade calls or relaxing application-owner authority.
  def handle_event(
        {:call, from},
        {ref, {:lifecycle_io, request}},
        :connected,
        %{lifecycle: %{tls: %{outcome_pending: false}}} = state
      ) do
    if elem(from, 0) == state.owner and not is_port(state.tcp) and
         private_request?(request),
       do: socket_call({:call, from}, {ref, request}, :connected, state),
       else: reply(from, {:error, :unauthorized_private_io})
  end

  def handle_event(
        {:call, from},
        {ref, request},
        phase,
        %{lifecycle: %{public: true, activated: true}} = state
      ) do
    if destructive?(request) and elem(from, 0) != state.owner,
      do: reply(from, {:error, :not_owner}),
      else: socket_call({:call, from}, {ref, request}, phase, state)
  end

  def handle_event({:call, from}, {_ref, _request}, _phase, %{lifecycle: lifecycle})
      when not is_nil(lifecycle),
      do: reply(from, {:error, :closed})

  def handle_event({:call, from}, request, phase, state),
    do: socket_call({:call, from}, request, phase, state)

  def handle_event(
        :info,
        {:"$socket", tcp, :select, handle},
        phase,
        %{tcp: tcp, native_read: {:select_info, _operation, handle}} = state
      ) do
    native_input(phase, NativeSocket.receive_nowait(tcp), %{
      state
      | armed: false,
        native_read: nil
    })
  end

  def handle_event(
        :info,
        {:"$socket", tcp, :abort, {handle, reason}},
        phase,
        %{tcp: tcp, native_read: {:select_info, _operation, handle}} = state
      ),
      do: native_input(phase, {:error, reason}, %{state | armed: false, native_read: nil})

  def handle_event(:internal, {:native_input, result}, phase, state),
    do: native_input(phase, result, state)

  def handle_event(:info, {:tcp, tcp, bytes}, phase, %{tcp: tcp} = state) do
    case enqueue_input(%{state | armed: false}, {:data, bytes}) do
      {:ok, state} -> drain_or_continue(phase, state)
      {:error, reason, failed_state} -> fail(failed_state, reason)
    end
  end

  def handle_event(:info, {:tcp_closed, tcp}, phase, %{tcp: tcp} = state) do
    state = enqueue_terminal(%{state | armed: false}, :closed)
    drain_or_continue(phase, state)
  end

  def handle_event(:info, {:tcp_error, tcp, reason}, phase, %{tcp: tcp} = state) do
    state = enqueue_terminal(%{state | armed: false}, {:error, reason})
    drain_or_continue(phase, state)
  end

  def handle_event(:internal, :drain_input, phase, state) do
    drain_input(phase, state)
  end

  def handle_event(:info, :handshake_timeout, phase, state) when phase != :connected,
    do: fail(state, :timeout)

  def handle_event(:info, {:recv_timeout, token}, :connected, %{recv: %{token: token}} = state) do
    state = finish_recv(state, {:error, :timeout})
    drain_or_continue(:connected, state)
  end

  def handle_event(
        :internal,
        :write_next,
        :connected,
        %{output: nil, write: %{cursor: cursor} = write} = state
      )
      when not is_nil(cursor) do
    cond do
      not Process.alive?(write.owner) ->
        fail(state, :closed)

      Options.remaining(write.deadline) == 0 ->
        fail(state, :timeout)

      true ->
        case IodataCursor.next(cursor, 16_384) do
          :done ->
            finish_write(state, :ok)

          {:ok, chunk, cursor} ->
            with {:ok, record, machine} <-
                   HandshakeMachine.encrypt(state.machine, :application_data, chunk),
                 {:ok, state} <-
                   start_output(
                     %{state | machine: machine, write: %{write | cursor: cursor}},
                     record,
                     :application,
                     :application,
                     write.deadline
                   ) do
              {:keep_state, %{state | write: %{state.write | waiting: state.output.token}}}
            else
              {:error, reason} -> fail(state, public_error(reason))
            end
        end
    end
  end

  def handle_event(:internal, :write_next, _phase, _state), do: :keep_state_and_data

  def handle_event(
        :info,
        {:writer_result, writer, token, :ok},
        phase,
        %{writer: writer, output: %{token: token} = output} = state
      ) do
    _ = cancel_timer(output.timer)
    complete_output(phase, output, %{state | output: nil})
  end

  def handle_event(
        :info,
        {:writer_result, writer, token, {:error, reason}},
        phase,
        %{writer: writer, output: %{token: token} = output} = state
      ),
      do: output_failed(phase, output, state, reason)

  def handle_event(
        :info,
        {:output_timeout, token},
        phase,
        %{output: %{token: token} = output} = state
      ),
      do: output_failed(phase, output, state, :timeout)

  def handle_event(
        :info,
        {:output_timeout, token},
        phase,
        %{pending_control: %{token: token} = output} = state
      ),
      do: output_failed(phase, output, state, :timeout)

  def handle_event(:info, {:write_timeout, token}, _phase, %{write: %{token: token}} = state),
    do: fail(state, :timeout)

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _pid, _reason},
        phase,
        %{owner_monitor: monitor} = state
      ) do
    Socket.mark_terminal(state.socket, true)
    notify_pending(state, {:error, :closed})

    if phase == :connected do
      case begin_shutdown(state, :owner, []) do
        {:ok, state} -> {:next_state, :closing, state}
        {:abort, state} -> {:stop, :normal, close_transport(state)}
      end
    else
      {:stop, :normal, close_transport(state)}
    end
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, pid, _reason},
        phase,
        %{
          writer_monitor: monitor,
          writer: pid,
          closed: true
        } = state
      ) do
    _ = if state.output, do: cancel_timer(state.output.timer)

    finish_shutdown(phase, :peer, %{
      state
      | writer: nil,
        writer_monitor: nil,
        output: nil
    })
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, pid, _reason},
        _phase,
        %{writer_monitor: monitor, writer: pid} = state
      ),
      do: fail(%{state | writer: nil, writer_monitor: nil}, :econnreset)

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _pid, _reason},
        phase,
        %{recv: %{monitor: monitor}} = state
      ) do
    _ = cancel_timer(state.recv.timer)
    drain_or_continue(phase, %{state | recv: nil})
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _pid, _reason},
        _phase,
        %{write: %{monitor: monitor, from: from}} = state
      ) do
    if from == nil do
      _ = cancel_timer(state.write.timer)
      {:keep_state, %{state | write: nil}}
    else
      fail(state, :closed)
    end
  end

  def handle_event(:info, _message, _phase, _state), do: :keep_state_and_data

  defp socket_call({:call, from}, {_ref, {:attach, tcp}}, :handoff, state),
    do: start_tls(from, tcp, state)

  defp socket_call({:call, from}, {_ref, :close}, _phase, state) do
    if match?(%{kind: :local}, state.closing) do
      closing = %{state.closing | waiters: [from | state.closing.waiters]}
      {:keep_state, %{state | closing: closing}}
    else
      Socket.mark_terminal(state.socket, true)
      notify_pending(state, {:error, :closed})

      case begin_shutdown(state, :local, [from]) do
        {:ok, state} ->
          {:next_state, :closing, state}

        {:abort, state} ->
          {:stop_and_reply, :normal, [{:reply, from, :ok}], close_transport(state)}
      end
    end
  end

  defp socket_call(
         {:call, from},
         {_ref, {:controlling_process, new_owner}},
         _phase,
         state
       ) do
    caller = elem(from, 0)

    cond do
      caller != state.owner ->
        reply(from, {:error, :not_owner})

      new_owner == state.owner ->
        reply(from, :ok)

      not Process.alive?(new_owner) ->
        reply(from, {:error, :noproc})

      state.lifecycle != nil and state.lifecycle.public and
          Observer.owner_change(
            state.lifecycle.receipt,
            state.owner,
            new_owner,
            {:abs_ms, System.monotonic_time(:millisecond) + 1_000}
          ) != :ok ->
        reply(from, {:error, :owner_change_not_permitted})

      true ->
        monitor = Process.monitor(new_owner)

        if Process.alive?(new_owner) do
          Process.demonitor(state.owner_monitor, [:flush])

          {:keep_state, %{state | owner: new_owner, owner_monitor: monitor},
           [{:reply, from, :ok}]}
        else
          Process.demonitor(monitor, [:flush])
          reply(from, {:error, :noproc})
        end
    end
  end

  defp socket_call({:call, from}, {_ref, {:setopts, options}}, :connected, state) do
    if options[:active] == :once and state.recv != nil do
      reply(from, {:error, :einval})
    else
      case apply_tcp_options(state.tcp, TCPOptions.mutable(options)) do
        :ok ->
          state =
            state
            |> apply_send_options(options)
            |> apply_active_option(options)
            |> deliver(true)

          continue(:connected, state, [{:reply, from, :ok}])

        {:error, reason} ->
          reply(from, {:error, reason})
      end
    end
  end

  defp socket_call({:call, from}, {_ref, :negotiated_protocol}, :connected, state) do
    result =
      case state.negotiated_protocol do
        protocol when is_binary(protocol) -> {:ok, protocol}
        nil -> {:error, :protocol_not_negotiated}
      end

    reply(from, result)
  end

  defp socket_call({:call, from}, {_ref, request}, :connected, %{closed: false, tcp: tcp} = state)
       when request in [:peercert, :peername, :sockname] and not is_nil(tcp) do
    result =
      case request do
        :peercert ->
          Diagnostics.peercert(state.machine)

        :peername ->
          diagnostic_result(
            if(is_port(tcp), do: :inet.peername(tcp), else: NativeSocket.peername(tcp))
          )

        :sockname ->
          diagnostic_result(
            if(is_port(tcp), do: :inet.sockname(tcp), else: NativeSocket.sockname(tcp))
          )
      end

    reply(from, result)
  end

  defp socket_call(
         {:call, from},
         {_ref, {:connection_information, keys}},
         :connected,
         %{closed: false, tcp: tcp} = state
       )
       when not is_nil(tcp) do
    reply(from, Diagnostics.connection_information(state.machine, keys))
  end

  defp socket_call({:call, from}, {_ref, request}, _phase, _state)
       when request in [:peercert, :peername, :sockname] do
    reply(from, {:error, :closed})
  end

  defp socket_call({:call, from}, {_ref, {:connection_information, _keys}}, _phase, _state),
    do: reply(from, {:error, :closed})

  defp socket_call({:call, from}, {_ref, {:recv, length, deadline}}, :connected, state) do
    cond do
      length > @max_plaintext ->
        reply(from, {:error, :emsgsize})

      state.active != false ->
        reply(from, {:error, :einval})

      state.recv != nil ->
        reply(from, {:error, :einval})

      true ->
        token = make_ref()

        receiver = %{
          from: from,
          length: length,
          deadline: deadline,
          token: token,
          monitor: Process.monitor(elem(from, 0)),
          timer: timer(deadline, {:recv_timeout, token})
        }

        continue(:connected, deliver(%{state | recv: receiver}, true))
    end
  end

  defp socket_call({:call, from}, {_ref, :enable_duplex_reads}, :connected, state) do
    cond do
      elem(from, 0) != state.owner ->
        reply(from, {:error, :not_owner})

      state.closed or state.write_abandoned? ->
        reply(from, {:error, :closed})

      state.send_timeout == :infinity or match?(%{deadline: :infinity}, state.write) or
          match?(%{timer: nil}, state.output) ->
        reply(from, {:error, :infinite_send_timeout})

      true ->
        drain_or_continue(:connected, %{state | duplex_reads?: true}, [{:reply, from, :ok}])
    end
  end

  defp socket_call({:call, from}, {_ref, :abandon_send}, :connected, state) do
    cond do
      elem(from, 0) != state.owner ->
        reply(from, {:error, :not_owner})

      state.output != nil and state.output.timer == nil ->
        reply(from, {:error, :infinite_send_timeout})

      true ->
        # Drop the plaintext cursor and caller monitor. Retain only the immutable
        # protected application job (possibly a KeyUpdate plus one record),
        # its original timer, and bytes already handed to the TCP driver.
        state = settle_write(state, {:error, :write_abandoned})

        case native_abort_policy(state) do
          :ok ->
            drain_or_continue(:connected, %{state | write_abandoned?: true}, [{:reply, from, :ok}])

          {:error, reason} ->
            fail(state, reason)
        end
    end
  end

  defp socket_call({:call, from}, {_ref, :reserve_write}, :connected, state) do
    reserve_write(from, :infinity, state)
  end

  defp socket_call({:call, from}, {_ref, {:reserve_write, deadline}}, :connected, state)
       when is_integer(deadline) do
    reserve_write(from, deadline, state)
  end

  defp socket_call(
         {:call, from},
         {_ref, {:send, token, cursor, size}},
         :connected,
         %{write: %{token: token, owner: owner, from: nil} = write} = state
       )
       when elem(from, 0) == owner do
    if Options.remaining(write.deadline) == 0 do
      fail(%{state | write: %{write | from: from}}, :timeout)
    else
      case send_options(state.tcp, Options.remaining(write.deadline)) do
        :ok ->
          state = %{state | write: %{write | from: from, cursor: cursor, size: size}}
          drain_or_continue(:connected, state)

        {:error, reason} ->
          fail(%{state | write: %{write | from: from}}, reason)
      end
    end
  end

  defp socket_call({:call, from}, {_ref, _}, _phase, _state), do: reply(from, {:error, :closed})

  defp reserve_write(from, requested_deadline, state) do
    {:ok, configured_deadline} = Options.deadline(state.send_timeout)
    deadline = earlier(requested_deadline, configured_deadline)

    cond do
      state.closed or state.write_abandoned? ->
        reply(from, {:error, :closed})

      state.duplex_reads? and deadline == :infinity ->
        reply(from, {:error, :infinite_send_timeout})

      requested_deadline != :infinity and Options.remaining(deadline) == 0 ->
        reply(from, {:error, :timeout})

      state.write != nil ->
        reply(from, {:error, :busy})

      true ->
        token = make_ref()

        write = %{
          token: token,
          owner: elem(from, 0),
          monitor: Process.monitor(elem(from, 0)),
          from: nil,
          cursor: nil,
          size: nil,
          waiting: nil,
          deadline: deadline,
          timer: timer(deadline, {:write_timeout, token})
        }

        {:keep_state, %{state | write: write}, [{:reply, from, {:ok, token}}]}
    end
  end

  defp destructive?(request) when request in [:close, :enable_duplex_reads, :abandon_send],
    do: true

  defp destructive?({:controlling_process, _}), do: true
  defp destructive?({:setopts, _}), do: true
  defp destructive?(_), do: false

  defp private_request?(:close), do: true
  defp private_request?(:reserve_write), do: true
  defp private_request?({:reserve_write, deadline}), do: is_integer(deadline)
  defp private_request?(:abandon_send), do: true
  defp private_request?(:enable_duplex_reads), do: true

  defp private_request?({:recv, length, deadline}),
    do: is_integer(length) and length >= 0 and is_integer(deadline)

  defp private_request?({:send, token, _cursor, size}),
    do: is_reference(token) and is_integer(size) and size >= 0

  defp private_request?(_), do: false

  defp consume_tcp(phase, bytes, state) do
    with {:ok, records, framer} <- RecordFramer.feed(state.records, bytes),
         {:ok, phase, state} <- process_records(phase, records, %{state | records: framer}) do
      {:ok, phase, deliver(state)}
    else
      {:paused, _, _} = paused -> paused
      {:error, reason, failed_state} -> {:error, public_error(reason), failed_state}
      {:error, reason} -> {:error, public_error(reason), state}
    end
  end

  defp enqueue_input(%{input_terminal: true} = state, _event),
    do: {:error, :econnreset, state}

  defp enqueue_input(state, {:data, bytes})
       when state.input_size + byte_size(bytes) <= @max_pending_input do
    {:ok,
     %{
       state
       | input: :queue.in({:data, bytes}, state.input),
         input_size: state.input_size + byte_size(bytes)
     }}
  end

  defp enqueue_input(state, {:data, _bytes}), do: {:error, :enobufs, state}

  defp enqueue_terminal(%{input_terminal: true} = state, _terminal), do: state

  defp enqueue_terminal(state, terminal) do
    %{
      state
      | input: :queue.in({:terminal, terminal}, state.input),
        input_terminal: true
    }
  end

  defp drain_or_continue(phase, state, actions \\ []) do
    cond do
      state.output == nil and state.pending_control != nil ->
        dispatch_pending_control(phase, state, actions)

      output_barrier?(state) ->
        {:next_state, phase, state, actions}

      not :queue.is_empty(state.input) ->
        {:next_state, phase, state, [{:next_event, :internal, :drain_input} | actions]}

      phase == :connected and not state.closed and ready_for_write?(state) ->
        continue(phase, state, [{:next_event, :internal, :write_next} | actions])

      true ->
        continue(phase, state, actions)
    end
  end

  defp output_barrier?(%{pending_control: pending}) when not is_nil(pending), do: true
  defp output_barrier?(%{output: nil}), do: false
  defp output_barrier?(%{output: %{kind: :application}, write_abandoned?: true}), do: false
  defp output_barrier?(%{output: %{kind: :application}, duplex_reads?: true}), do: false
  defp output_barrier?(_state), do: true

  defp ready_for_write?(%{write: %{cursor: cursor, waiting: nil}}) when not is_nil(cursor),
    do: true

  defp ready_for_write?(_state), do: false

  defp drain_input(phase, %{pending_control: pending} = state) when not is_nil(pending),
    do: {:next_state, phase, state}

  defp drain_input(
         phase,
         %{output: output, write_abandoned?: abandoned?, duplex_reads?: duplex?} = state
       )
       when not is_nil(output) and
              ((not abandoned? and not duplex?) or output.kind != :application),
       do: {:next_state, phase, state}

  defp drain_input(phase, state) do
    case :queue.out(state.input) do
      {:empty, _input} ->
        drain_or_continue(phase, state)

      {{:value, {:data, bytes}}, input} ->
        state = %{state | input: input, input_size: state.input_size - byte_size(bytes)}

        case consume_tcp(phase, bytes, state) do
          {:ok, phase, state} -> drain_or_continue(phase, state)
          {:paused, phase, state} -> {:next_state, phase, state}
          {:error, reason, failed_state} -> fail(failed_state, reason)
        end

      {{:value, {:terminal, terminal}}, input} ->
        state = %{state | input: input, input_terminal: false}

        if state.closed do
          drain_or_continue(phase, state)
        else
          reason = if terminal == :closed, do: :econnreset, else: elem(terminal, 1)
          fail(state, reason)
        end
    end
  end

  @impl true
  def terminate(_reason, _phase, state) do
    Socket.mark_terminal(state.socket, false)
    _ = cancel_timer(state.handshake_timer)

    if state.recv do
      _ = cancel_timer(state.recv.timer)
      if state.recv.monitor, do: Process.demonitor(state.recv.monitor, [:flush])
    end

    if state.write && state.write.monitor, do: Process.demonitor(state.write.monitor, [:flush])
    _ = if state.write, do: cancel_timer(state.write.timer)
    if state.writer, do: Process.exit(state.writer, :kill)
    if state.writer_monitor, do: Process.demonitor(state.writer_monitor, [:flush])
    if state.owner_monitor, do: Process.demonitor(state.owner_monitor, [:flush])
    if state.lifecycle, do: Process.demonitor(state.lifecycle.observer_monitor, [:flush])
    _ = close_transport(state)
    :ok
  end

  @impl true
  def format_status(status) do
    Map.merge(status, %{data: :redacted, reason: :redacted, log: [], queue: [], postponed: []})
  end

  defp process_records(phase, [], state), do: {:ok, phase, state}

  defp process_records(phase, [record | rest], state) do
    {result, accepted_hello?} = HandshakeMachine.feed_with_progress(state.machine, record)
    state = record_setup_progress(state, accepted_hello?)

    case result do
      {:ok, machine, outbound, events} ->
        state = %{state | machine: machine}

        if outbound == [] do
          with {:ok, phase, state} <- apply_events(phase, events, state) do
            continue_records(phase, rest, state)
          end
        else
          deadline = if phase == :handshaking, do: state.deadline, else: :infinity

          case start_output(
                 state,
                 outbound,
                 output_kind(phase, machine),
                 {:protocol, events, rest},
                 deadline
               ) do
            {:ok, state} ->
              {:paused, phase, state}

            {:error, reason} ->
              {:error, reason, state}
          end
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp continue_records(phase, rest, state) do
    if state.closed and rest != [],
      do: {:error, :closed, state},
      else: process_records(phase, rest, state)
  end

  defp prepare_resumption(%{session_tickets: :disabled} = options, _tcp),
    do: SSL.ResumptionContext.prepare(options, nil)

  defp prepare_resumption(options, tcp) do
    result = if is_port(tcp), do: :inet.peername(tcp), else: NativeSocket.peername(tcp)

    with {:ok, endpoint} <- result,
         do: SSL.ResumptionContext.prepare(options, endpoint)
  end

  defp apply_events(phase, [], state), do: {:ok, phase, state}

  defp apply_events(phase, [{:session_ticket, material} | rest], state) do
    :ok = SSL.ResumptionContext.store(state.ticket_key, material, state.owner)
    apply_events(phase, rest, state)
  end

  defp apply_events(_phase, [{:connected, negotiated_protocol} | rest], state) do
    if Options.remaining(state.deadline) == 0 do
      {:error, :timeout, state}
    else
      case SSL.PolicyIO.finish(state.policy_context) do
        :ok ->
          state = notify_connected(%{state | policy_context: nil})
          _ = cancel_timer(state.handshake_timer)

          apply_events(:connected, rest, %{
            state
            | connect_from: nil,
              handshake_timer: nil,
              negotiated_protocol: negotiated_protocol
          })

        {:error, _} ->
          {:error, :policy_io_unconfirmed, state}
      end
    end
  end

  defp apply_events(phase, [{:application_data, bytes} | rest], state) do
    case buffer_application_data(deliver(state), bytes) do
      {:ok, state} -> apply_events(phase, rest, state)
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp apply_events(phase, [:closed | rest], state) do
    Socket.mark_terminal(state.socket, true)

    if rest == [] do
      state = %{state | closed: true, armed: false} |> settle_write({:error, :closed})

      case begin_shutdown(state, :peer, []) do
        {:ok, state} -> {:paused, phase, state}
        {:abort, state} -> {:ok, phase, close_transport(state)}
      end
    else
      {:error, :closed, state}
    end
  end

  defp deliver(state, immediate \\ false) do
    state
    |> deliver_recv(immediate)
    |> deliver_active()
  end

  defp deliver_recv(%{recv: nil} = state, _immediate), do: state

  defp deliver_recv(%{recv: receiver} = state, immediate) do
    cond do
      not Process.alive?(elem(receiver.from, 0)) ->
        _ = cancel_timer(receiver.timer)
        Process.demonitor(receiver.monitor, [:flush])
        %{state | recv: nil}

      not immediate and Options.remaining(receiver.deadline) == 0 ->
        finish_recv(state, {:error, :timeout})

      receiver.length == 0 and state.size > 0 ->
        deliver_bytes(state, state.size)

      receiver.length > 0 and state.size >= receiver.length ->
        deliver_bytes(state, receiver.length)

      state.closed and (state.output != nil or state.pending_control != nil) ->
        state

      state.closed ->
        finish_recv(state, {:error, :closed})

      Options.remaining(receiver.deadline) == 0 ->
        finish_recv(state, {:error, :timeout})

      true ->
        state
    end
  end

  defp deliver_active(%{recv: nil, active: :once, size: size} = state) when size > 0 do
    {bytes, buffer} = take(state.buffer, size, [])
    send(state.owner, {:ssl, state.socket, bytes})

    %{
      state
      | active: false,
        active_terminal: true,
        buffer: buffer,
        size: 0
    }
  end

  defp deliver_active(state), do: state

  defp buffer_application_data(state, bytes)
       when state.size + byte_size(bytes) <= @max_plaintext do
    {:ok, deliver(enqueue_application_data(state, bytes))}
  end

  defp buffer_application_data(%{recv: %{length: length}} = state, bytes)
       when length > state.size do
    needed = length - state.size
    <<requested::binary-size(^needed), surplus::binary>> = bytes

    state
    |> enqueue_application_data(requested)
    |> deliver()
    |> buffer_application_data(surplus)
  end

  defp buffer_application_data(state, _bytes), do: {:error, :enobufs, state}

  defp enqueue_application_data(state, <<>>), do: state

  defp enqueue_application_data(state, bytes) do
    %{
      state
      | buffer: :queue.in(bytes, state.buffer),
        size: state.size + byte_size(bytes)
    }
  end

  defp deliver_bytes(state, length) do
    {bytes, buffer} = take(state.buffer, length, [])
    finish_recv(%{state | buffer: buffer, size: state.size - length}, {:ok, bytes})
  end

  defp take(buffer, 0, acc), do: {IO.iodata_to_binary(Enum.reverse(acc)), buffer}

  defp take(buffer, length, acc) do
    {{:value, chunk}, buffer} = :queue.out(buffer)

    if byte_size(chunk) <= length do
      take(buffer, length - byte_size(chunk), [chunk | acc])
    else
      <<head::binary-size(^length), tail::binary>> = chunk
      {IO.iodata_to_binary(Enum.reverse([head | acc])), :queue.in_r(tail, buffer)}
    end
  end

  defp finish_recv(state, result) do
    :gen_statem.reply(state.recv.from, result)
    _ = cancel_timer(state.recv.timer)
    Process.demonitor(state.recv.monitor, [:flush])
    %{state | recv: nil}
  end

  defp continue(phase, state, actions \\ [])

  # Delivery may exhaust the buffer before reciprocal close_notify completes.
  # Keep its deadline serviceable instead of entering termination mid-output.
  defp continue(phase, %{closed: true, size: 0, output: output} = state, actions)
       when not is_nil(output),
       do: {:next_state, phase, state, actions}

  defp continue(_phase, %{closed: true, size: 0} = state, actions) do
    notify_pending(state, {:error, :closed})
    state = notify_active_terminal(state, :closed)

    if actions == [] do
      {:stop, :normal, state}
    else
      {:stop_and_reply, :normal, actions, state}
    end
  end

  defp continue(phase, state, actions) do
    can_read = state.size < @max_plaintext - @rearm_reserve or state.recv != nil
    input_idle = not output_barrier?(state) and :queue.is_empty(state.input)

    if state.tcp && not state.armed && not state.closed && can_read && input_idle do
      arm_input(phase, state, actions)
    else
      {:next_state, phase, state, actions}
    end
  end

  defp arm_input(phase, %{tcp: tcp} = state, actions) when is_port(tcp) do
    case :inet.setopts(tcp, active: :once) do
      :ok -> {:next_state, phase, %{state | armed: true}, actions}
      {:error, reason} -> fail(state, reason)
    end
  end

  defp arm_input(phase, state, actions) do
    case NativeSocket.receive_nowait(state.tcp) do
      {:select, {:select_info, _operation, _handle} = info} ->
        # Publish the exact read identity before a queued write continuation can
        # reenter continue/3. Ready bytes precede that continuation as well.
        {:next_state, phase, %{state | armed: true, native_read: info}, actions}

      result ->
        {:next_state, phase, state, [{:next_event, :internal, {:native_input, result}} | actions]}
    end
  end

  defp native_input(phase, {:select, {:select_info, _operation, _handle} = info}, state),
    do: {:next_state, phase, %{state | armed: true, native_read: info}}

  defp native_input(phase, {:ok, bytes}, state) do
    case enqueue_input(state, {:data, bytes}) do
      {:ok, state} -> drain_or_continue(phase, state)
      {:error, reason, state} -> fail(state, reason)
    end
  end

  defp native_input(phase, {:error, :closed}, state),
    do: drain_or_continue(phase, enqueue_terminal(state, :closed))

  defp native_input(phase, {:error, reason}, state),
    do: drain_or_continue(phase, enqueue_terminal(state, {:error, reason}))

  defp native_input(_phase, _unsupported, state), do: fail(state, :unsupported_socket_operation)

  # Public attempt failure retires the enrolled writer and transport. Keep them
  # alive until the bounded local fatal-alert output completes; fail_now records
  # the outcome on completion or output failure. The original setup deadline
  # and cancellation authority remain active throughout this shutdown.
  defp fail(
         %{lifecycle: %{public: true, tls: %{outcome_pending: true}}, output: nil} = state,
         {:tls_alert, {_, _}} = reason
       ),
       do: do_fail(record_setup_failure(state, reason), reason)

  defp fail(state, reason) do
    state = state |> record_setup_failure(reason) |> record_private_failure(reason)
    do_fail(state, reason)
  end

  defp do_fail(state, {:peer_alert, _level, description}) do
    category =
      Enum.find_value(@alert_codes, :handshake_failure, fn {name, code} ->
        if code == description, do: name
      end)

    notify_pending(state, {:error, {:tls_alert, {category, ~c"Peer terminated TLS"}}})
    state = notify_active_terminal(state, {:tls_alert, {category, ~c"Peer terminated TLS"}})
    {:stop, :normal, close_transport(state)}
  end

  defp do_fail(state, reason) do
    if match?({:tls_alert, {_alert, _description}}, reason) and state.output == nil do
      case begin_fatal_alert(state, reason) do
        {:ok, state} -> {:next_state, :closing, state}
        {:abort, state} -> fail_now(state, reason)
      end
    else
      fail_now(state, reason)
    end
  end

  defp begin_fatal_alert(%{machine: nil} = state, _reason), do: {:abort, state}

  defp begin_fatal_alert(state, {:tls_alert, {alert, _description}} = reason) do
    code = @alert_codes[alert] || 80

    case HandshakeMachine.encrypt(state.machine, :alert, <<2, code>>) do
      {:ok, record, machine} ->
        {:ok, deadline} = Options.deadline(@shutdown_timeout)

        case start_output(
               %{
                 state
                 | machine: machine,
                   closing: %{kind: :fatal, waiters: [], reason: reason}
               },
               record,
               :fatal_alert,
               {:shutdown, :fatal},
               deadline
             ) do
          {:ok, state} -> {:ok, state}
          {:error, _reason} -> {:abort, state}
        end

      _ ->
        {:abort, state}
    end
  end

  defp fail_now(state, reason), do: do_fail_now(record_private_failure(state, reason), reason)

  defp do_fail_now(state, reason) do
    notify_pending(state, {:error, reason})
    state = notify_active_terminal(state, reason)
    {:stop, :normal, close_transport(state)}
  end

  defp notify_pending(state, result) do
    if match?(%{public: true, tls: %{outcome_pending: true}}, state.lifecycle) do
      {setup, nonce} = state.lifecycle.ready

      send(
        setup,
        {:lifecycle_tls_failed, self(), nonce, state.lifecycle.observer, elem(result, 1)}
      )
    end

    if state.connect_from, do: :gen_statem.reply(state.connect_from, result)
    if state.recv, do: :gen_statem.reply(state.recv.from, result)
    if state.write && state.write.from, do: :gen_statem.reply(state.write.from, result)
  end

  defp notify_active_terminal(%{active_terminal: true, terminal_notified: false} = state, :closed) do
    send(state.owner, {:ssl_closed, state.socket})
    %{state | terminal_notified: true}
  end

  defp notify_active_terminal(
         %{active_terminal: true, terminal_notified: false} = state,
         reason
       ) do
    send(state.owner, {:ssl_error, state.socket, reason})
    %{state | terminal_notified: true}
  end

  defp notify_active_terminal(state, _reason), do: state

  defp apply_active_option(state, options) do
    case Keyword.fetch(options, :active) do
      {:ok, :once} -> %{state | active: :once, active_terminal: true}
      {:ok, false} -> %{state | active: false, active_terminal: false}
      :error -> state
    end
  end

  defp apply_send_options(state, options) do
    case Keyword.fetch(options, :send_timeout) do
      {:ok, timeout} -> %{state | send_timeout: timeout}
      :error -> state
    end
  end

  defp apply_tcp_options(_tcp, []), do: :ok
  defp apply_tcp_options(nil, _options), do: {:error, :closed}
  defp apply_tcp_options(tcp, options) when is_port(tcp), do: :inet.setopts(tcp, options)
  defp apply_tcp_options(tcp, options), do: NativeSocket.setopts(tcp, options)

  defp send_options(tcp, timeout) when is_port(tcp),
    do: :inet.setopts(tcp, send_timeout: timeout, send_timeout_close: true)

  defp send_options(_tcp, _timeout), do: :ok

  defp finish_write(state, result) do
    state = settle_write(state, result)
    drain_or_continue(:connected, state)
  end

  defp settle_write(%{write: nil} = state, _result), do: state

  defp settle_write(%{write: write} = state, result) do
    if write.from, do: :gen_statem.reply(write.from, result)
    _ = cancel_timer(write.timer)
    Process.demonitor(write.monitor, [:flush])
    %{state | write: nil}
  end

  defp start_output(
         %{output: nil, writer: writer, tcp: tcp} = state,
         bytes,
         kind,
         continuation,
         deadline
       )
       when is_pid(writer) and not is_nil(tcp) do
    size = :erlang.iolist_size(bytes)

    cond do
      size == 0 ->
        {:error, :empty_output}

      size > @max_pending_output ->
        {:error, :enobufs}

      Options.remaining(deadline) == 0 ->
        {:error, :timeout}

      true ->
        token = make_ref()
        shutdown? = kind in [:close_notify, :fatal_alert]

        with {:ok, state} <- send_output(state, token, tcp, bytes, shutdown?, deadline) do
          {:ok,
           %{
             state
             | output: %{
                 token: token,
                 kind: kind,
                 continuation: continuation,
                 size: size,
                 deadline: deadline,
                 timer: timer(deadline, {:output_timeout, token})
               }
           }}
        end
    end
  end

  defp start_output(
         %{output: %{kind: :application} = output, pending_control: nil} = state,
         bytes,
         kind,
         continuation,
         deadline
       )
       when kind in [:control, :close_notify] do
    size = :erlang.iolist_size(bytes)
    {:ok, send_deadline} = Options.deadline(state.send_timeout)
    deadline = deadline |> earlier(output.deadline) |> earlier(send_deadline)
    deadline = if state.write, do: earlier(deadline, state.write.deadline), else: deadline

    cond do
      size == 0 ->
        {:error, :empty_output}

      size > @max_pending_output ->
        {:error, :enobufs}

      deadline == :infinity or Options.remaining(deadline) == 0 ->
        {:error, :timeout}

      true ->
        token = make_ref()

        {:ok,
         %{
           state
           | pending_control: %{
               token: token,
               bytes: bytes,
               kind: kind,
               continuation: continuation,
               size: size,
               deadline: deadline,
               timer: timer(deadline, {:output_timeout, token})
             }
         }}
    end
  end

  defp start_output(_state, _bytes, _kind, _continuation, _deadline), do: {:error, :busy}

  defp dispatch_pending_control(phase, %{pending_control: output} = state, actions) do
    if Options.remaining(output.deadline) == 0 do
      output_failed(phase, output, state, :timeout)
    else
      case send_output(
             state,
             output.token,
             state.tcp,
             output.bytes,
             output.kind == :close_notify,
             output.deadline
           ) do
        {:ok, state} ->
          # Reuse the original token/timer and already-protected bytes. Queue
          # residence consumed this deadline; dispatch grants no new budget.
          {:next_state, phase,
           %{state | output: Map.delete(output, :bytes), pending_control: nil}, actions}

        {:error, reason} ->
          output_failed(phase, output, state, reason)
      end
    end
  end

  defp earlier(:infinity, deadline), do: deadline
  defp earlier(deadline, :infinity), do: deadline
  defp earlier(first, second), do: min(first, second)

  defp complete_output(phase, %{continuation: :handshake_start}, state),
    do: drain_or_continue(phase, state)

  defp complete_output(phase, %{continuation: :application}, %{write: nil} = state),
    do: drain_or_continue(phase, state)

  defp complete_output(phase, %{continuation: :application}, %{write: write} = state) do
    state = %{state | write: %{write | waiting: nil}}

    if state.write.cursor == [] and state.pending_control == nil do
      finish_write(state, :ok)
    else
      drain_or_continue(phase, state)
    end
  end

  defp complete_output(phase, %{continuation: {:protocol, events, rest}}, state) do
    with {:ok, phase, state} <- apply_events(phase, events, state),
         {:ok, phase, state} <- process_records(phase, rest, state) do
      drain_or_continue(phase, deliver(state))
    else
      {:paused, phase, state} -> {:next_state, phase, state}
      {:error, reason, failed_state} -> fail(failed_state, public_error(reason))
    end
  end

  defp complete_output(phase, %{continuation: {:shutdown, kind}}, state),
    do: finish_shutdown(phase, kind, state)

  defp output_failed(phase, output, state, reason) do
    _ = cancel_timer(output.timer)

    case {state.closing, output.continuation} do
      {%{kind: :peer}, _} -> finish_shutdown(phase, :peer, state)
      {_, {:shutdown, kind}} -> finish_shutdown(phase, kind, state)
      _ -> fail_now(state, reason)
    end
  end

  defp output_kind(:handshaking, %{phase: :connected}), do: :client_finished
  defp output_kind(:handshaking, _machine), do: :handshake
  defp output_kind(:connected, _machine), do: :control

  defp begin_shutdown(%{machine: nil} = state, _kind, _waiters), do: {:abort, state}

  defp begin_shutdown(%{write_abandoned?: true} = state, kind, _waiters) when kind != :peer,
    do: {:abort, state}

  defp begin_shutdown(%{output: output} = state, kind, _waiters)
       when not is_nil(output) and (kind != :peer or output.kind != :application),
       do: {:abort, state}

  defp begin_shutdown(state, kind, waiters) do
    case HandshakeMachine.encrypt(state.machine, :alert, <<1, 0>>) do
      {:ok, record, machine} ->
        {:ok, deadline} = Options.deadline(@shutdown_timeout)

        case start_output(
               %{state | machine: machine, closing: %{kind: kind, waiters: waiters}},
               record,
               :close_notify,
               {:shutdown, kind},
               deadline
             ) do
          {:ok, state} -> {:ok, state}
          {:error, _reason} -> {:abort, state}
        end

      {:error, _reason} ->
        {:abort, state}
    end
  end

  defp finish_shutdown(_phase, :local, state) do
    state.closing.waiters
    |> Enum.each(&:gen_statem.reply(&1, :ok))

    {:stop, :normal, close_transport(%{state | closing: nil})}
  end

  defp finish_shutdown(_phase, :owner, state),
    do: {:stop, :normal, close_transport(%{state | closing: nil})}

  defp finish_shutdown(_phase, :fatal, state),
    do: fail_now(%{state | closing: nil}, state.closing.reason)

  defp finish_shutdown(_phase, :peer, state) do
    state = close_transport(%{state | closing: nil})
    drain_or_continue(:connected, deliver(state))
  end

  # Explicit close can suppress the original native Socket monitor on supported
  # OTP versions. Retain its original controller and identity until controller
  # exit; never turn that absence of DOWN into cleanup proof. Peer close_notify
  # may leave bounded authenticated plaintext to drain. In that state reads are
  # disarmed, the TLS machine/output are discarded and writes stay closed. Cancel
  # and owner loss still terminate the same enrolled controller and writer.
  defp close_transport(%{lifecycle: lifecycle, tcp: tcp} = state)
       when not is_nil(lifecycle) and not is_nil(tcp) and not is_port(tcp) do
    if lifecycle.public, do: Observer.logical_closed(lifecycle.receipt)
    _ = if state.output, do: cancel_timer(state.output.timer)
    _ = if state.pending_control, do: cancel_timer(state.pending_control.timer)
    _ = NativeSocket.cancel_read(tcp, state.native_read)
    _ = if state.write_abandoned? or state.output != nil, do: NativeSocket.abort_on_close(tcp)
    %{state | machine: nil, armed: false, native_read: nil, output: nil, pending_control: nil}
  end

  # A managed inet port has the same independent Observer obligation as a
  # native socket. Closing it while authenticated plaintext is queued would
  # retire and kill this controller before the application can drain that data.
  # Keep the actual owned port and controller live until explicit close/cancel
  # or owner loss; neither logical closure nor this return certifies cleanup.
  defp close_transport(
         %{lifecycle: %{public: true} = lifecycle, tcp: tcp, closed: true, size: size} = state
       )
       when is_port(tcp) and size > 0 do
    Observer.logical_closed(lifecycle.receipt)
    _ = :inet.setopts(tcp, active: false)
    _ = if state.output, do: cancel_timer(state.output.timer)
    _ = if state.pending_control, do: cancel_timer(state.pending_control.timer)
    %{state | machine: nil, armed: false, output: nil, pending_control: nil}
  end

  defp close_transport(state) do
    _ = if state.output, do: cancel_timer(state.output.timer)
    _ = if state.pending_control, do: cancel_timer(state.pending_control.timer)

    # Port.close does not block the callback, but inet can retain the port
    # while flushing. Driver completion does not acknowledge an abandoned
    # logical upload. Preserve that abort intent at this terminal boundary;
    # leave ordinary, acknowledged empty-queue closes graceful.
    if is_port(state.tcp) do
      pending = :inet.getstat(state.tcp, [:send_pend])

      _ =
        if state.write_abandoned? or state.output != nil or
             match?({:ok, [{:send_pend, size}]} when size > 0, pending) do
          _ = :inet.setopts(state.tcp, linger: {true, 0})
        end

      try do
        Port.close(state.tcp)
      rescue
        ArgumentError -> :ok
      end
    end

    %{state | tcp: nil, machine: nil, armed: false, output: nil, pending_control: nil}
  end

  defp native_abort_policy(%{tcp: tcp}) when is_port(tcp), do: :ok
  defp native_abort_policy(%{tcp: tcp}), do: NativeSocket.abort_on_close(tcp)

  defp diagnostic_result({:error, _}), do: {:error, :closed}
  defp diagnostic_result(result), do: result

  defp record_setup_progress(
         %{lifecycle: %{public: true, tls: %{outcome_pending: true}}} = state,
         true
       ),
       do: put_in(state.lifecycle.tls.accepted_server_hello, true)

  defp record_setup_progress(state, _accepted), do: state

  defp record_setup_failure(
         %{
           lifecycle: %{
             public: true,
             tls: %{outcome_pending: true, accepted_server_hello: true, phase_attempted: false}
           }
         } = state,
         reason
       ) do
    if setup_phase_failure?(reason) do
      state = put_in(state.lifecycle.tls.phase_attempted, true)
      lifecycle = state.lifecycle
      control = System.monotonic_time(:millisecond) + 100
      expiry = if state.deadline == :infinity, do: control, else: min(state.deadline, control)
      deadline = {:abs_ms, expiry}

      with {:ok, nonce} <-
             Observer.prepare_setup_failure(
               lifecycle.receipt,
               lifecycle.attempt,
               lifecycle.epoch,
               deadline
             ) do
        _ =
          Observer.commit_setup_failure(
            lifecycle.receipt,
            lifecycle.attempt,
            lifecycle.epoch,
            nonce,
            deadline
          )
      end

      state
    else
      state
    end
  end

  defp record_setup_failure(state, _reason), do: state

  defp setup_phase_failure?({:tls_alert, {alert, _}}),
    do: alert not in [:close_notify, :user_canceled]

  defp setup_phase_failure?({:peer_alert, 2, description}), do: description not in [0, 90]
  defp setup_phase_failure?(_reason), do: false

  defp record_private_failure(
         %{lifecycle: %{public: true, tls: %{outcome_pending: true}}} = state,
         reason
       ) do
    category = if reason in [:timeout, :deadline_exceeded], do: :timeout, else: :tls

    _ =
      Observer.attempt_failed(
        state.lifecycle.receipt,
        category,
        reason,
        {:abs_ms, System.monotonic_time(:millisecond) + 250}
      )

    state
  end

  defp record_private_failure(
         %{lifecycle: %{tls: %{initial: false, outcome_pending: true, failure_attempted: false}}} =
           state,
         reason
       ) do
    if tls_failure?(reason) do
      record_tls_failure(put_in(state.lifecycle.tls.failure_attempted, true))
    else
      state
    end
  end

  defp record_private_failure(state, _reason), do: state

  defp tls_failure?({:tls_alert, {_, _}}), do: true
  defp tls_failure?({:peer_alert, _, _}), do: true
  defp tls_failure?(_reason), do: false

  defp record_tls_failure(state) do
    completion = System.monotonic_time(:millisecond) + 1_000

    deadline =
      if state.deadline == :infinity, do: completion, else: min(state.deadline, completion)

    _ = Observer.record_tls_failure(state.lifecycle.receipt, {:abs_ms, deadline})
    state
  catch
    _kind, _reason -> state
  end

  defp send_output(
         %{lifecycle: nil, writer: writer} = state,
         token,
         tcp,
         bytes,
         shutdown?,
         _deadline
       ) do
    send(writer, {:send, token, tcp, bytes, shutdown?})
    {:ok, state}
  end

  defp send_output(
         %{lifecycle: %{tls: %{initial: true}}} = state,
         token,
         _tcp,
         bytes,
         shutdown?,
         deadline
       ) do
    if private_tls_live?(state) do
      enqueue_lifecycle(
        put_in(state.lifecycle.tls.initial, false),
        token,
        bytes,
        shutdown?,
        deadline
      )
    else
      {:error, :timeout}
    end
  end

  defp send_output(state, token, _tcp, bytes, shutdown?, deadline),
    do: enqueue_lifecycle(state, token, bytes, shutdown?, deadline)

  defp enqueue_lifecycle(state, token, bytes, shutdown?, deadline) do
    # Later control output retains the original capability, not admission E or Setup life.
    message =
      if is_port(state.tcp) do
        {:lifecycle_send, state.lifecycle.writer_nonce, token, state.tcp, bytes, shutdown?}
      else
        {:ok, send_deadline} = Options.deadline(state.send_timeout)
        bound = if deadline == :infinity, do: send_deadline, else: min(deadline, send_deadline)

        {:lifecycle_socket_send, state.lifecycle.writer_nonce, token, state.tcp, bytes, shutdown?,
         bound}
      end

    send(state.writer, message)

    {:ok, state}
  end

  defp start_private_tls(from, attach, requested, state) do
    {setup, _nonce} = state.lifecycle.ready
    {:abs_ms, original} = state.lifecycle.control_deadline

    tls = %{
      recipient: setup,
      nonce: attach,
      deadline: min(requested, original),
      initial: true,
      outcome_pending: true,
      failure_attempted: false,
      accepted_server_hello: false,
      phase_attempted: false
    }

    state = %{state | lifecycle: Map.put(state.lifecycle, :tls, tls)}

    if private_tls_live?(state) do
      state = %{state | records: RecordFramer.new(), active_terminal: false}
      private_tls_started(start_tls(from, state.tcp, state), from, attach)
    else
      reply(from, {:error, :deadline_exceeded})
    end
  end

  defp private_tls_started({:next_state, :handshaking, state}, from, attach) do
    result =
      if private_tls_live?(state),
        do: {:ok, attach},
        else: {:error, :acceptance_unconfirmed}

    {:next_state, :handshaking, %{state | connect_from: nil}, [{:reply, from, result}]}
  end

  defp private_tls_started(failure, _from, _attach), do: failure

  defp private_tls_live?(state) do
    tls = state.lifecycle.tls

    birth_live?(state) and Process.alive?(tls.recipient) and Process.alive?(state.writer) and
      Options.remaining(tls.deadline) > 0 and
      transport_owned?(state.tcp)
  end

  defp transport_owned?(tcp) when is_port(tcp),
    do: Port.info(tcp, :connected) == {:connected, self()}

  defp transport_owned?(tcp), do: :socket.getopt(tcp, :otp, :controlling_process) == {:ok, self()}

  defp notify_connected(
         %{lifecycle: %{tls: tls, ready: {_setup, nonce}, observer: observer}} = state
       ) do
    state = put_in(state.lifecycle.tls.outcome_pending, false)

    send(
      tls.recipient,
      {:lifecycle_tls_connected, self(), nonce, observer, tls.nonce, state.socket}
    )

    state
  end

  defp notify_connected(state) do
    :gen_statem.reply(state.connect_from, {:ok, state.socket})
    state
  end

  defp start_tls(from, tcp, state) do
    state = %{state | tcp: tcp, connect_from: from}

    if Options.remaining(state.deadline) == 0 do
      fail(state, :timeout)
    else
      with :ok <- prepare_transport(tcp, state),
           {:ok, options, ticket, ticket_key} <- prepare_resumption(state.options, tcp),
           {:ok, policy_context, certificate_policy} <-
             SSL.PolicyIO.prepare(options, state.lifecycle, state.owner, state.deadline),
           {:ok, materialized} <-
             Materializer.materialize(
               options.profile,
               Options.capabilities(),
               SSL.PolicyIO.profile_context(policy_context, options.context)
             ),
           {:ok, machine, outbound} <-
             HandshakeMachine.init(
               materialized,
               options.trust_source,
               options.identity,
               verify: options.verify,
               verify_fun: options.verify_fun,
               certificate_policy: certificate_policy,
               customize_hostname_check: options.hostname_check,
               depth: options.depth,
               client_identity: options.client_identity,
               ticket: ticket,
               enable_tickets:
                 options.session_tickets in [:auto, :manual] and options.policy == nil
             ),
           {:ok, state} <-
             start_output(
               %{
                 state
                 | machine: machine,
                   options: nil,
                   ticket_key: ticket_key,
                   policy_context: policy_context
               },
               outbound,
               :handshake,
               :handshake_start,
               state.deadline
             ) do
        {:next_state, :handshaking, state}
      else
        {:error, reason} -> fail(state, public_error(reason))
      end
    end
  end

  defp prepare_transport(tcp, state) when is_port(tcp) do
    :inet.setopts(
      tcp,
      [
        :binary,
        packet: :raw,
        active: false,
        send_timeout: state.send_timeout,
        send_timeout_close: state.send_timeout_close
      ] ++
        TCPOptions.mutable(state.options.tcp_options)
    )
  end

  defp prepare_transport(tcp, state), do: NativeSocket.prepare(tcp, state.options)

  defp commit_handoff(from, allocator, tcp, grant, requested, state) do
    {:abs_ms, original} = state.lifecycle.preparation.deadline
    deadline = min(requested, original)

    with true <- native_handoff_live?(state, allocator, tcp, deadline),
         :ok <-
           Observer.commit_handoff(
             state.lifecycle.receipt,
             tcp,
             allocator,
             grant,
             {:abs_ms, deadline}
           ),
         true <- native_handoff_live?(state, allocator, tcp, deadline) do
      {:next_state, :inert_owned, %{state | tcp: tcp}, [{:reply, from, :ok}]}
    else
      _ -> {:stop_and_reply, :normal, [{:reply, from, {:error, :acceptance_unconfirmed}}], state}
    end
  end

  defp native_handoff_live?(state, allocator, tcp, deadline) when is_port(tcp),
    do:
      preparation_live?(state) and Process.alive?(allocator) and
        Options.remaining(deadline) > 0 and Port.info(tcp, :connected) == {:connected, self()}

  defp native_handoff_live?(state, allocator, tcp, deadline) do
    handoff_participants_live?(state, allocator, deadline) and handoff_owned?(tcp) and
      handoff_participants_live?(state, allocator, deadline)
  end

  defp handoff_participants_live?(state, allocator, deadline),
    do:
      preparation_live?(state) and Process.alive?(allocator) and
        Options.remaining(deadline) > 0

  defp handoff_owned?(tcp) do
    :socket.getopt(tcp, :otp, :controlling_process) == {:ok, self()}
  catch
    _kind, _reason -> false
  end

  defp prepare_handoff(from, requested, state) do
    deadline = if state.deadline == :infinity, do: requested, else: min(requested, state.deadline)
    preparation = %{from: from, request: make_ref(), deadline: {:abs_ms, deadline}}
    lifecycle = Map.put(state.lifecycle, :preparation, preparation)
    state = %{state | lifecycle: lifecycle}

    if preparation_live?(state) do
      send(
        state.writer,
        {:lifecycle_prepare, self(), lifecycle.writer_nonce, lifecycle.observer,
         preparation.request, preparation.deadline}
      )

      {:next_state, :inert_preparing, state,
       [{:state_timeout, Options.remaining(deadline), {:handoff_expired, preparation.request}}]}
    else
      stop_preparation(state)
    end
  end

  defp preparation_live?(state) do
    {:abs_ms, deadline} = state.lifecycle.preparation.deadline
    {recipient, _nonce} = state.lifecycle.ready

    birth_live?(state) and Process.alive?(recipient) and Process.alive?(state.writer) and
      Options.remaining(deadline) > 0
  end

  defp stop_preparation(state),
    do:
      {:stop_and_reply, :normal,
       [{:reply, state.lifecycle.preparation.from, {:error, :acceptance_unconfirmed}}], state}

  defp birth_live?(state),
    do: Process.alive?(state.lifecycle.observer) and Process.alive?(state.owner)

  defp birth_remaining(state) do
    {:abs_ms, control} = state.lifecycle.control_deadline
    Options.remaining(control)
  end

  defp public_error({:fatal_alert, alert, _}), do: {:tls_alert, {alert, ~c"TLS protocol error"}}
  defp public_error({:peer_alert, _, _} = alert), do: alert

  defp public_error({:record_length_exceeded, _, _}),
    do: {:tls_alert, {:record_overflow, ~c"Record limit exceeded"}}

  defp public_error(reason) when is_atom(reason), do: reason
  defp public_error(_), do: {:tls_alert, {:internal_error, ~c"TLS connection failed"}}
  defp reply(from, result), do: {:keep_state_and_data, [{:reply, from, result}]}
  defp timer(:infinity, _message), do: nil

  defp timer(deadline, message),
    do: Process.send_after(self(), message, Options.remaining(deadline))

  defp cancel_timer(nil), do: :ok
  defp cancel_timer(timer), do: Process.cancel_timer(timer, async: false, info: false)
end
