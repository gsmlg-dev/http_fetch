defmodule SSL.Connection do
  @moduledoc false
  @behaviour :gen_statem
  alias SSL.{ConnectionWriter, Diagnostics, IodataCursor, Options, Socket, TCPOptions}
  alias SSL.ClientHello.Materializer
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
      :handshake_timer,
      :active,
      :send_timeout,
      :send_timeout_close,
      :negotiated_protocol,
      :output,
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

  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
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
  def handle_event({:call, from}, {ref, _request}, _phase, %{socket: %{ref: actual}})
      when ref != actual,
      do: {:keep_state_and_data, [{:reply, from, {:error, :badarg}}]}

  def handle_event({:call, from}, {_ref, {:attach, tcp}}, :handoff, state) do
    state = %{state | tcp: tcp, connect_from: from}

    if Options.remaining(state.deadline) == 0 do
      fail(state, :timeout)
    else
      with :ok <-
             :inet.setopts(
               tcp,
               [
                 :binary,
                 packet: :raw,
                 active: false,
                 send_timeout: state.send_timeout,
                 send_timeout_close: state.send_timeout_close,
                 buffer: 16_640
               ] ++ TCPOptions.mutable(state.options.tcp_options)
             ),
           {:ok, options, ticket, ticket_key} <- prepare_resumption(state.options, tcp),
           {:ok, materialized} <-
             Materializer.materialize(
               options.profile,
               Options.capabilities(),
               options.context
             ),
           {:ok, machine, outbound} <-
             HandshakeMachine.init(
               materialized,
               options.trust_source,
               options.identity,
               customize_hostname_check: options.hostname_check,
               depth: options.depth,
               client_identity: options.client_identity,
               ticket: ticket,
               enable_tickets: options.session_tickets == :auto
             ),
           {:ok, state} <-
             start_output(
               %{state | machine: machine, options: nil, ticket_key: ticket_key},
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

  def handle_event({:call, from}, {_ref, :close}, _phase, state) do
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

  def handle_event(
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

  def handle_event({:call, from}, {_ref, {:setopts, options}}, :connected, state) do
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

  def handle_event({:call, from}, {_ref, :negotiated_protocol}, :connected, state) do
    result =
      case state.negotiated_protocol do
        protocol when is_binary(protocol) -> {:ok, protocol}
        nil -> {:error, :protocol_not_negotiated}
      end

    reply(from, result)
  end

  def handle_event({:call, from}, {_ref, request}, :connected, %{closed: false, tcp: tcp} = state)
      when request in [:peercert, :peername, :sockname] and not is_nil(tcp) do
    result =
      case request do
        :peercert -> Diagnostics.peercert(state.machine)
        :peername -> diagnostic_result(:inet.peername(tcp))
        :sockname -> diagnostic_result(:inet.sockname(tcp))
      end

    reply(from, result)
  end

  def handle_event(
        {:call, from},
        {_ref, {:connection_information, keys}},
        :connected,
        %{closed: false, tcp: tcp} = state
      )
      when not is_nil(tcp) do
    reply(from, Diagnostics.connection_information(state.machine, keys))
  end

  def handle_event({:call, from}, {_ref, request}, _phase, _state)
      when request in [:peercert, :peername, :sockname] do
    reply(from, {:error, :closed})
  end

  def handle_event({:call, from}, {_ref, {:connection_information, _keys}}, _phase, _state),
    do: reply(from, {:error, :closed})

  def handle_event({:call, from}, {_ref, {:recv, length, deadline}}, :connected, state) do
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

  def handle_event({:call, from}, {_ref, :enable_duplex_reads}, :connected, state) do
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

  def handle_event({:call, from}, {_ref, :abandon_send}, :connected, state) do
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
        drain_or_continue(:connected, %{state | write_abandoned?: true}, [{:reply, from, :ok}])
    end
  end

  def handle_event({:call, from}, {_ref, :reserve_write}, :connected, state) do
    cond do
      state.closed or state.write_abandoned? ->
        reply(from, {:error, :closed})

      state.duplex_reads? and state.send_timeout == :infinity ->
        reply(from, {:error, :infinite_send_timeout})

      state.write != nil ->
        reply(from, {:error, :busy})

      true ->
        token = make_ref()

        {:ok, deadline} = Options.deadline(state.send_timeout)

        write = %{
          token: token,
          owner: elem(from, 0),
          monitor: Process.monitor(elem(from, 0)),
          from: nil,
          cursor: nil,
          size: nil,
          waiting: nil,
          deadline: deadline,
          timer: timer(deadline, {:write_timeout, token}),
          send_timeout: state.send_timeout
        }

        {:keep_state, %{state | write: write}, [{:reply, from, {:ok, token}}]}
    end
  end

  def handle_event(
        {:call, from},
        {_ref, {:send, token, cursor, size}},
        :connected,
        %{write: %{token: token, owner: owner, from: nil} = write} = state
      )
      when elem(from, 0) == owner do
    if Options.remaining(write.deadline) == 0 do
      fail(%{state | write: %{write | from: from}}, :timeout)
    else
      case :inet.setopts(state.tcp,
             send_timeout: write.send_timeout,
             send_timeout_close: true
           ) do
        :ok ->
          state = %{state | write: %{write | from: from, cursor: cursor, size: size}}
          drain_or_continue(:connected, state)

        {:error, reason} ->
          fail(%{state | write: %{write | from: from}}, reason)
      end
    end
  end

  def handle_event({:call, from}, {_ref, _}, _phase, _state), do: reply(from, {:error, :closed})

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

  defp output_barrier?(%{output: nil}), do: false
  defp output_barrier?(%{output: %{kind: :application}, write_abandoned?: true}), do: false
  defp output_barrier?(%{output: %{kind: :application}, duplex_reads?: true}), do: false
  defp output_barrier?(_state), do: true

  defp ready_for_write?(%{write: %{cursor: cursor, waiting: nil}}) when not is_nil(cursor),
    do: true

  defp ready_for_write?(_state), do: false

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
    _ = close_transport(state)
    :ok
  end

  @impl true
  def format_status(status) do
    Map.merge(status, %{data: :redacted, reason: :redacted, log: [], queue: [], postponed: []})
  end

  defp process_records(phase, [], state), do: {:ok, phase, state}

  defp process_records(phase, [record | rest], state) do
    case HandshakeMachine.feed(state.machine, record) do
      {:ok, machine, outbound, events} ->
        state = %{state | machine: machine}

        if outbound == [] do
          with {:ok, phase, state} <- apply_events(phase, events, state) do
            if state.closed and rest != [],
              do: {:error, :closed, state},
              else: process_records(phase, rest, state)
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

  defp prepare_resumption(%{session_tickets: :disabled} = options, _tcp),
    do: SSL.ResumptionContext.prepare(options, nil)

  defp prepare_resumption(options, tcp) do
    with {:ok, endpoint} <- :inet.peername(tcp),
         do: SSL.ResumptionContext.prepare(options, endpoint)
  end

  defp apply_events(phase, [], state), do: {:ok, phase, state}

  defp apply_events(phase, [{:session_ticket, material} | rest], state) do
    :ok = SSL.ResumptionContext.store(state.ticket_key, material)
    apply_events(phase, rest, state)
  end

  defp apply_events(_phase, [{:connected, negotiated_protocol} | rest], state) do
    if Options.remaining(state.deadline) == 0 do
      {:error, :timeout, state}
    else
      :gen_statem.reply(state.connect_from, {:ok, state.socket})
      _ = cancel_timer(state.handshake_timer)

      apply_events(:connected, rest, %{
        state
        | connect_from: nil,
          handshake_timer: nil,
          negotiated_protocol: negotiated_protocol
      })
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
      case :inet.setopts(state.tcp, active: :once) do
        :ok -> {:next_state, phase, %{state | armed: true}, actions}
        {:error, reason} -> fail(state, reason)
      end
    else
      {:next_state, phase, state, actions}
    end
  end

  defp fail(state, {:peer_alert, _level, description}) do
    category =
      Enum.find_value(@alert_codes, :handshake_failure, fn {name, code} ->
        if code == description, do: name
      end)

    notify_pending(state, {:error, {:tls_alert, {category, ~c"Peer terminated TLS"}}})
    state = notify_active_terminal(state, {:tls_alert, {category, ~c"Peer terminated TLS"}})
    {:stop, :normal, close_transport(state)}
  end

  defp fail(state, reason) do
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

  defp fail_now(state, reason) do
    notify_pending(state, {:error, reason})
    state = notify_active_terminal(state, reason)
    {:stop, :normal, close_transport(state)}
  end

  defp notify_pending(state, result) do
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
  defp apply_tcp_options(tcp, options), do: :inet.setopts(tcp, options)

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
        send(writer, {:send, token, tcp, bytes, shutdown?})

        {:ok,
         %{
           state
           | output: %{
               token: token,
               kind: kind,
               continuation: continuation,
               size: size,
               timer: timer(deadline, {:output_timeout, token})
             }
         }}
    end
  end

  defp start_output(_state, _bytes, _kind, _continuation, _deadline), do: {:error, :busy}

  defp complete_output(phase, %{continuation: :handshake_start}, state),
    do: drain_or_continue(phase, state)

  defp complete_output(phase, %{continuation: :application}, %{write: nil} = state),
    do: drain_or_continue(phase, state)

  defp complete_output(phase, %{continuation: :application}, %{write: write} = state) do
    state = %{state | write: %{write | waiting: nil}}

    if state.write.cursor == [] do
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

    case output.continuation do
      {:shutdown, kind} -> finish_shutdown(phase, kind, state)
      _ -> fail_now(state, reason)
    end
  end

  defp output_kind(:handshaking, %{phase: :connected}), do: :client_finished
  defp output_kind(:handshaking, _machine), do: :handshake
  defp output_kind(:connected, _machine), do: :control

  defp begin_shutdown(%{machine: nil} = state, _kind, _waiters), do: {:abort, state}

  defp begin_shutdown(%{output: output} = state, _kind, _waiters) when not is_nil(output),
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

  defp close_transport(state) do
    _ = if state.output, do: cancel_timer(state.output.timer)

    # Port.close does not block the callback, but inet can retain the port
    # while flushing. Discard pending output at this terminal boundary;
    # leave ordinary, acknowledged empty-queue closes graceful.
    if is_port(state.tcp) do
      pending = :inet.getstat(state.tcp, [:send_pend])

      _ =
        if state.output != nil or match?({:ok, [{:send_pend, size}]} when size > 0, pending) do
          _ = :inet.setopts(state.tcp, linger: {true, 0})
        end

      try do
        Port.close(state.tcp)
      rescue
        ArgumentError -> :ok
      end
    end

    %{state | tcp: nil, machine: nil, armed: false, output: nil}
  end

  defp diagnostic_result({:error, _}), do: {:error, :closed}
  defp diagnostic_result(result), do: result

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
