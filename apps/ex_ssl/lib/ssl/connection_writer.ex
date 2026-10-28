defmodule SSL.ConnectionWriter do
  @moduledoc false

  alias SSL.Lifecycle.{Observer, Receipt}

  @typep birth_context :: %{
           receipt: Receipt.t(),
           permit: reference(),
           control_deadline: {:abs_ms, integer()},
           setup_deadline: integer() | :infinity,
           nonce: reference()
         }

  # Private birth protocol. The permit, readiness nonce and exact monitor
  # identities have separate jobs; no native allocation happens in this entry.
  @spec start(pid(), birth_context()) :: {pid(), reference()}
  def start(
        connection,
        %{
          receipt: %Receipt{observer: observer, cell: cell},
          permit: permit,
          control_deadline: {:abs_ms, control},
          setup_deadline: setup,
          nonce: nonce
        } = context
      )
      when is_pid(connection) and is_pid(observer) and is_reference(cell) and
             is_reference(permit) and is_integer(control) and
             (is_integer(setup) or setup == :infinity) and is_reference(nonce) do
    # Context shape and finite admission are checked before the spawn constructor.
    # Standalone private writers also clip once before the first Observer call;
    # Connection-created writers receive the same already-clipped deadline.

    control =
      if context.setup_deadline == :infinity,
        do: control,
        else: min(control, context.setup_deadline)

    context = %{context | control_deadline: {:abs_ms, control}}

    spawn_monitor(fn ->
      Process.flag(:sensitive, true)
      connection_monitor = Process.monitor(connection)
      observer = Receipt.observer(context.receipt)
      observer_monitor = Process.monitor(observer)
      enroll(connection, connection_monitor, observer, observer_monitor, context)
    end)
  end

  @spec start(pid()) :: {pid(), reference()}
  def start(connection) when is_pid(connection) do
    spawn_monitor(fn ->
      Process.flag(:sensitive, true)
      connection_monitor = Process.monitor(connection)
      loop(connection, connection_monitor)
    end)
  end

  defp enroll(connection, connection_monitor, observer, observer_monitor, context) do
    # A born writer must attempt accounting even if its parent has already died.
    # Only observer absence prevents accounting. Neither event proves port DOWN.
    if Process.alive?(observer) and
         Observer.enroll_self(context.receipt, :writer, context.permit, context.control_deadline) ==
           :use do
      if live?(connection, observer) and remaining(context) > 0 do
        send(connection, {:lifecycle_writer_ready, self(), context.nonce, observer})
        await_release(connection, connection_monitor, observer, observer_monitor, context)
      end
    end
  end

  defp await_release(connection, connection_monitor, observer, observer_monitor, context) do
    nonce = context.nonce

    receive do
      {:lifecycle_writer_release, ^connection, ^nonce, ^observer} ->
        if live?(connection, observer) and remaining(context) > 0,
          do:
            enrolled_loop(
              connection,
              connection_monitor,
              observer,
              observer_monitor,
              context,
              false
            )

      {:DOWN, ^connection_monitor, :process, ^connection, _reason} ->
        :ok

      {:DOWN, ^observer_monitor, :process, ^observer, _reason} ->
        :ok
    after
      remaining(context) -> :ok
    end
  end

  defp enrolled_loop(connection, connection_monitor, observer, observer_monitor, context, spent) do
    nonce = context.nonce

    receive do
      {:lifecycle_socket_send, ^nonce, token, tcp, bytes, shutdown?, deadline}
      when is_reference(token) and (is_binary(bytes) or is_list(bytes)) and
             is_boolean(shutdown?) and (is_integer(deadline) or deadline == :infinity) ->
        if live?(connection, observer) do
          result = SSL.Lifecycle.NativeSocket.send_bytes(tcp, bytes, shutdown?, deadline)
          send(connection, {:writer_result, self(), token, result})

          enrolled_loop(
            connection,
            connection_monitor,
            observer,
            observer_monitor,
            context,
            spent
          )
        end

      {:lifecycle_send, ^nonce, token, tcp, bytes, shutdown?}
      when is_reference(token) and (is_binary(bytes) or is_list(bytes)) and
             is_boolean(shutdown?) ->
        if live?(connection, observer) do
          send(connection, {:writer_result, self(), token, write(tcp, bytes, shutdown?)})

          enrolled_loop(
            connection,
            connection_monitor,
            observer,
            observer_monitor,
            context,
            spent
          )
        end

      {:lifecycle_prepare, ^connection, ^nonce, ^observer, request, {:abs_ms, deadline}}
      when is_reference(request) and is_integer(deadline) ->
        result = prepare(context, connection, observer, deadline, spent)
        send(connection, {:lifecycle_handoff_ready, self(), nonce, observer, request, result})
        enrolled_loop(connection, connection_monitor, observer, observer_monitor, context, true)

      {:DOWN, ^connection_monitor, :process, ^connection, _reason} ->
        :ok

      {:DOWN, ^observer_monitor, :process, ^observer, _reason} ->
        :ok
    end
  end

  defp prepare(_context, _connection, _observer, _deadline, true),
    do: {:error, :handoff_spent}

  defp prepare(context, connection, observer, requested, false) do
    deadline =
      if context.setup_deadline == :infinity,
        do: requested,
        else: min(requested, context.setup_deadline)

    if live?(connection, observer) and SSL.Options.remaining(deadline) > 0,
      do: Observer.writer_ready(context.receipt, {:abs_ms, deadline}),
      else: {:error, :deadline_exceeded}
  end

  defp live?(connection, observer), do: Process.alive?(connection) and Process.alive?(observer)

  defp remaining(context) do
    {:abs_ms, deadline} = context.control_deadline
    SSL.Options.remaining(deadline)
  end

  defp write(tcp, bytes, shutdown?) do
    with :ok <- :gen_tcp.send(tcp, bytes),
         do: if(shutdown?, do: :gen_tcp.shutdown(tcp, :write), else: :ok)
  end

  defp loop(connection, connection_monitor) do
    receive do
      {:carrier_send, token, %SSL.Socket{} = carrier, bytes, _shutdown?, deadline}
      when is_reference(token) and (is_binary(bytes) or is_list(bytes)) and
             (is_integer(deadline) or deadline == :infinity) ->
        # The controller closes the carrier only after this record is acknowledged.
        # Half-closing its underlying TCP would bypass the outer TLS close_notify.
        result =
          if deadline == :infinity,
            do: SSL.send(carrier, bytes),
            else: SSL.send(carrier, bytes, {:abs_ms, deadline})

        send(connection, {:writer_result, self(), token, result})
        loop(connection, connection_monitor)

      {:send, token, tcp, bytes, shutdown?}
      when is_reference(token) and (is_binary(bytes) or is_list(bytes)) and
             is_boolean(shutdown?) ->
        result = write(tcp, bytes, shutdown?)

        send(connection, {:writer_result, self(), token, result})
        loop(connection, connection_monitor)

      {:DOWN, ^connection_monitor, :process, ^connection, _reason} ->
        :ok
    end
  end
end
