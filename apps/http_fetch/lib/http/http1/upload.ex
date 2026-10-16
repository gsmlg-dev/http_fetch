defmodule HTTP.HTTP1.Upload do
  @moduledoc false

  @max_chunk_bytes 65_536

  # The socket owner keeps read credit; this linked worker holds at most one
  # acknowledged source chunk and performs writes without blocking that owner.
  def start(
        transport,
        socket,
        stream,
        remaining,
        deadline_at,
        headers \\ %HTTP.Headers{},
        head \\ nil,
        options \\ []
      ) do
    owner = self()
    token = make_ref()
    completion = :atomics.new(2, [])
    if remaining == 0, do: begin_completion(completion, deadline_at)

    tracker = HTTP.RequestLifecycle.current()

    {pid, monitor} =
      :erlang.spawn_opt(
        fn ->
          Process.put(HTTP.RequestLifecycle, tracker)

          state = %{
            transport: transport,
            socket: socket,
            stream: stream,
            remaining: remaining,
            completion: completion,
            deadline_at: deadline_at,
            headers: headers,
            trailers: nil,
            options: Keyword.put(options, :deadline_at, deadline_at)
          }

          result =
            receive do
              {:start_upload, ^token} ->
                with :ok <- send_head(state, head), do: read_body(state)
            after
              remaining_timeout(deadline_at) -> {:error, :request_timeout}
            end

          if match?({:error, _}, result) do
            {:error, reason} = result
            HTTP.Stream.error(stream, reason)
          end

          send(owner, {:http1_upload, token, result})
        end,
        [:link, :monitor]
      )

    # Bind source cleanup before releasing the first header write. If the owner
    # dies on the peer's first header byte, the source still observes reader DOWN.
    HTTP.RequestLifecycle.register(tracker, pid, :upload)
    send(stream, {:read_chunk, pid, :ack})
    send(pid, {:start_upload, token})
    %{pid: pid, monitor: monitor, stream: stream, token: token, completion: completion}
  end

  # Publish eligibility before the final native write: peer headers can reach
  # the read owner before that write returns or its result message is delivered.
  def completion_deadline(upload) do
    if :atomics.get(upload.completion, 1) == 1,
      do: :atomics.get(upload.completion, 2)
  end

  defp begin_completion(completion, deadline_at) do
    if :atomics.get(completion, 1) == 0 do
      budget = HTTP.Config.streaming_timeout()
      deadline = min(deadline_at, System.monotonic_time(:millisecond) + budget)
      :atomics.put(completion, 2, deadline)
      :atomics.put(completion, 1, 1)
    end
  end

  defp send_head(_state, nil), do: :ok
  defp send_head(state, head), do: send_data(state, head)

  defp send_data(state, data),
    do: HTTP.HTTP1.IdleTimeout.send(state.transport, state.socket, data, state.options)

  def completed(upload) do
    Process.unlink(upload.pid)
    Process.demonitor(upload.monitor, [:flush])
    :ok
  end

  # Signalling error alone is not confirmation: await both writer termination
  # and the source's reader cleanup before exposing the final response.
  def stop(upload, reason, deadline_at) do
    # The owner can already have consumed the original DOWN while observing a
    # lost completion result. A fresh monitor still confirms a terminated writer.
    writer_monitor = Process.monitor(upload.pid)
    Process.demonitor(upload.monitor, [:flush])
    source_monitor = Process.monitor(upload.stream)
    HTTP.Stream.error(upload.stream, reason)
    Process.unlink(upload.pid)
    Process.exit(upload.pid, :kill)

    try do
      with :ok <- await_down(writer_monitor, deadline_at) do
        await_down(source_monitor, deadline_at)
      end
    after
      Process.demonitor(writer_monitor, [:flush])
      Process.demonitor(source_monitor, [:flush])
    end
  end

  defp await_down(monitor, deadline_at) do
    receive do
      {:DOWN, ^monitor, :process, _pid, _reason} -> :ok
    after
      remaining_timeout(deadline_at) ->
        Process.demonitor(monitor, [:flush])
        {:error, :request_timeout}
    end
  end

  defp read_body(state) do
    if remaining_timeout(body_deadline(state)) == 0,
      do: {:error, body_timeout(state)},
      else: receive_body(state)
  end

  defp receive_body(state) do
    stream = state.stream

    receive do
      {:stream_chunk, ^stream, chunk, ack_ref} ->
        write_chunk(state, chunk, ack_ref)

      {:stream_chunk, ^stream, chunk} ->
        write_chunk(state, chunk, nil)

      {:stream_trailers, ^stream, fields} ->
        if state.remaining != nil do
          {:error, :request_trailers_require_chunked}
        else
          case HTTP.Trailers.upload(fields, state.headers) do
            {:ok, trailers} -> read_body(%{state | trailers: trailers})
            error -> error
          end
        end

      {:stream_end, ^stream} ->
        case state.remaining do
          nil ->
            send_data(state, [
              "0\r\n",
              if(state.trailers, do: HTTP.Trailers.serialize(state.trailers), else: []),
              "\r\n"
            ])

          0 ->
            if remaining_timeout(body_deadline(state)) == 0,
              do: {:error, body_timeout(state)},
              else: :ok

          _ ->
            {:error, :content_length_mismatch}
        end

      {:stream_error, ^stream, reason} ->
        {:error, reason}
    after
      remaining_timeout(body_deadline(state)) -> {:error, body_timeout(state)}
    end
  end

  defp write_chunk(state, chunk, ack_ref) do
    cond do
      byte_size(chunk) > @max_chunk_bytes ->
        {:error, :buffer_limit}

      state.remaining != nil and byte_size(chunk) > state.remaining ->
        {:error, :content_length_mismatch}

      true ->
        if state.remaining != nil and byte_size(chunk) == state.remaining,
          do: begin_completion(state.completion, state.deadline_at)

        data =
          if state.remaining == nil and chunk != "",
            do: [Integer.to_string(byte_size(chunk), 16), "\r\n", chunk, "\r\n"],
            else: chunk

        with :ok <- send_data(state, data) do
          if ack_ref, do: send(state.stream, {:stream_chunk_ack, ack_ref})
          remaining = if state.remaining != nil, do: state.remaining - byte_size(chunk)
          read_body(%{state | remaining: remaining})
        end
    end
  end

  defp body_deadline(state) do
    if :atomics.get(state.completion, 1) == 1,
      do: :atomics.get(state.completion, 2),
      else: state.deadline_at
  end

  defp body_timeout(state) do
    if remaining_timeout(state.deadline_at) == 0, do: :request_timeout, else: :timeout
  end

  defp remaining_timeout(:infinity), do: :infinity

  defp remaining_timeout(deadline_at),
    do: max(deadline_at - System.monotonic_time(:millisecond), 0)
end
