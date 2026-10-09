defmodule HTTP.HTTP1.Upload do
  @moduledoc false

  @max_chunk_bytes 65_536

  # The socket owner keeps read credit; this linked worker holds at most one
  # acknowledged source chunk and performs writes without blocking that owner.
  def start(transport, socket, stream, remaining, deadline_at, headers \\ %HTTP.Headers{}) do
    owner = self()
    token = make_ref()

    {pid, monitor} =
      :erlang.spawn_opt(
        fn ->
          result =
            read_body(%{
              transport: transport,
              socket: socket,
              stream: stream,
              remaining: remaining,
              deadline_at: deadline_at,
              headers: headers,
              trailers: nil
            })

          send(owner, {:http1_upload, token, result})
        end,
        [:link, :monitor]
      )

    # Subscribe from the owner before it can cancel the worker. This also gives
    # the source a reader monitor when a final response wins the startup race.
    send(stream, {:read_chunk, pid, :ack})
    %{pid: pid, monitor: monitor, stream: stream, token: token}
  end

  def completed(upload) do
    Process.unlink(upload.pid)
    Process.demonitor(upload.monitor, [:flush])
    :ok
  end

  # Signalling error alone is not confirmation: await both writer termination
  # and the source's reader cleanup before exposing the final response.
  def stop(upload, reason, deadline_at) do
    source_monitor = Process.monitor(upload.stream)
    HTTP.Stream.error(upload.stream, reason)
    Process.unlink(upload.pid)
    Process.exit(upload.pid, :kill)

    with :ok <- await_down(upload.monitor, deadline_at) do
      await_down(source_monitor, deadline_at)
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
            state.transport.send(state.socket, [
              "0\r\n",
              if(state.trailers, do: HTTP.Trailers.serialize(state.trailers), else: []),
              "\r\n"
            ])

          0 ->
            :ok

          _ ->
            {:error, :content_length_mismatch}
        end

      {:stream_error, ^stream, reason} ->
        {:error, reason}
    after
      remaining_timeout(state.deadline_at) -> {:error, :request_timeout}
    end
  end

  defp write_chunk(state, chunk, ack_ref) do
    cond do
      byte_size(chunk) > @max_chunk_bytes ->
        {:error, :buffer_limit}

      state.remaining != nil and byte_size(chunk) > state.remaining ->
        {:error, :content_length_mismatch}

      true ->
        data =
          if state.remaining == nil and chunk != "",
            do: [Integer.to_string(byte_size(chunk), 16), "\r\n", chunk, "\r\n"],
            else: chunk

        with :ok <- state.transport.send(state.socket, data) do
          if ack_ref, do: send(state.stream, {:stream_chunk_ack, ack_ref})
          remaining = if state.remaining != nil, do: state.remaining - byte_size(chunk)
          read_body(%{state | remaining: remaining})
        end
    end
  end

  defp remaining_timeout(deadline_at),
    do: max(deadline_at - System.monotonic_time(:millisecond), 0)
end
