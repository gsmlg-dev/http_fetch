defmodule HTTP.HTTP1.Upload do
  @moduledoc false

  @max_chunk_bytes 65_536

  # The socket owner keeps read credit; this linked worker holds at most one
  # acknowledged source chunk and performs writes without blocking that owner.
  def start(transport, socket, stream, remaining, deadline_at) do
    owner = self()
    token = make_ref()

    {pid, monitor} =
      :erlang.spawn_opt(
        fn ->
          result = read_body(transport, socket, stream, remaining, deadline_at)
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

  defp read_body(transport, socket, stream, remaining, deadline_at) do
    receive do
      {:stream_chunk, ^stream, chunk, ack_ref} ->
        write_chunk(transport, socket, stream, chunk, ack_ref, remaining, deadline_at)

      {:stream_chunk, ^stream, chunk} ->
        write_chunk(transport, socket, stream, chunk, nil, remaining, deadline_at)

      {:stream_end, ^stream} ->
        case remaining do
          nil -> transport.send(socket, "0\r\n\r\n")
          0 -> :ok
          _ -> {:error, :content_length_mismatch}
        end

      {:stream_error, ^stream, reason} ->
        {:error, reason}
    after
      remaining_timeout(deadline_at) -> {:error, :request_timeout}
    end
  end

  defp write_chunk(transport, socket, stream, chunk, ack_ref, remaining, deadline_at) do
    cond do
      byte_size(chunk) > @max_chunk_bytes ->
        {:error, :buffer_limit}

      remaining != nil and byte_size(chunk) > remaining ->
        {:error, :content_length_mismatch}

      true ->
        data =
          if remaining == nil and chunk != "",
            do: [Integer.to_string(byte_size(chunk), 16), "\r\n", chunk, "\r\n"],
            else: chunk

        with :ok <- transport.send(socket, data) do
          if ack_ref, do: send(stream, {:stream_chunk_ack, ack_ref})
          remaining = if remaining != nil, do: remaining - byte_size(chunk)
          read_body(transport, socket, stream, remaining, deadline_at)
        end
    end
  end

  defp remaining_timeout(deadline_at),
    do: max(deadline_at - System.monotonic_time(:millisecond), 0)
end
