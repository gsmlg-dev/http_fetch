defmodule HTTP.HTTP3 do
  @moduledoc false

  alias HTTP.HTTP3.Stream
  alias HTTP.Request

  @spec request(Request.t(), term(), function()) :: term()
  def request(%Request{} = request, state, handler) do
    opening = Keyword.get(request.transport_options, :connect_timeout, 5_000)

    case Stream.start(request, self(), opening_timeout: opening) do
      {:ok, stream, generation} ->
        monitor = Process.monitor(stream)

        try do
          await(stream, generation, monitor, state, handler)
        after
          Stream.close(stream)
          Process.demonitor(monitor, [:flush])
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp await(stream, generation, monitor, state, handler) do
    receive do
      {:http_runtime, ^generation, ^stream, {:error, reason}} ->
        {:error, reason, state}

      {:http_runtime, ^generation, ^stream, {:data, bytes, ref}} ->
        case handler.(state, {:body, bytes}) do
          {:cont, next} ->
            Stream.acknowledge(stream, ref)
            await(stream, generation, monitor, next, handler)

          {:halt, next} ->
            {:ok, next}

          {:error, reason, next} ->
            {:error, reason, next}
        end

      {:http_runtime, ^generation, ^stream, event} ->
        case handler.(state, event) do
          {:cont, next} -> await(stream, generation, monitor, next, handler)
          {:halt, next} -> {:ok, next}
          {:error, reason, next} -> {:error, reason, next}
        end

      {:DOWN, ^monitor, :process, ^stream, reason} ->
        {:error, {:http3_stream_down, reason}, state}

      :abort ->
        {:error, :aborted, state}

      :deadline ->
        {:error, :request_timeout, state}
    after
      max(state.deadline_at - System.monotonic_time(:millisecond), 0) ->
        {:error, :request_timeout, state}
    end
  end
end
