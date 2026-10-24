defmodule HTTP.HTTP1.IdleTimeout do
  @moduledoc false

  alias HTTP.Transport.ExSSL

  @write_bytes 16_384

  # A completed send means transport acceptance, not remote receipt. Keep each
  # public transport write bounded and reset its deadline before the next one.
  def send(transport, socket, data, options) do
    case options[:write_idle_timeout] do
      nil -> transport.send(socket, data)
      timeout -> send_vectors(transport, socket, :erlang.iolist_to_iovec(data), options, timeout)
    end
  end

  defp send_vectors(_transport, _socket, [], _options, _timeout), do: :ok

  defp send_vectors(transport, socket, [<<>> | rest], options, timeout),
    do: send_vectors(transport, socket, rest, options, timeout)

  defp send_vectors(transport, socket, [data | rest], options, timeout) do
    size = min(byte_size(data), @write_bytes)
    <<chunk::binary-size(^size), tail::binary>> = data
    started = System.monotonic_time(:millisecond)
    remaining = remaining(options[:deadline_at])
    configured = Keyword.get(options[:socket_opts] || [], :send_timeout, :infinity)
    budget = min(timeout, min(configured, remaining))

    result =
      if remaining == 0 do
        {:error, :request_timeout}
      else
        send_chunk(transport, socket, chunk, budget, started)
      end

    case result do
      :ok ->
        send_vectors(transport, socket, [tail | rest], options, timeout)

      {:error, :timeout} ->
        cond do
          remaining(options[:deadline_at]) == 0 ->
            {:error, :request_timeout}

          budget == timeout and System.monotonic_time(:millisecond) - started >= timeout ->
            {:error, :write_idle_timeout}

          true ->
            {:error, :timeout}
        end

      error ->
        error
    end
  end

  defp send_chunk(ExSSL, socket, chunk, budget, started),
    do: ExSSL.send(socket, chunk, {:abs_ms, started + budget})

  defp send_chunk(transport, socket, chunk, budget, _started) do
    with :ok <- transport.setopts(socket, send_timeout: budget),
         do: transport.send(socket, chunk)
  end

  defp remaining(nil), do: :infinity
  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
