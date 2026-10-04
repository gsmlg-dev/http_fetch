defmodule SSL.ConnectionWriter do
  @moduledoc false

  @spec start(pid()) :: {pid(), reference()}
  def start(connection) when is_pid(connection) do
    spawn_monitor(fn ->
      Process.flag(:sensitive, true)
      connection_monitor = Process.monitor(connection)
      loop(connection, connection_monitor)
    end)
  end

  defp loop(connection, connection_monitor) do
    receive do
      {:send, token, tcp, bytes, shutdown?}
      when is_reference(token) and (is_binary(bytes) or is_list(bytes)) and
             is_boolean(shutdown?) ->
        result =
          with :ok <- :gen_tcp.send(tcp, bytes),
               do: if(shutdown?, do: :gen_tcp.shutdown(tcp, :write), else: :ok)

        send(connection, {:writer_result, self(), token, result})
        loop(connection, connection_monitor)

      {:DOWN, ^connection_monitor, :process, ^connection, _reason} ->
        :ok
    end
  end
end
