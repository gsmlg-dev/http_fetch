defmodule P5NativeConsumer do
  alias Abyss.DhcpSocket.Native

  def run do
    true = Code.ensure_loaded?(AbyssDhcpSocket.Native)
    parent = self()

    spawn_link(fn ->
      for line <- IO.stream(:stdio, :line), do: send(parent, {:command, String.split(line)})
    end)

    socket = Native.open("eth0", self())
    true = is_reference(socket)
    IO.puts("WIRE READY DHCP")
    loop(socket, nil)
  end

  defp loop(socket, orphan) do
    receive do
      {:dhcp_rx, payload} ->
        IO.puts("WIRE DHCP " <> Base.encode64(payload))
        loop(socket, orphan)

      {:arp_rx, frame} ->
        IO.puts("WIRE ARP " <> Base.encode64(frame))
        loop(socket, orphan)

      {:command, [id, "BROADCAST", payload]} ->
        :ok = Native.send_broadcast(socket, Base.decode64!(payload))
        ack(id)
        loop(socket, orphan)

      {:command, [id, "UNICAST", payload]} ->
        :ok = Native.send_unicast(socket, {192, 0, 2, 11}, Base.decode64!(payload))
        ack(id)
        loop(socket, orphan)

      {:command, [id, "PROBE"]} ->
        :ok = Native.send_arp_probe(socket, {192, 0, 2, 99})
        ack(id)
        loop(socket, orphan)

      {:command, [id, "CLOSE"]} ->
        :ok = Native.close(socket)
        :ok = Native.close(socket)
        {:error, "socket closed"} = Native.send_broadcast(socket, <<1>>)
        {:error, "socket closed"} = Native.send_unicast(socket, {192, 0, 2, 11}, <<1>>)
        {:error, "socket closed"} = Native.send_arp_probe(socket, {192, 0, 2, 99})
        no_down()
        ack(id)
        loop(socket, orphan)

      {:command, [id, "DEAD_OWNER"]} ->
        parent = self()

        {owner, monitor} =
          spawn_monitor(fn ->
            resource = Native.open("eth0", self())
            true = is_reference(resource)
            send(parent, {:resource, self(), resource})
            receive do: (:stop -> :ok)
          end)

        resource = receive do: ({:resource, ^owner, resource} -> resource)
        Process.exit(owner, :kill)
        receive do: ({:DOWN, ^monitor, :process, ^owner, :killed} -> :ok)
        ack(id)
        loop(socket, resource)

      {:command, [id, "CLOSE_ORPHAN"]} ->
        :ok = Native.close(orphan)
        :ok = Native.close(orphan)
        no_down()
        ack(id)
        loop(socket, nil)

      {:command, [id, "STOP"]} ->
        :ok = Native.close(socket)
        if orphan, do: Native.close(orphan)
        no_down()
        ack(id)

      message ->
        raise "unexpected native owner message: #{inspect(message)}"
    end
  end

  defp no_down do
    receive do
      {tag, reason} when tag in [:dhcp_socket_down, :arp_socket_down] ->
        raise "unexpected shutdown message: #{inspect({tag, reason})}"
    after
      0 -> :ok
    end
  end

  defp ack(id), do: IO.puts("WIRE OK " <> id)
end

P5NativeConsumer.run()
