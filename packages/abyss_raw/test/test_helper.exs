interface = if match?({:unix, :darwin}, :os.type()), do: "lo0", else: "lo"

exclude =
  case AbyssDhcpSocket.Native.open(interface, self()) do
    socket when is_reference(socket) ->
      AbyssDhcpSocket.Native.close(socket)
      []

    other ->
      IO.puts("Excluding :dhcp_loopback tests: cannot bind #{interface}:68 (#{inspect(other)})")
      [:dhcp_loopback]
  end

ExUnit.start(exclude: exclude)
