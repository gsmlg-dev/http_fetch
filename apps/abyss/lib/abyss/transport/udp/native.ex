defmodule Abyss.Transport.UDP.Native do
  @moduledoc """
  Direct public OTP socket UDP adapter for Linux.

  This adapter is distinct from GenUDP's socket driver. The existing Listener
  owns the returned socket and tracks each nonblocking receive by operation
  reference and socket generation. `arm/2` never runs a callback or waits for
  traffic. Receive buffers are 65,535 data bytes and 4,096 control bytes.

  Linux packet-info controls use public `setopt_native` and `sendmsg` APIs.
  Their numeric constants and structure layouts are isolated here because
  OTP 27 does not support symbolic packet-info send controls. These layouts
  were checked against Linux headers and actual IPv4/IPv6 traffic; other
  platforms are rejected. A strict reply uses per-message controls on the
  original socket, without changing shared socket options.
  """

  alias Abyss.Datagram
  alias Abyss.Transport.UDP.Multicast

  @data_buffer 65_535
  @control_buffer 4096
  @send_timeout 100
  @ip 0
  @ipv6 41
  @ip_pktinfo 8
  @ipv6_pktinfo 50

  def listen(port, options) when is_integer(port) and port in 0..65_535 and is_list(options) do
    with :ok <- platform(),
         {:ok, bind_address} <- bind_address(port, options),
         {:ok, socket} <- :socket.open(bind_address.family, :dgram, :udp) do
      case configure(socket, bind_address, options) do
        :ok ->
          {:ok, socket}

        {:error, _} = error ->
          _ = :socket.close(socket)
          error
      end
    end
  end

  def listen(_, _), do: {:error, :invalid_native_options}

  defp configure(socket, address, options) do
    {memberships, ordinary} =
      Enum.split_with(
        options,
        &match?({operation, _} when operation in [:add_membership, :drop_membership], &1)
      )

    ordinary = Enum.reject(ordinary, &match?({key, _} when key in [:ip, :ifaddr, :scope_id], &1))

    with :ok <- default_metadata(socket, address.family),
         :ok <- setopts(socket, ordinary),
         :ok <- :socket.bind(socket, address),
         do: setopts(socket, memberships)
  end

  def sockname(socket) do
    with {:ok, %{addr: address, port: port}} <- :socket.sockname(socket),
         do: {:ok, {address, port}}
  end

  def close(socket), do: :socket.close(socket)

  @doc "Start one nonblocking receive with an operation reference chosen by the owner."
  def arm(socket, operation_ref) when is_reference(operation_ref),
    do: :socket.recvmsg(socket, @data_buffer, @control_buffer, [], operation_ref)

  @doc "Cancel an outstanding receive owned by the caller; preserve the OTP result."
  def cancel(socket, select_info), do: :socket.cancel(socket, select_info)

  @doc "Reject incomplete payloads and normalize truthful receive metadata."
  def datagram(message, context) do
    if :trunc in Map.get(message, :flags, []) do
      {:error, :payload_truncated}
    else
      datagram = Datagram.from_native(message, context)
      {:ok, local_ipv6_source(datagram)}
    end
  end

  @doc "Submit a native send or strict reply with a finite local socket deadline."
  def send(socket, {:native, destination}, payload) when is_binary(payload) do
    with :ok <- validate_destination(destination),
         do: send_message(socket, %{addr: destination, iov: [payload]})
  end

  def send(socket, {:native_reply, %Datagram{} = datagram}, payload) when is_binary(payload) do
    with {:ok, destination, control} <- reply_control(datagram),
         do: send_message(socket, %{addr: destination, iov: [payload], ctrl: [control]})
  end

  def send(_, _, _), do: {:error, :invalid_native_send}

  defp send_message(socket, message) do
    result = :socket.sendmsg(socket, message, [], @send_timeout)

    Abyss.Telemetry.track_send_result(
      Abyss.Telemetry.socket_scope(socket),
      result,
      IO.iodata_length(message.iov),
      %{socket: socket}
    )

    result
  end

  def setopts(socket, options) when is_list(options) do
    Enum.reduce_while(options, :ok, fn option, :ok ->
      case set_option(socket, option) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  def setopts(_, _), do: {:error, :invalid_native_options}

  defp set_option(_, option) when option in [:inet, :inet6, :binary], do: :ok
  defp set_option(_, {:mode, :binary}), do: :ok
  defp set_option(_, {:active, false}), do: :ok
  defp set_option(_, {:active, _}), do: {:error, :native_receive_requires_arm}

  defp set_option(socket, {key, value})
       when key in [:recbuf, :sndbuf] and is_integer(value) and value > 0,
       do:
         :socket.setopt(socket, {:socket, if(key == :recbuf, do: :rcvbuf, else: :sndbuf)}, value)

  # GenUDP's BEAM buffer hint does not select the recvmsg buffer: arm/2 uses
  # the fixed complete-datagram bound above. Kernel :recbuf remains separate.
  defp set_option(_socket, {:buffer, value}) when is_integer(value) and value > 0,
    do: :ok

  defp set_option(socket, {key, value})
       when key in [:reuseaddr, :reuseport, :broadcast] and is_boolean(value),
       do: :socket.setopt(socket, {:socket, key}, value)

  defp set_option(socket, {operation, membership})
       when operation in [:add_membership, :drop_membership] do
    with {:ok, {group, interface}} <- Multicast.normalize_membership(membership),
         {:ok, %{family: family}} <- :socket.sockname(socket),
         true <- family == Multicast.family(group) do
      {level, option, value} = membership_option(family, operation, group, interface)
      native_option(socket, level, option, value)
    else
      false -> {:error, :membership_family_mismatch}
      error -> error
    end
  end

  defp set_option(socket, {:multicast_if, interface}) do
    with {:ok, %{family: family}} <- :socket.sockname(socket),
         {:ok, normalized} <- Multicast.resolve_interface(interface, family) do
      {level, option, value} = multicast_interface_option(family, normalized)
      native_option(socket, level, option, value)
    end
  end

  defp set_option(socket, {key, value}) when key in [:multicast_loop, :multicast_ttl] do
    with {:ok, %{family: family}} <- :socket.sockname(socket) do
      if valid_multicast_value?(key, value) do
        {level, option} = multicast_option(family, key)
        native_option(socket, level, option, value)
      else
        {:error, {:invalid_native_option, key, value}}
      end
    end
  end

  defp set_option(socket, {:ipv6_v6only, value}) when is_boolean(value),
    do: native_option(socket, @ipv6, 26, value)

  defp set_option(socket, {:strict_group_filter, value}) when is_boolean(value) do
    with {:ok, %{family: family}} <- :socket.sockname(socket) do
      if family == :inet,
        do: native_option(socket, @ip, 49, not value),
        else: {:error, :strict_group_filter_unsupported}
    end
  end

  defp set_option(socket, {key, value})
       when key in [:recvttl, :recvtos, :recvpktinfo, :recvhoplimit, :recvtclass] and
              is_boolean(value) do
    {level, option} =
      case key do
        :recvttl -> {@ip, 12}
        :recvtos -> {@ip, 13}
        :recvpktinfo -> {@ipv6, 49}
        :recvhoplimit -> {@ipv6, 51}
        :recvtclass -> {@ipv6, 66}
      end

    native_option(socket, level, option, value)
  end

  defp set_option(_, option), do: {:error, {:unsupported_native_option, option}}

  defp membership_option(:inet, operation, group, interface) do
    option = if operation == :add_membership, do: 35, else: 36
    {@ip, option, ipv4_bytes(group) <> ipv4_bytes(interface)}
  end

  defp membership_option(:inet6, operation, group, interface) do
    option = if operation == :add_membership, do: 20, else: 21
    {@ipv6, option, <<ipv6_bytes(group)::binary, interface::native-unsigned-32>>}
  end

  defp multicast_interface_option(:inet, interface), do: {@ip, 32, ipv4_bytes(interface)}
  defp multicast_interface_option(:inet6, interface), do: {@ipv6, 17, interface}
  defp multicast_option(:inet, :multicast_loop), do: {@ip, 34}
  defp multicast_option(:inet, :multicast_ttl), do: {@ip, 33}
  defp multicast_option(:inet6, :multicast_loop), do: {@ipv6, 19}
  defp multicast_option(:inet6, :multicast_ttl), do: {@ipv6, 18}
  defp valid_multicast_value?(:multicast_loop, value), do: is_boolean(value)
  defp valid_multicast_value?(:multicast_ttl, value), do: is_integer(value) and value in 0..255

  defp default_metadata(socket, :inet) do
    with :ok <- native_option(socket, @ip, @ip_pktinfo, true),
         :ok <- native_option(socket, @ip, 12, true),
         do: native_option(socket, @ip, 13, true)
  end

  defp default_metadata(socket, :inet6) do
    with :ok <- native_option(socket, @ipv6, 26, true),
         :ok <- native_option(socket, @ipv6, 49, true),
         :ok <- native_option(socket, @ipv6, 51, true),
         do: native_option(socket, @ipv6, 66, true)
  end

  defp native_option(socket, level, option, value),
    do: :socket.setopt_native(socket, {level, option}, value)

  defp bind_address(port, options) do
    address = option(options, :ifaddr, option(options, :ip, nil))
    family = bind_family(address, options)
    sockaddr = bind_sockaddr(address, port, family, options)

    with :ok <- validate_destination(sockaddr) do
      if sockaddr.family == family,
        do: {:ok, sockaddr},
        else: {:error, :native_family_mismatch}
    end
  end

  defp bind_family(address, options) do
    explicit = Enum.find(options, &(&1 in [:inet, :inet6]))
    inferred = if is_map(address), do: Map.get(address, :family), else: Multicast.family(address)
    explicit || if(inferred == :inet6, do: :inet6, else: :inet)
  end

  defp bind_sockaddr(address, port, family, options) do
    wildcard = if family == :inet, do: {0, 0, 0, 0}, else: {0, 0, 0, 0, 0, 0, 0, 0}
    address = address || wildcard

    sockaddr =
      cond do
        is_map(address) -> Map.put(address, :port, port)
        Multicast.family(address) == family -> Datagram.sockaddr(address, port)
        true -> %{}
      end

    if family == :inet6,
      do: Map.put_new(sockaddr, :scope_id, option(options, :scope_id, 0)),
      else: sockaddr
  end

  defp option(options, key, default) do
    case List.keyfind(options, key, 0) do
      {^key, value} -> value
      nil -> default
    end
  end

  defp validate_destination(%{family: family, addr: address, port: port} = destination)
       when family in [:inet, :inet6] and is_integer(port) and port in 0..65_535 do
    scope = Map.get(destination, :scope_id, 0)

    if Multicast.family(address) == family and is_integer(scope) and scope >= 0,
      do: :ok,
      else: {:error, :invalid_native_destination}
  end

  defp validate_destination(_), do: {:error, :invalid_native_destination}

  defp reply_control(%Datagram{flags: flags} = datagram) do
    if :ctrunc in flags,
      do: {:error, :missing_reply_metadata},
      else: complete_reply_control(datagram)
  end

  defp complete_reply_control(%Datagram{
         peer: peer,
         local_address: source,
         interface_index: index
       })
       when is_integer(index) and index > 0 and index <= 0xFFFFFFFF do
    with :ok <- validate_destination(peer),
         true <- Multicast.family(source) == peer.family and usable_source?(source) do
      case peer.family do
        :inet ->
          data = <<index::native-unsigned-32, ipv4_bytes(source)::binary, 0, 0, 0, 0>>
          {:ok, peer, %{level: @ip, type: @ip_pktinfo, data: data}}

        :inet6 ->
          data = <<ipv6_bytes(source)::binary, index::native-unsigned-32>>
          {:ok, peer, %{level: @ipv6, type: @ipv6_pktinfo, data: data}}
      end
    else
      false -> {:error, :missing_reply_metadata}
      error -> error
    end
  end

  defp complete_reply_control(_), do: {:error, :missing_reply_metadata}

  defp local_ipv6_source(
         %Datagram{
           peer: %{family: :inet6},
           local_address: nil,
           interface_index: index,
           flags: flags
         } = datagram
       )
       when is_integer(index) and index > 0 do
    if :ctrunc in flags do
      datagram
    else
      case interface_source(index, datagram.peer.addr) do
        {:ok, address} -> %{datagram | local_address: address}
        {:error, _} -> datagram
      end
    end
  end

  defp local_ipv6_source(datagram), do: datagram

  defp interface_source(index, peer) do
    with {:ok, interfaces} <- :net.getifaddrs(),
         %{name: name} <-
           Enum.find(interfaces, &match?(%{addr: %{family: :packet, ifindex: ^index}}, &1)) do
      candidates =
        for %{name: ^name, addr: %{family: :inet6, addr: address}} <- interfaces,
            not Multicast.multicast_address?(address),
            link_local?(address) == link_local?(peer),
            do: address

      case Enum.sort(candidates) do
        [address | _] -> {:ok, address}
        [] -> {:error, :local_address_unavailable}
      end
    else
      nil -> {:error, :interface_unavailable}
      error -> error
    end
  end

  defp usable_source?(address),
    do:
      address not in [{0, 0, 0, 0}, {255, 255, 255, 255}, {0, 0, 0, 0, 0, 0, 0, 0}] and
        not Multicast.multicast_address?(address)

  defp link_local?({first, _, _, _, _, _, _, _}), do: Bitwise.band(first, 0xFFC0) == 0xFE80

  defp ipv4_bytes(address), do: address |> Tuple.to_list() |> :erlang.list_to_binary()

  defp ipv6_bytes(address),
    do: for(segment <- Tuple.to_list(address), into: <<>>, do: <<segment::unsigned-16>>)

  def capabilities(socket) do
    with {:ok, %{family: family}} <- :socket.sockname(socket) do
      metadata =
        if family == :inet,
          do: enabled(socket, @ip, @ip_pktinfo),
          else: enabled(socket, @ipv6, 49)

      %{
        adapter: :socket_native,
        driver: nil,
        family: family,
        platform: :linux,
        runtime: %{otp: :erlang.system_info(:otp_release), erts: :erlang.system_info(:version)},
        constraints: %{minimum_otp: 27, verified_otp: [27, 28], platform: :linux},
        destination: capability(true, metadata),
        interface_index: capability(true, metadata),
        local_address: capability(true, metadata),
        scoped_send: capability(family == :inet6, family == :inet6),
        source_control: capability(true, true),
        memberships: capability(true, true),
        strict_group_filter:
          capability(family == :inet, family == :inet and not enabled(socket, @ip, 49)),
        strict_interface_filter: %{supported: false, enabled: false, reason: :not_implemented}
      }
    end
  end

  defp enabled(socket, level, option),
    do: :socket.getopt_native(socket, {level, option}, :boolean) == {:ok, true}

  defp capability(supported, enabled),
    do: %{
      supported: supported,
      enabled: enabled,
      reason:
        cond do
          not supported -> :family_unsupported
          not enabled -> :disabled
          true -> nil
        end
    }

  defp platform do
    cond do
      :os.type() != {:unix, :linux} ->
        {:error, :native_socket_platform_unsupported}

      List.to_integer(:erlang.system_info(:otp_release)) < 27 ->
        {:error, :native_socket_runtime_unsupported}

      true ->
        :ok
    end
  end
end
