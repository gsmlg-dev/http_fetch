defmodule Abyss.Transport.UDP.NativeTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  alias Abyss.Datagram
  alias Abyss.Transport.UDP.Native

  if :os.type() != {:unix, :linux} do
    @moduletag :skip
  end

  test "nonblocking receive uses owner references and actual IPv4 metadata" do
    socket = native_socket(ip: {0, 0, 0, 0})
    peer = udp_peer(:inet)
    {:ok, {_, port}} = Native.sockname(socket)
    operation = make_ref()
    assert {:select, {:select_info, :recvmsg, ^operation}} = Native.arm(socket, operation)
    assert :ok = :gen_udp.send(peer, {127, 0, 0, 2}, port, <<>>)
    assert_receive {:"$socket", ^socket, :select, ^operation}
    assert {:ok, message} = Native.arm(socket, make_ref())

    assert {:ok,
            %Datagram{
              payload: <<>>,
              destination: {127, 0, 0, 2},
              local_address: {127, 0, 0, 2},
              interface_index: index,
              hop_limit: 64,
              local_endpoint: {{0, 0, 0, 0}, ^port}
            }} = Native.datagram(message, context(socket))

    assert index > 0
    assert Enum.any?(message.ctrl, &(&1.type == :pktinfo))

    assert %{
             adapter: :socket_native,
             driver: nil,
             family: :inet,
             destination: %{supported: true, enabled: true},
             source_control: %{supported: true}
           } = Native.capabilities(socket)
  end

  test "IPv4 strict reply retains original wildcard socket port and packet source address" do
    socket = native_socket(ip: {0, 0, 0, 0})
    peer = udp_peer(:inet)
    {:ok, {_, port}} = Native.sockname(socket)
    assert :ok = :gen_udp.send(peer, {127, 0, 0, 2}, port, "request")
    datagram = receive_datagram(socket)
    assert :ok = Native.send(socket, {:native_reply, datagram}, "reply")
    assert {:ok, {{127, 0, 0, 2}, ^port, "reply"}} = :gen_udp.recv(peer, 0, 1000)
  end

  test "per-packet source controls do not mutate shared socket settings" do
    socket = native_socket(ip: {0, 0, 0, 0})
    peer = udp_peer(:inet)
    {:ok, {_, port}} = Native.sockname(socket)

    for address <- [{127, 0, 0, 1}, {127, 0, 0, 2}] do
      assert :ok = :gen_udp.send(peer, address, port, "same")
    end

    first = receive_datagram(socket)
    second = receive_datagram(socket)
    assert first.destination == {127, 0, 0, 1}
    assert second.destination == {127, 0, 0, 2}
    assert :ok = Native.send(socket, {:native_reply, first}, "first")
    assert :ok = Native.send(socket, {:native_reply, second}, "second")
    assert {:ok, {{127, 0, 0, 1}, ^port, "first"}} = :gen_udp.recv(peer, 0, 1000)
    assert {:ok, {{127, 0, 0, 2}, ^port, "second"}} = :gen_udp.recv(peer, 0, 1000)
    assert {:ok, {{0, 0, 0, 0}, ^port}} = Native.sockname(socket)
  end

  test "IPv6 native metadata and strict replies preserve original endpoint" do
    socket = native_socket([:inet6, ip: {0, 0, 0, 0, 0, 0, 0, 0}])
    peer = udp_peer(:inet6)
    address = {0, 0, 0, 0, 0, 0, 0, 1}
    {:ok, {_, port}} = Native.sockname(socket)
    assert :ok = :gen_udp.send(peer, address, port, "request")
    datagram = receive_datagram(socket)

    assert %Datagram{
             peer: %{family: :inet6, scope_id: 0},
             destination: ^address,
             local_address: ^address,
             interface_index: index,
             hop_limit: 64
           } = datagram

    assert index > 0
    assert :ok = Native.send(socket, {:native_reply, datagram}, <<>>)
    assert {:ok, {^address, ^port, <<>>}} = :gen_udp.recv(peer, 0, 1000)
  end

  test "same sender payload to two IPv4 groups retains each destination without deduplication" do
    groups = [{239, 255, 71, 1}, {239, 255, 71, 2}]
    socket = native_socket(ip: {0, 0, 0, 0}, reuseaddr: true)
    peer = udp_peer(:inet, multicast_if: {127, 0, 0, 1}, multicast_loop: true)
    {:ok, {_, port}} = Native.sockname(socket)

    for group <- groups,
        do: assert(:ok = Native.setopts(socket, add_membership: {group, {127, 0, 0, 1}}))

    for group <- groups, do: assert(:ok = :gen_udp.send(peer, group, port, "identical"))
    datagrams = [receive_datagram(socket), receive_datagram(socket)]
    assert Enum.map(datagrams, & &1.destination) == groups

    assert [
             %Datagram{
               payload: "identical",
               local_address: {127, 0, 0, 1},
               interface_index: index
             },
             %Datagram{
               payload: "identical",
               local_address: {127, 0, 0, 1},
               interface_index: index
             }
           ] = datagrams

    for group <- groups,
        do: assert(:ok = Native.setopts(socket, drop_membership: {group, {127, 0, 0, 1}}))
  end

  test "cancelling a pending receive prevents readiness for the retired operation" do
    socket = native_socket(ip: {127, 0, 0, 1})
    operation = make_ref()
    assert {:select, select_info} = Native.arm(socket, operation)
    assert :ok = Native.cancel(socket, select_info)
    peer = udp_peer(:inet)
    {:ok, {_, port}} = Native.sockname(socket)
    assert :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, "fresh")
    datagram = receive_datagram(socket)
    assert datagram.payload == "fresh"
    refute_receive {:"$socket", ^socket, :select, ^operation}, 10
  end

  test "actual receive truncation never presents a complete datagram" do
    socket = native_socket(ip: {127, 0, 0, 1})
    peer = udp_peer(:inet)
    {:ok, {_, port}} = Native.sockname(socket)
    assert :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, "long-payload")
    assert {:ok, message} = :socket.recvmsg(socket, 2, 4096, [], 1000)
    assert :trunc in message.flags
    assert {:error, :payload_truncated} = Native.datagram(message, context(socket))
    assert :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, "complete")
    assert {:ok, message} = :socket.recvmsg(socket, 65_535, 1, [], 1000)
    assert :ctrunc in message.flags

    assert {:ok,
            %Datagram{
              payload: "complete",
              destination: nil,
              interface_index: nil,
              local_address: nil
            }} = Native.datagram(message, context(socket))
  end

  test "missing or unsafe strict metadata rejects without a routed fallback" do
    socket = native_socket(ip: {127, 0, 0, 1})
    peer = udp_peer(:inet)
    {:ok, {_, port}} = Native.sockname(socket)
    assert :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, "request")
    datagram = receive_datagram(socket)

    for invalid <- [
          %{datagram | local_address: nil},
          %{datagram | local_address: {239, 1, 2, 3}},
          %{datagram | interface_index: 0},
          %{datagram | flags: [:ctrunc]}
        ] do
      assert {:error, :missing_reply_metadata} =
               Native.send(socket, {:native_reply, invalid}, "reply")
    end

    assert {:error, :timeout} = :gen_udp.recv(peer, 0, 10)
  end

  test "small retained native payload and controls release parent receive buffers" do
    parent = :binary.copy(<<1>>, 65_535)
    payload = binary_part(parent, 0, 128)
    data = binary_part(parent, 0, 256)
    assert :binary.referenced_byte_size(payload) > byte_size(payload)
    context = %{endpoint_id: :endpoint, generation: make_ref()}

    message = %{
      addr: %{family: :inet, addr: {127, 0, 0, 1}, port: 1},
      iov: [payload],
      ctrl: [%{level: 1, type: 99, data: data}],
      flags: []
    }

    assert {:ok, datagram} = Native.datagram(message, context)
    assert datagram.payload == payload
    assert :binary.referenced_byte_size(datagram.payload) == byte_size(payload)
    assert [%{data: control}] = datagram.ancillary
    assert control == data
    assert :binary.referenced_byte_size(control) == byte_size(data)
  end

  test "host buffer hints remain distinct from native receive and kernel buffers" do
    socket = native_socket(ip: {127, 0, 0, 1}, buffer: 65_536, recbuf: 65_536, sndbuf: 65_536)
    assert {:ok, {{127, 0, 0, 1}, _port}} = Native.sockname(socket)
  end

  test "unsupported options fail startup and leave no open native socket" do
    assert {:error, {:unsupported_native_option, {:inet_backend, :socket}}} =
             Native.listen(0, inet_backend: :socket)

    assert {:error, {:unsupported_native_option, {:unknown, true}}} =
             Native.listen(0, unknown: true)

    assert {:error, :invalid_native_destination} = Native.listen(0, ip: {999, 0, 0, 1})
    socket = native_socket(ip: {127, 0, 0, 1})
    assert {:error, :native_receive_requires_arm} = Native.setopts(socket, active: :once)
  end

  defp native_socket(options) do
    {:ok, socket} = Native.listen(0, options)
    on_exit(fn -> Native.close(socket) end)
    socket
  end

  defp udp_peer(family, options \\ []) do
    address = if family == :inet, do: {127, 0, 0, 1}, else: {0, 0, 0, 0, 0, 0, 0, 1}

    {:ok, socket} =
      :gen_udp.open(0, [family, :binary, {:active, false}, {:ip, address}] ++ options)

    on_exit(fn -> :gen_udp.close(socket) end)
    socket
  end

  defp receive_datagram(socket) do
    {:ok, message} = :socket.recvmsg(socket, 65_535, 4096, [], 1000)
    {:ok, datagram} = Native.datagram(message, context(socket))
    datagram
  end

  defp context(socket) do
    {:ok, local} = Native.sockname(socket)
    %{endpoint_id: :native_test, generation: make_ref(), local_endpoint: local}
  end
end
