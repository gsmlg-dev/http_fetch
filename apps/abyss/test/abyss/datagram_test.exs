defmodule Abyss.DatagramTest do
  use ExUnit.Case, async: true
  alias Abyss.Datagram

  setup do
    %{
      context: %{
        endpoint_id: "endpoint",
        generation: make_ref(),
        local_endpoint: {{0, 0, 0, 0}, 4000}
      }
    }
  end

  test "empty GenUDP datagrams keep wildcard binding and unknown packet metadata", %{
    context: context
  } do
    before_receive = System.monotonic_time(:microsecond)
    datagram = Datagram.from_gen_udp({{127, 0, 0, 1}, 1000, <<>>}, context)
    after_receive = System.monotonic_time(:microsecond)

    assert %Datagram{
             payload: <<>>,
             peer: %{family: :inet, addr: {127, 0, 0, 1}, port: 1000},
             local_endpoint: {{0, 0, 0, 0}, 4000},
             destination: nil,
             interface_index: nil,
             local_address: nil,
             ancillary: [],
             flags: []
           } = datagram

    assert datagram.generation == context.generation
    assert datagram.received_at >= before_receive and datagram.received_at <= after_receive
  end

  test "preserves actual GenUDP ancillary independent of telemetry configuration", %{
    context: context
  } do
    controls = [ttl: 42, tos: 16, unknown_control: <<1, 2>>]
    context = Map.put(context, :received_at, 123)
    received = {{127, 0, 0, 1}, 1000, controls, "packet"}

    assert %Datagram{hop_limit: 42, traffic_class: 16, ancillary: ^controls, destination: nil} =
             Datagram.from_gen_udp(received, context)

    assert Datagram.from_gen_udp(received, Map.put(context, :telemetry_sample_rate, 0)) ==
             Datagram.from_gen_udp(received, Map.put(context, :telemetry_sample_rate, 1))
  end

  test "native packet info distinguishes group destination from unicast local address", %{
    context: context
  } do
    controls = [
      %{
        level: :ip,
        type: :pktinfo,
        value: %{addr: {239, 1, 2, 3}, spec_dst: {192, 0, 2, 1}, ifindex: 7}
      }
    ]

    message = %{
      addr: %{family: :inet, addr: {192, 0, 2, 2}, port: 1000},
      iov: ["a", "b"],
      ctrl: controls,
      flags: []
    }

    assert %Datagram{
             payload: "ab",
             destination: {239, 1, 2, 3},
             local_address: {192, 0, 2, 1},
             interface_index: 7,
             ancillary: ^controls
           } =
             Datagram.from_native(message, context)
  end

  test "native IPv6 peer scope survives and group address is never a reply source", %{
    context: context
  } do
    group = {0xFF02, 0, 0, 0, 0, 0, 0, 1}
    peer = %{family: :inet6, addr: {0xFE80, 0, 0, 0, 0, 0, 0, 2}, port: 1000, scope_id: 7}

    message = %{
      addr: peer,
      iov: [<<>>],
      ctrl: [%{level: :ipv6, type: :pktinfo, value: %{addr: group, ifindex: 7}}]
    }

    assert %Datagram{peer: ^peer, destination: ^group, interface_index: 7, local_address: nil} =
             Datagram.from_native(message, context)
  end

  test "truncated control data preserves raw controls but yields unknown metadata", %{
    context: context
  } do
    controls = [
      %{
        level: :ip,
        type: :pktinfo,
        value: %{addr: {239, 1, 2, 3}, spec_dst: {192, 0, 2, 1}, ifindex: 7}
      }
    ]

    message = %{
      addr: %{family: :inet, addr: {192, 0, 2, 2}, port: 1000},
      iov: ["packet"],
      ctrl: controls,
      flags: [:ctrunc]
    }

    assert %Datagram{
             destination: nil,
             local_address: nil,
             interface_index: nil,
             ancillary: ^controls,
             flags: [:ctrunc]
           } = Datagram.from_native(message, context)
  end
end
