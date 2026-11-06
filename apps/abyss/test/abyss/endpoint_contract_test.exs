defmodule Abyss.EndpointContractTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  alias Abyss.Datagram
  alias Abyss.Dispatcher.SendCapability
  alias Abyss.Dispatcher.Writer
  alias Abyss.Endpoint

  setup do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, peer_port}} = :inet.sockname(peer)
    {:ok, local_endpoint} = :inet.sockname(socket)
    generation = make_ref()

    writer =
      start_supervised!(
        {Writer,
         socket: socket,
         transport: Abyss.Transport.UDP,
         owner: self(),
         generation: generation,
         max_queue: 2,
         max_bytes: 1024}
      )

    capability = %SendCapability{writer: writer, generation: generation}

    on_exit(fn ->
      :gen_udp.close(socket)
      :gen_udp.close(peer)
    end)

    %{
      capability: capability,
      peer: peer,
      destination: %{family: :inet, addr: {127, 0, 0, 1}, port: peer_port},
      local_endpoint: local_endpoint
    }
  end

  test "send admits complete empty payloads and await reports local completion", context do
    assert {:ok, ref} = Endpoint.send(context.capability, context.destination, <<>>)
    assert {:ok, completed_at} = Endpoint.await(context.capability, ref)
    assert is_integer(completed_at)
    assert {:ok, {{127, 0, 0, 1}, _source_port, <<>>}} = :gen_udp.recv(context.peer, 0, 1000)
  end

  test "ordinary reply uses the observed peer and original source port", context do
    datagram =
      Datagram.from_gen_udp({context.destination.addr, context.destination.port, "request"}, %{
        endpoint_id: :endpoint,
        generation: context.capability.generation,
        local_endpoint: context.local_endpoint
      })

    assert {:ok, ref} = Endpoint.reply(context.capability, datagram, "reply")
    assert {:ok, _} = Endpoint.await(context.capability, ref)
    {_, source_port} = context.local_endpoint
    assert {:ok, {{127, 0, 0, 1}, ^source_port, "reply"}} = :gen_udp.recv(context.peer, 0, 1000)
  end

  test "generation mismatches and invalid destinations reject before sending", context do
    stale = %{context.capability | generation: make_ref()}
    assert {:error, :stale_generation} = Endpoint.send(stale, context.destination, "stale")

    assert {:error, :invalid_destination} =
             Endpoint.send(context.capability, %{port: 10}, "invalid")

    assert {:error, :invalid_destination} =
             Endpoint.send(context.capability, %{context.destination | family: :inet6}, "invalid")

    assert {:error, :invalid_destination} =
             Endpoint.send(
               context.capability,
               %{context.destination | addr: {999, 0, 0, 1}},
               "invalid"
             )

    assert {:error, :timeout} = :gen_udp.recv(context.peer, 0, 10)
  end

  test "GenUDP strict reply fails explicitly even when metadata is supplied", context do
    datagram =
      Datagram.from_gen_udp({context.destination.addr, context.destination.port, "request"}, %{
        endpoint_id: :endpoint,
        generation: context.capability.generation
      })

    datagram = %{datagram | local_address: {127, 0, 0, 1}, interface_index: 1}

    assert {:error, :strict_reply_unsupported} =
             Endpoint.reply(context.capability, datagram, "reply", :strict)

    assert {:error, :stale_generation} =
             Endpoint.reply(context.capability, %{datagram | generation: make_ref()}, "reply")

    assert {:error, :timeout} = :gen_udp.recv(context.peer, 0, 10)
  end

  test "native strict reply rejects missing metadata before admission", context do
    capability = Map.put(context.capability, :io_backend, :socket_native)

    datagram =
      Datagram.from_gen_udp({context.destination.addr, context.destination.port, "request"}, %{
        endpoint_id: :endpoint,
        generation: capability.generation
      })

    assert {:error, :missing_reply_metadata} =
             Endpoint.reply(capability, datagram, "reply", :strict)
  end
end
