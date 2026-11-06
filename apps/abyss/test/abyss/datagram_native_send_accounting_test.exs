defmodule Abyss.DatagramNativeSendAccountingTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Endpoint
  import Abyss.Test.SendAccountingFixture

  if :os.type() != {:unix, :linux}, do: @moduletag(:skip)

  setup do
    capture()
    :ok
  end

  for family <- [:inet, :inet6], rate <- [0.0, 1.0] do
    test "native #{family} ordinary and strict outcomes count payload bytes once with sampling #{rate}" do
      family = unquote(family)
      rate = unquote(rate)
      {peer, destination} = peer(family)
      options = [family, ip: destination.addr]

      config = [
        io_backend: :socket_native,
        transport_options: options,
        connection_telemetry_sample_rate: rate
      ]

      {server, capability} = endpoint(config)
      {other, other_capability} = endpoint(config)
      successful_send(server, capability, peer, destination, "payload")
      successful_send(server, capability, peer, destination, <<>>)
      assert_counts(server, 2, 7, 0)
      assert_counts(other, 0, 0, 0)

      {:ok, {_, port}} = Endpoint.local_endpoint(server)
      assert :ok = :gen_udp.send(peer, destination.addr, port, "request")
      assert_receive {:accounting_datagram, datagram}, 1000
      assert datagram.local_address == destination.addr
      assert datagram.interface_index > 0

      for payload <- ["strict", <<>>] do
        assert {:ok, ref} = Endpoint.reply(capability, datagram, payload, :strict)
        assert {:ok, at} = Endpoint.await(capability, ref, 1000)
        address = destination.addr
        assert {:ok, {^address, ^port, ^payload}} = :gen_udp.recv(peer, 0, 1000)
        assert_event(server, :ok, byte_size(payload))
        assert {:ok, ^at} = Endpoint.await(capability, ref, 1000)
      end

      assert_counts(server, 4, 13, 0)

      assert {:error, :missing_reply_metadata} =
               Endpoint.reply(capability, %{datagram | local_address: nil}, "rejected", :strict)

      assert {:ok, ref} = Endpoint.send(capability, %{destination | port: 0}, "failed")
      assert {:error, :einval} = Endpoint.await(capability, ref, 1000)
      assert_event(server, {:error, :einval}, 6)
      assert {:error, :einval} = Endpoint.await(capability, ref, 1000)
      assert_counts(server, 4, 13, 1)
      assert_counts(other, 0, 0, 0)
      refute_receive {:socket_send_event, ^server, _, _}, 0
      successful_send(other, other_capability, peer, destination, "other")
      assert_counts(other, 1, 5, 0)
      assert_counts(server, 4, 13, 1)
    end
  end

  test "native transport validation never records a nonexistent send attempt" do
    {_, destination} = peer(:inet)
    {server, capability} = endpoint(io_backend: :socket_native)

    assert {:error, :invalid_destination} =
             Endpoint.send(capability, %{destination | addr: {999, 0, 0, 1}}, "rejected")

    assert_counts(server, 0, 0, 0)
    refute_receive {:socket_send_event, ^server, _, _}, 0
  end
end
