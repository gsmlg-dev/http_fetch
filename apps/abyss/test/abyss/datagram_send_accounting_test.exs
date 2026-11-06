defmodule Abyss.DatagramSendAccountingTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Endpoint
  import Abyss.Test.SendAccountingFixture

  setup do
    capture()
    :ok
  end

  for driver <- [:inet, :socket], family <- [:inet, :inet6], rate <- [0.0, 1.0] do
    test "#{driver} #{family} local sends count once independently of sampling #{rate}" do
      driver = unquote(driver)
      family = unquote(family)
      rate = unquote(rate)
      {peer, destination} = peer(family)
      options = [family, inet_backend: driver, ip: destination.addr]

      {server, capability} =
        endpoint(transport_options: options, connection_telemetry_sample_rate: rate)

      {other, other_capability} =
        endpoint(transport_options: options, connection_telemetry_sample_rate: rate)

      successful_send(server, capability, peer, destination, "payload")
      successful_send(server, capability, peer, destination, <<>>)
      assert_counts(server, 2, 7, 0)
      assert_counts(other, 0, 0, 0)

      close_send_socket(server)
      assert {:ok, ref} = Endpoint.send(capability, destination, "failed")
      assert {:error, :closed} = Endpoint.await(capability, ref, 1000)
      assert_event(server, {:error, :closed}, 6)
      assert {:error, :closed} = Endpoint.await(capability, ref, 1000)
      assert_counts(server, 2, 7, 1)
      assert_counts(other, 0, 0, 0)
      refute_receive {:socket_send_event, ^server, _, _}, 0
      successful_send(other, other_capability, peer, destination, "other")
      assert_counts(other, 1, 5, 0)
      assert_counts(server, 2, 7, 1)
    end
  end

  test "unsupported scoped GenUDP socket destination is not an attempted socket send" do
    {_, destination} = peer(:inet6)

    {server, capability} =
      endpoint(transport_options: [:inet6, inet_backend: :socket, ip: destination.addr])

    assert {:ok, ref} = Endpoint.send(capability, Map.put(destination, :scope_id, 1), "rejected")
    error = {:error, {:unsupported_capability, :scoped_sockaddr_send, :socket}}
    assert ^error = Endpoint.await(capability, ref, 1000)
    assert_counts(server, 0, 0, 0)
    refute_receive {:socket_send_event, ^server, _, _}, 0
  end

  test "wait timeout and queue rejection do not count before accepted send completes once" do
    key = {Abyss.Test.SendAccountingBlockingTransport, :owner}
    :persistent_term.put(key, self())
    on_exit(fn -> :persistent_term.erase(key) end)
    {peer, destination} = peer(:inet)

    {server, capability} =
      endpoint(
        transport_module: Abyss.Test.SendAccountingBlockingTransport,
        dispatcher_max_queue: 1
      )

    assert {:ok, ref} = Endpoint.send(capability, destination, "late")
    assert_receive {:accounting_send_blocked, writer}, 1000
    assert {:unknown, ^ref} = Endpoint.await(capability, ref, 0)
    assert {:error, :queue_limit} = Endpoint.send(capability, destination, "rejected")
    assert_counts(server, 0, 0, 0)
    refute_receive {:socket_send_event, ^server, _, _}, 0
    send(writer, :complete_send)
    assert {:ok, {_, _, "late"}} = :gen_udp.recv(peer, 0, 1000)
    assert_event(server, :ok, 4)
    wait_for_completion(server, System.monotonic_time(:millisecond) + 1000)
    assert {:ok, at} = Endpoint.await(capability, ref, 1000)
    assert {:ok, ^at} = Endpoint.await(capability, ref, 1000)
    assert_counts(server, 1, 4, 0)
    refute_receive {:socket_send_event, ^server, _, _}, 0
  end

  defp wait_for_completion(server, deadline) do
    {:ok, info} = Endpoint.info(server)

    if info.egress.entries != 0 do
      assert System.monotonic_time(:millisecond) < deadline
      wait_for_completion(server, deadline)
    end
  end
end
