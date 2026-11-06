defmodule Abyss.ClientTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Client

  setup do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(socket)
    on_exit(fn -> :gen_udp.close(socket) end)
    %{socket: socket, port: port}
  end

  test "send delivers default binary and empty packets", %{socket: socket, port: port} do
    for packet <- ["hello unicast", ""] do
      assert :ok = Client.send({127, 0, 0, 1}, port, packet)
      assert {:ok, {{127, 0, 0, 1}, _, ^packet}} = :gen_udp.recv(socket, 0, 1000)
    end
  end

  test "source selection and an explicit loopback interface deliver packets", %{
    socket: socket,
    port: port
  } do
    assert :ok = Client.send({127, 0, 0, 1}, port, "source", source: {127, 0, 0, 1})
    assert {:ok, {{127, 0, 0, 1}, _, "source"}} = :gen_udp.recv(socket, 0, 1000)

    if :os.type() == {:unix, :linux} do
      assert :ok = Client.send({127, 0, 0, 1}, port, "interface", interface: "lo")
      assert {:ok, {{127, 0, 0, 1}, _, "interface"}} = :gen_udp.recv(socket, 0, 1000)
    end
  end

  test "invalid addresses and explicitly missing interfaces fail before sending" do
    assert {:error, {:invalid_address, :invalid}} = Client.send(:invalid, 49_999, "packet")

    assert {:error, :enodev} =
             Client.send({127, 0, 0, 1}, 49_999, "packet", interface: "abyss-missing")

    assert {:error, {:invalid_port, -1}} = Client.send({127, 0, 0, 1}, -1, "packet")
  end

  test "send and broadcast send failures close every ephemeral socket" do
    before = owned_ports()
    oversized = :binary.copy("a", 70_000)

    for _ <- 1..20 do
      assert {:error, :emsgsize} = Client.send({127, 0, 0, 1}, 49_999, oversized)
      assert {:error, :emsgsize} = Client.broadcast({127, 0, 0, 1}, 49_999, oversized)
    end

    assert owned_ports() == before
  end

  test "request-response and broadcast request-response preserve replies and source" do
    for helper <- [&Client.send_recv/5, &Client.broadcast_send_recv/5] do
      {echo, port} = echo_peer()

      assert {:ok, "echo: request"} =
               helper.({127, 0, 0, 1}, port, "request", 1000, source: {127, 0, 0, 1})

      assert {{127, 0, 0, 1}, "request"} = Task.await(echo)
    end
  end

  test "source bind and local send failures are preserved" do
    assert {:error, :eaddrnotavail} =
             Client.broadcast_send_recv({127, 0, 0, 1}, 49_999, "x", 20, source: {203, 0, 113, 7})

    assert {:error, :emsgsize} =
             Client.broadcast_send_recv({127, 0, 0, 1}, 49_999, :binary.copy("a", 70_000), 20)
  end

  test "a bound silent peer causes exactly a receive timeout", %{port: port} do
    assert {:error, :timeout} = Client.send_recv({127, 0, 0, 1}, port, "silent", 20)
  end

  test "limited and directed broadcast deliver over loopback with explicit egress" do
    if :os.type() == {:unix, :linux} do
      {:ok, receiver} = :gen_udp.open(0, [:binary, active: false, broadcast: true])

      try do
        {:ok, {_, port}} = :inet.sockname(receiver)

        for address <- [{255, 255, 255, 255}, {127, 255, 255, 255}] do
          payload = :erlang.term_to_binary(address)

          assert :ok =
                   Client.broadcast(address, port, payload,
                     source: {127, 0, 0, 1},
                     interface: "lo"
                   )

          assert {:ok, {{127, 0, 0, 1}, _, ^payload}} = :gen_udp.recv(receiver, 0, 1000)
        end
      after
        :gen_udp.close(receiver)
      end
    else
      assert {:error, :explicit_device_binding_not_supported} =
               Client.broadcast({255, 255, 255, 255}, 49_999, "packet",
                 interface: loopback_interface()
               )
    end
  end

  test "multicast subscription actually receives on a selected interface" do
    parent = self()
    group = {239, 255, 42, 21}

    subscriber =
      Task.async(fn ->
        Client.subscribe_broadcast(group, 0, 50,
          membership_interface: {127, 0, 0, 1},
          on_ready: fn endpoint -> send(parent, {:subscribed, endpoint}) end
        )
      end)

    assert_receive {:subscribed, {_, port}}, 1000

    assert :ok =
             Client.broadcast(group, port, "multicast",
               source: {127, 0, 0, 1},
               loopback: true,
               ttl: 1
             )

    assert {:ok, ["multicast"]} = Task.await(subscriber)
  end

  test "subscription with no traffic ends normally and sends no packet", %{socket: socket} do
    assert {:ok, []} = Client.subscribe_broadcast({127, 0, 0, 1}, 0, 10)
    assert {:error, :timeout} = :gen_udp.recv(socket, 0, 10)

    assert {:ok, []} =
             Client.subscribe_broadcast({239, 255, 42, 22}, 0, 10,
               membership_interface: {127, 0, 0, 1}
             )
  end

  test "resolves loopback and rejects nonexistent interfaces" do
    assert {:ok, {127, 0, 0, 1}} = Client.resolve_interface_ip(loopback_interface())
    assert {:error, :enodev} = Client.resolve_interface_ip("abyss-missing")
  end

  describe "telemetry" do
    setup do
      id = "client-test-#{inspect(self())}"

      events =
        for kind <- [:send, :send_recv, :subscribe],
            phase <- [:start, :stop, :exception],
            do: [:abyss, :client, kind, phase]

      :ok = :telemetry.attach_many(id, events, &__MODULE__.notify/4, self())
      on_exit(fn -> :telemetry.detach(id) end)
      :ok
    end

    test "send retains legacy metadata and reports success after actual local send", %{
      socket: socket,
      port: port
    } do
      assert :ok = Client.send({127, 0, 0, 1}, port, "telemetry")
      assert {:ok, {_, _, "telemetry"}} = :gen_udp.recv(socket, 0, 1000)
      assert_receive {:event, [:abyss, :client, :send, :start], %{}, metadata}
      assert metadata == %{host: {127, 0, 0, 1}, port: port, size: 9, type: :unicast}
      assert_receive {:event, [:abyss, :client, :send, :stop], %{duration: duration}, _}
      assert is_integer(duration) and duration >= 0
    end

    test "explicit interface errors emit exceptions" do
      assert {:error, :enodev} =
               Client.send({127, 0, 0, 1}, 49_999, "packet", interface: "abyss-missing")

      assert_receive {:event, [:abyss, :client, :send, :start], %{}, _}

      assert_receive {:event, [:abyss, :client, :send, :exception], %{duration: duration},
                      %{reason: :enodev}}

      assert is_integer(duration)
    end

    test "broadcast preserves its metadata type", %{port: port} do
      assert :ok = Client.broadcast({127, 0, 0, 1}, port, "packet")
      assert_receive {:event, [:abyss, :client, :send, :start], %{}, %{type: :broadcast}}
      assert_receive {:event, [:abyss, :client, :send, :stop], _, _}
    end

    test "request-response success records response size" do
      {echo, port} = echo_peer()
      assert {:ok, "echo: packet"} = Client.send_recv({127, 0, 0, 1}, port, "packet", 1000)
      Task.await(echo)

      assert_receive {:event, [:abyss, :client, :send_recv, :start], %{},
                      %{type: :request_response, timeout: 1000}}

      assert_receive {:event, [:abyss, :client, :send_recv, :stop], %{response_size: 12}, _}
    end

    test "expected receive timeout emits an exception", %{port: port} do
      assert {:error, :timeout} = Client.send_recv({127, 0, 0, 1}, port, "packet", 10)
      assert_receive {:event, [:abyss, :client, :send_recv, :exception], _, %{reason: :timeout}}
    end
  end

  def notify(event, measurements, metadata, pid),
    do: send(pid, {:event, event, measurements, metadata})

  defp loopback_interface, do: if(:os.type() == {:unix, :darwin}, do: "lo0", else: "lo")

  defp owned_ports,
    do:
      Enum.filter(Port.list(), &(:erlang.port_info(&1, :connected) == {:connected, self()}))
      |> Enum.sort()

  defp echo_peer do
    parent = self()

    task =
      Task.async(fn ->
        {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])

        try do
          {:ok, {_, port}} = :inet.sockname(socket)
          send(parent, {:echo_ready, port})
          {:ok, {address, port, data}} = :gen_udp.recv(socket, 0, 1000)
          :ok = :gen_udp.send(socket, address, port, "echo: " <> data)
          {address, data}
        after
          :gen_udp.close(socket)
        end
      end)

    assert_receive {:echo_ready, port}, 1000
    {task, port}
  end
end
