defmodule Abyss.ClientRegressionTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  if :os.type() != {:unix, :linux} do
    @moduletag skip:
                 "Linux reference socket/interface tests; use the portable client and prepared platform matrix"
  end

  alias Abyss.Client

  test "explicit nonexistent interface does not fall back" do
    assert {:error, :enodev} =
             Client.send({127, 0, 0, 1}, 49_999, "packet", interface: "abyss-missing")

    assert {:error, :enodev} =
             Client.multicast_query({239, 255, 42, 1}, 49_999, "packet", 1,
               interface: "abyss-missing"
             )
  end

  test "multicast send failure is propagated before collection" do
    assert {:error, :emsgsize} =
             Client.multicast_query({239, 255, 42, 1}, 49_999, :binary.copy("a", 65_536), 1,
               source: {127, 0, 0, 1}
             )
  end

  test "subscription collectors bound count, bytes, and retain empty datagrams" do
    assert {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    assert {:ok, {_, port}} = :inet.sockname(peer)
    :gen_udp.close(peer)
    parent = self()

    task =
      Task.async(fn ->
        Client.subscribe_broadcast({127, 0, 0, 1}, port, 1000,
          source: {127, 0, 0, 1},
          max_responses: 1,
          on_ready: fn endpoint -> send(parent, {:ready, endpoint}) end
        )
      end)

    assert_receive {:ready, _}, 500
    assert {:ok, sender} = :gen_udp.open(0, [:binary])

    try do
      assert :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, "")
      assert :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, "overflow")
      assert {:error, {:response_limit, :count}, [""]} = Task.await(task)
    after
      :gen_udp.close(sender)
    end
  end

  test "invalid deadlines and collection bounds are rejected" do
    assert {:error, {:invalid_option, :timeout, -1}} =
             Client.subscribe_broadcast({127, 0, 0, 1}, 0, -1)

    assert {:error, {:invalid_option, :max_responses, 0}} =
             Client.subscribe_broadcast({127, 0, 0, 1}, 0, 0, max_responses: 0)
  end

  test "collection byte overflow preserves prior results and closed receive is an error" do
    parent = self()

    task =
      Task.async(fn ->
        Client.subscribe_broadcast({127, 0, 0, 1}, 0, 1000,
          max_response_bytes: 3,
          on_ready: fn endpoint -> send(parent, {:ready_bytes, endpoint}) end
        )
      end)

    assert_receive {:ready_bytes, {_, port}}, 500
    {:ok, sender} = :gen_udp.open(0, [:binary])

    try do
      assert :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, "abc")
      assert :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, "d")
      assert {:error, {:response_limit, :bytes}, ["abc"]} = Task.await(task)
    after
      :gen_udp.close(sender)
    end

    assert {:error, :closed, []} =
             Client.subscribe_broadcast({127, 0, 0, 1}, 0, 1000,
               on_ready: fn {_, port} ->
                 # The client owns this temporary socket; identify its own port deterministically.
                 socket =
                   Enum.find(Port.list(), fn socket ->
                     :inet.sockname(socket) == {:ok, {{0, 0, 0, 0}, port}}
                   end)

                 :gen_udp.close(socket)
               end
             )
  end

  test "multicast query receives unicast responses without joining sender socket" do
    group = {239, 255, 42, 11}

    {:ok, peer} =
      :gen_udp.open(0, [
        :binary,
        active: false,
        reuseaddr: true,
        add_membership: {group, {127, 0, 0, 1}}
      ])

    try do
      {:ok, {_, port}} = :inet.sockname(peer)

      task =
        Task.async(fn ->
          Client.multicast_query(group, port, "query", 50, source: {127, 0, 0, 1}, loopback: true)
        end)

      assert {:ok, {address, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
      assert :ok = :gen_udp.send(peer, address, client_port, "reply")
      assert {:ok, [{{127, 0, 0, 1}, ^port, "reply"}]} = Task.await(task)
    after
      :gen_udp.close(peer)
    end
  end

  test "multicast reply mode binds and joins before sending" do
    group = {239, 255, 42, 12}

    {:ok, peer} =
      :gen_udp.open(0, [
        :binary,
        active: false,
        reuseaddr: true,
        multicast_if: {127, 0, 0, 1},
        multicast_loop: true,
        add_membership: {group, {127, 0, 0, 1}}
      ])

    try do
      {:ok, {_, port}} = :inet.sockname(peer)

      task =
        Task.async(fn ->
          Client.multicast_query(group, port, "query", 50,
            source: {127, 0, 0, 1},
            reply_mode: :multicast,
            loopback: true
          )
        end)

      assert {:ok, {{127, 0, 0, 1}, ^port, "query"}} = :gen_udp.recv(peer, 0, 1000)
      assert :ok = :gen_udp.send(peer, group, port, "group-reply")
      assert {:ok, replies} = Task.await(task)
      assert {{127, 0, 0, 1}, port, "group-reply"} in replies
    after
      :gen_udp.close(peer)
    end
  end

  test "socket backend uses the same bounded multicast query contract" do
    group = {239, 255, 42, 61}

    {:ok, peer} =
      :gen_udp.open(0, [:binary, active: false, add_membership: {group, {127, 0, 0, 1}}])

    try do
      {:ok, {_, port}} = :inet.sockname(peer)

      query =
        Task.async(fn ->
          Client.multicast_query(group, port, "socket-query", 50,
            inet_backend: :socket,
            source: {127, 0, 0, 1}
          )
        end)

      assert {:ok, {address, query_port, "socket-query"}} = :gen_udp.recv(peer, 0, 1000)
      assert :ok = :gen_udp.send(peer, address, query_port, "socket-reply")
      assert {:ok, [{{127, 0, 0, 1}, ^port, "socket-reply"}]} = Task.await(query)
    after
      :gen_udp.close(peer)
    end
  end
end
