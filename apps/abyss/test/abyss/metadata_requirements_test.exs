defmodule Abyss.MetadataRequirementsHandler do
  @behaviour Abyss.DatagramHandler
  def init(owner, _context), do: {:ok, owner}

  def handle_datagram(datagram, owner) do
    send(owner, {:delivered, datagram})
    {:ok, owner, [{:reply, datagram.payload}]}
  end
end

defmodule Abyss.MetadataRequirementsTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Endpoint
  alias Abyss.ServerConfig

  test "unavailable required capability fails startup and releases bound port" do
    {:ok, probe} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(probe)
    :gen_udp.close(probe)
    previous = Process.flag(:trap_exit, true)

    try do
      assert {:error, _} =
               Endpoint.start_link(options(port, required_capabilities: [:destination]))

      assert {:ok, socket} = :gen_udp.open(port, [:binary, active: false, ip: {127, 0, 0, 1}])
      :gen_udp.close(socket)
    after
      Process.flag(:trap_exit, previous)
    end
  end

  test "missing metadata drops before application admission with measured reason" do
    {:ok, endpoint} = Endpoint.start_link(options(0, required_metadata: [:destination]))
    {:ok, {_, port}} = Endpoint.local_endpoint(endpoint)
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false])
    tag = make_ref()
    owner = self()
    event = [:abyss, :datagram, :dropped]

    :ok =
      :telemetry.attach(
        tag,
        event,
        fn _event, measurements, metadata, _ ->
          send(owner, {:drop, measurements, metadata})
        end,
        nil
      )

    try do
      :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, "missing")
      assert_receive {:drop, _, %{reason: {:missing_metadata, [:destination]}}}, 1000
      refute_receive {:delivered, _}, 20
      assert {:ok, %{dropped: 1}} = Endpoint.info(endpoint)
    after
      :telemetry.detach(tag)
      :gen_udp.close(peer)
      Endpoint.stop(endpoint, 100)
    end
  end

  test "native required metadata reaches application and strict-capability rejection is explicit" do
    if :os.type() == {:unix, :linux} do
      {:ok, endpoint} =
        Endpoint.start_link(
          options(0,
            io_backend: :socket_native,
            required_capabilities: [:destination, :interface_index, :source_control],
            required_metadata: [:destination, :interface_index, :local_address]
          )
        )

      {:ok, {_, port}} = Endpoint.local_endpoint(endpoint)
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false])

      try do
        :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, <<>>)
        assert_receive {:delivered, %{destination: {127, 0, 0, 1}, interface_index: index}}, 1000
        assert index > 0
        assert {:ok, {_, ^port, <<>>}} = :gen_udp.recv(peer, 0, 1000)
      after
        :gen_udp.close(peer)
        Endpoint.stop(endpoint, 100)
      end
    end
  end

  test "unsupported scoped IPv6 capability on IPv4 has a family reason" do
    {:ok, endpoint} = Endpoint.start_link(options(0, []))

    try do
      assert {:ok,
              %{scoped_send: %{supported: false, enabled: false, reason: :family_unsupported}}} =
               Endpoint.capabilities(endpoint)
    after
      Endpoint.stop(endpoint, 100)
    end
  end

  test "unknown requirement and requirements on legacy configuration reject early" do
    assert_raise ArgumentError, fn ->
      ServerConfig.new(options(0, required_metadata: [:invented]))
    end

    assert_raise ArgumentError, fn ->
      ServerConfig.new(handler_module: nil, required_metadata: [:destination])
    end
  end

  defp options(port, more) do
    Keyword.merge(
      [
        datagram_handler: Abyss.MetadataRequirementsHandler,
        handler_options: self(),
        port: port,
        transport_options: [ip: {127, 0, 0, 1}]
      ],
      more
    )
  end
end
