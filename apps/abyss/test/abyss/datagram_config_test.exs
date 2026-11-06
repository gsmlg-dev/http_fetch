defmodule Abyss.DatagramConfigTestHandler do
  @behaviour Abyss.DatagramHandler
  @impl true
  def init(_opts, _context), do: {:ok, nil}
  @impl true
  def handle_datagram(_datagram, state), do: {:ok, state, []}
end

defmodule Abyss.DatagramConfigTestDispatcher do
  @behaviour Abyss.DatagramDispatcher
  @impl true
  def init(_context, _opts), do: {:ok, nil}
  @impl true
  def handle_datagram(_peer, _payload, _at, %{state: state}), do: {:ok, state}
end

defmodule Abyss.DatagramConfigTest do
  use ExUnit.Case, async: true

  @moduletag :integration
  alias Abyss.DatagramConfigTestHandler, as: Handler
  alias Abyss.ServerConfig

  test "new handlers do not require dummy legacy modules and default to one receiver" do
    assert %{
             handler_module: nil,
             num_listeners: 1,
             datagram_options: %{
               datagram_handler: Handler,
               execution: :per_datagram,
               io_backend: :gen_udp
             }
           } = ServerConfig.new(datagram_handler: Handler)

    assert %{num_listeners: 100} = ServerConfig.new(handler_module: Abyss.TestHandler)
  end

  test "dispatchers do not require dummy handlers and retain multicast eligibility" do
    assert %{handler_module: nil, datagram_dispatcher: Abyss.DatagramConfigTestDispatcher} =
             ServerConfig.new(
               datagram_dispatcher: Abyss.DatagramConfigTestDispatcher,
               transport_module: Abyss.Transport.UDP.Multicast
             )
  end

  test "rejects ambiguous processing and duplicated receive topologies" do
    for opts <- [
          [handler_module: Abyss.TestHandler],
          [datagram_dispatcher: Abyss.DatagramConfigTestDispatcher],
          [num_listeners: 2],
          [dynamic_listeners: true],
          [datagram_handler: :invalid],
          [datagram_handler: false]
        ] do
      assert_raise ArgumentError, fn ->
        ServerConfig.new(Keyword.merge([datagram_handler: Handler], opts))
      end
    end
  end

  test "keyed execution requires explicit application routing" do
    assert_raise ArgumentError, ~r/explicit route_key/, fn ->
      ServerConfig.new(datagram_handler: Handler, execution: :keyed)
    end

    route = fn datagram -> datagram.payload end

    assert %{datagram_options: %{route_key: ^route}} =
             ServerConfig.new(datagram_handler: Handler, execution: :keyed, route_key: route)

    assert %{datagram_options: %{route_key: {__MODULE__, :route}}} =
             ServerConfig.new(
               datagram_handler: Handler,
               execution: :keyed,
               route_key: {__MODULE__, :route}
             )

    assert_raise ArgumentError, fn ->
      ServerConfig.new(datagram_handler: Handler, route_key: route)
    end
  end

  test "native adapter rejects legacy processing and contradictory driver selection" do
    assert_raise ArgumentError, ~r/native transport requires/, fn ->
      ServerConfig.new(
        handler_module: Abyss.TestHandler,
        transport_module: Abyss.Transport.UDP.Native
      )
    end

    assert_raise ArgumentError, ~r/requires datagram_handler/, fn ->
      ServerConfig.new(handler_module: Abyss.TestHandler, io_backend: :socket_native)
    end

    assert_raise ArgumentError, ~r/inet_backend cannot/, fn ->
      ServerConfig.new(
        datagram_handler: Handler,
        io_backend: :socket_native,
        transport_options: [inet_backend: :socket]
      )
    end

    assert %{
             transport_module: Abyss.Transport.UDP.Native,
             datagram_options: %{io_backend: :socket_native}
           } =
             ServerConfig.new(datagram_handler: Handler, io_backend: :socket_native)
  end

  test "duplicate new options use the same first occurrence throughout selection" do
    config =
      ServerConfig.new(
        datagram_handler: Handler,
        datagram_handler: :invalid,
        io_backend: :gen_udp,
        io_backend: :socket_native
      )

    assert config.transport_module == Abyss.Transport.UDP
    assert config.datagram_options.io_backend == :gen_udp
    assert config.datagram_options.datagram_handler == Handler

    config =
      ServerConfig.new(
        datagram_handler: Handler,
        io_backend: :socket_native,
        io_backend: :gen_udp
      )

    assert config.transport_module == Abyss.Transport.UDP.Native
    assert config.datagram_options.io_backend == :socket_native
  end

  test "new handlers require finite positive egress item and byte bounds" do
    for key <- [:dispatcher_max_queue, :dispatcher_max_queue_bytes],
        invalid <- [:infinity, 0, -1, 1.5] do
      assert_raise ArgumentError, fn ->
        ServerConfig.new([datagram_handler: Handler] ++ [{key, invalid}])
      end
    end
  end

  test "runtime limits are finite, recognized and independently merged" do
    for opts <- [
          [max_keys: :infinity],
          [callback_timeout: 0],
          [max_queue_bytes: -1],
          [max_actions: 1.5],
          [unknown_limit: 1]
        ] do
      assert_raise ArgumentError, fn ->
        ServerConfig.new(datagram_handler: Handler, runtime_options: opts)
      end
    end

    assert_raise ArgumentError, fn ->
      ServerConfig.new(datagram_handler: Handler, runtime_options: %{max_keys: 1})
    end

    config = ServerConfig.new(datagram_handler: Handler, runtime_options: [max_keys: 4])
    assert [max_keys: 4] = config.datagram_options.runtime_options

    assert %{max_keys: 4, callback_timeout: 1000, max_key_queue: 32, max_key_queue_bytes: 262_144} =
             Map.new(ServerConfig.runtime_options(config))

    assert Enum.all?(ServerConfig.runtime_options(config), fn {_, value} ->
             is_integer(value) and value > 0
           end)
  end
end
