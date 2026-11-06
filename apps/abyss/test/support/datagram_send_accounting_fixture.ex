defmodule Abyss.Test.SendAccountingHandler do
  @moduledoc "Observed datagrams for public send-accounting regressions."
  @behaviour Abyss.DatagramHandler
  def init(options, _context), do: {:ok, options[:owner]}

  def handle_datagram(datagram, owner) do
    send(owner, {:accounting_datagram, datagram})
    {:ok, owner, []}
  end
end

defmodule Abyss.Test.SendAccountingBlockingTransport do
  @moduledoc "Real GenUDP sends gated by an explicit test completion barrier."
  alias Abyss.Transport.UDP
  defdelegate listen(port, options), to: UDP
  defdelegate sockname(socket), to: UDP
  defdelegate setopts(socket, options), to: UDP
  defdelegate close(socket), to: UDP

  def send(socket, ip, port, payload) do
    owner = :persistent_term.get({__MODULE__, :owner})
    send(owner, {:accounting_send_blocked, self()})
    receive do: (:complete_send -> :ok)
    UDP.send(socket, ip, port, payload)
  end
end

defmodule Abyss.Test.SendAccountingFixture do
  @moduledoc "Endpoint, peer and actual-send observations shared by accounting regressions."
  import ExUnit.Assertions
  import ExUnit.Callbacks
  alias Abyss.{Endpoint, Telemetry}

  def capture do
    handler = make_ref()
    :ok = :telemetry.attach(handler, [:abyss, :datagram, :send], &__MODULE__.event/4, self())
    on_exit(fn -> :telemetry.detach(handler) end)
  end

  def event(_event, measurements, metadata, owner),
    do: send(owner, {:socket_send_event, metadata.server_id, measurements, metadata})

  def endpoint(options \\ []) do
    {:ok, server} =
      Endpoint.start_link(
        Keyword.merge(
          [
            datagram_handler: Abyss.Test.SendAccountingHandler,
            handler_options: [owner: self()],
            port: 0,
            transport_options: [ip: {127, 0, 0, 1}]
          ],
          options
        )
      )

    Process.unlink(server)
    on_exit(fn -> if Process.alive?(server), do: Endpoint.stop(server, 100) end)
    {:ok, capability} = Endpoint.capability(server)
    {server, capability}
  end

  def peer(family) do
    address = if family == :inet, do: {127, 0, 0, 1}, else: {0, 0, 0, 0, 0, 0, 0, 1}
    {:ok, peer} = :gen_udp.open(0, [family, :binary, active: false, ip: address])
    on_exit(fn -> :gen_udp.close(peer) end)
    {:ok, {_, port}} = :inet.sockname(peer)
    {peer, %{family: family, addr: address, port: port}}
  end

  def close_send_socket(server) do
    [listener] = Abyss.Listener.for_server(server)
    :ok = :sys.suspend(listener)
    on_exit(fn -> if Process.alive?(listener), do: :sys.resume(listener) end)
    %{listener_socket: socket} = :sys.get_state(listener)
    assert Telemetry.socket_scope(socket) == server
    :ok = :gen_udp.close(socket)
  end

  def successful_send(server, capability, peer, destination, payload) do
    assert {:ok, ref} = Endpoint.send(capability, destination, payload)
    assert {:ok, at} = Endpoint.await(capability, ref, 1000)
    assert is_integer(at)
    {:ok, {source, port}} = Endpoint.local_endpoint(server)
    assert {:ok, {^source, ^port, ^payload}} = :gen_udp.recv(peer, 0, 1000)
    assert_event(server, :ok, byte_size(payload))
    assert {:ok, ^at} = Endpoint.await(capability, ref, 1000)
  end

  def assert_event(server, result, bytes) do
    assert_receive {:socket_send_event, ^server, %{bytes: ^bytes}, metadata}, 1000
    assert metadata.result == result
    assert Telemetry.socket_scope(metadata.socket) == server
  end

  def assert_counts(server, successes, bytes, failures) do
    metrics = Telemetry.get_metrics(server)
    assert metrics.responses_total == successes
    assert metrics.bytes_sent == bytes
    assert metrics.send_errors_total == failures
  end
end
