defmodule Quic.ExternalEndpointTest do
  use ExUnit.Case, async: true

  alias Quic.{Endpoint, HandshakeScheduler}

  defmodule RecordedTLS do
    def new(:client, _), do: {:ok, :client, [{:emit, :initial, <<1, 2>>}]}
    def new(:server, _), do: {:ok, :server, []}
    def info(_), do: %{receive_level: :initial}
    def feed(:server, :initial, <<1, 2>>), do: {:ok, :done, [{:emit, :initial, <<3, 4>>}]}
    def feed(:client, :initial, <<3, 4>>), do: {:ok, :done, []}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  test "routes a datagram through an externally owned writer" do
    parent = self()
    remote = {{127, 0, 0, 1}, 45_001}

    send_fun = fn destination, bytes ->
      send(parent, {:egress, destination, bytes})
      :ok
    end

    {:ok, endpoint} =
      Endpoint.start_link(
        role: :server,
        io: {:external, {{127, 0, 0, 1}, 45_000}, send_fun},
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> stop(endpoint) end)

    {:ok, _client, [initial]} =
      HandshakeScheduler.new(:client,
        dcid: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        scid: <<9, 10, 11, 12, 13, 14, 15, 16>>,
        adapter: RecordedTLS
      )

    assert :ok = Endpoint.receive_datagram(endpoint, remote, initial.bytes, 100)
    assert eventually(fn -> Endpoint.connections(endpoint) != [] end)
    assert_receive {:egress, ^remote, bytes}, 1_000
    assert is_binary(bytes)
  end

  test "external writer preserves callback errors" do
    {:ok, writer} =
      Quic.IO.ExternalWriter.start_link(
        owner: self(),
        send_fun: fn _remote, _bytes -> {:error, :closed} end
      )

    on_exit(fn -> if Process.alive?(writer), do: GenServer.stop(writer) end)
    assert {:error, :closed} = Quic.IO.ExternalWriter.send(writer, <<1>>, {{127, 0, 0, 1}, 1})
  end

  test "external writer does not treat an admission reference as local success" do
    {:ok, writer} =
      Quic.IO.ExternalWriter.start_link(
        owner: self(),
        send_fun: fn _remote, _bytes -> {:ok, make_ref()} end
      )

    on_exit(fn -> if Process.alive?(writer), do: GenServer.stop(writer) end)

    assert {:error, {:invalid_send_result, {:ok, _}}} =
             Quic.IO.ExternalWriter.send(writer, <<1>>, {{127, 0, 0, 1}, 1})
  end

  test "Abyss callback adapter owns the QUIC endpoint and uses injected egress" do
    parent = self()
    remote = {{127, 0, 0, 1}, 45_002}

    send_fun = fn destination, bytes ->
      send(parent, {:adapter_egress, destination, bytes})
      :ok
    end

    {:ok, state} =
      Quic.AbyssDispatcher.init(
        %{local_info: {{127, 0, 0, 1}, 45_003}, send_fun: send_fun},
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> Quic.AbyssDispatcher.terminate(:normal, state) end)

    {:ok, _client, [initial]} =
      HandshakeScheduler.new(:client,
        dcid: <<11, 12, 13, 14, 15, 16, 17, 18>>,
        scid: <<19, 20, 21, 22, 23, 24, 25, 26>>,
        adapter: RecordedTLS
      )

    assert {:ok, _} =
             Quic.AbyssDispatcher.handle_datagram(
               remote,
               initial.bytes,
               200,
               %{state: state}
             )

    assert_receive {:adapter_egress, ^remote, bytes}, 1_000
    assert is_binary(bytes)
  end

  defp stop(pid) do
    if Process.alive?(pid), do: GenServer.stop(pid)
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(_fun, 0), do: false

  defp eventually(fun, attempts) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(5)
          eventually(fun, attempts - 1)
        )
  end
end
