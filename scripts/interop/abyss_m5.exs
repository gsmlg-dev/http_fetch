abyss_root = System.fetch_env!("ABYSS_CHECKOUT")
ex_quic_root = Path.expand("../..", __DIR__)

for path <- Path.wildcard(Path.join(abyss_root, "_build/dev/lib/*/ebin")),
    do: Code.prepend_path(path)

Code.ensure_loaded!(Quic.AbyssDispatcher)
{:ok, _} = Application.ensure_all_started(:telemetry)

defmodule Quic.AbyssM5Handler do
  use Abyss.Handler

  @impl true
  def handle_data(_data, state), do: {:continue, state}
end

fixture = Path.join(ex_quic_root, "apps/elixir_quic/test/fixtures/tls")

der = fn name ->
  [{:Certificate, bytes, :not_encrypted}] =
    :public_key.pem_decode(File.read!(Path.join(fixture, name)))

  bytes
end

[{key_type, key, :not_encrypted}] =
  :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

server_tls = [cert: [der.("leaf.pem")], key: {key_type, key}, alpn: ["ex-quic-test"]]

client_tls = [
  cacerts: [der.("root.pem")],
  reference_identity: {:dns_id, "example.test"},
  alpn: ["ex-quic-test"]
]

{:ok, server} =
  Abyss.start_link(
    handler_module: Quic.AbyssM5Handler,
    port: 0,
    num_listeners: 1,
    transport_options: [ip: {127, 0, 0, 1}],
    datagram_dispatcher: Quic.AbyssDispatcher,
    dispatcher_options: [tls: server_tls, streams: [delivery: :immediate], stream_observer: self()]
  )

pool = Abyss.Server.listener_pool_pid(server)
[listener] = Abyss.ListenerPool.listener_pids(pool)
{:ok, address} = Abyss.Listener.listener_info_cached(listener)
{:ok, client_one} = Quic.Endpoint.start_link(role: :client, remote: address, tls: client_tls)
{:ok, client_two} = Quic.Endpoint.start_link(role: :client, remote: address, tls: client_tls)

deadline = System.monotonic_time(:millisecond) + 12_000

established? = fn endpoint ->
  case Quic.Endpoint.connections(endpoint) do
    [%{pid: pid}] ->
      status = Quic.Connection.status(pid)
      status.phase == :established and status.quic_confirmed

    _ ->
      false
  end
end

wait_until = fn wait_until, predicate, deadline ->
  cond do
    predicate.() ->
      :ok

    System.monotonic_time(:millisecond) >= deadline ->
      :timeout

    true ->
      Process.sleep(20)
      wait_until.(wait_until, predicate, deadline)
  end
end

first_pair =
  wait_until.(
    wait_until,
    fn -> established?.(client_one) and established?.(client_two) end,
    deadline
  )

if first_pair == :ok do
  [%{pid: first_pid}] = Quic.Endpoint.connections(client_one)
  :ok = Quic.Connection.close(first_pid)
end

second_survives = wait_until.(wait_until, fn -> established?.(client_two) end, deadline)

{stream_one, stream_two, stream_result} =
  if second_survives == :ok do
    [%{pid: client_pid}] = Quic.Endpoint.connections(client_two)
    {:ok, stream_one} = Quic.Connection.open_stream(client_pid, :bidi)
    {:ok, stream_two} = Quic.Connection.open_stream(client_pid, :bidi)
    :ok = Quic.Connection.send_stream(client_pid, stream_one, "stream-one", true)
    :ok = Quic.Connection.send_stream(client_pid, stream_two, "stream-two", true)

    collect_streams = fn collect_streams, deadline, seen ->
      receive do
        {:quic_stream, _pid, stream_id, events} when stream_id in [stream_one, stream_two] ->
          next = Map.put(seen, stream_id, events)
          if map_size(next) == 2, do: next, else: collect_streams.(collect_streams, deadline, next)
      after
        20 ->
          if System.monotonic_time(:millisecond) >= deadline,
            do: seen,
            else: collect_streams.(collect_streams, deadline, seen)
      end
    end

    {stream_one, stream_two, collect_streams.(collect_streams, deadline, %{})}
  else
    {nil, nil, %{}}
  end

stream_ok =
  is_integer(stream_one) and is_integer(stream_two) and
    Enum.all?([{stream_one, "stream-one"}, {stream_two, "stream-two"}], fn {stream_id, expected} ->
      case Map.get(stream_result, stream_id) do
        [{:data, ^stream_id, ^expected}, {:fin, ^stream_id}] -> true
        _ -> false
      end
    end)

:ok = Abyss.suspend(server)
:ok = Abyss.resume(server)
pool = Abyss.Server.listener_pool_pid(server)
[restarted_listener] = Abyss.ListenerPool.listener_pids(pool)
{:ok, restarted_address} = Abyss.Listener.listener_info_cached(restarted_listener)

{:ok, client_three} =
  Quic.Endpoint.start_link(role: :client, remote: restarted_address, tls: client_tls)

third_ready = wait_until.(wait_until, fn -> established?.(client_three) end, deadline)

result =
if first_pair == :ok and second_survives == :ok and third_ready == :ok and stream_ok,
    do: :ok,
    else:
     {:error,
       %{first_pair: first_pair, second_survives: second_survives, third_ready: third_ready,
         stream_result: stream_result}}

IO.inspect(%{result: result, address: address, restarted_address: restarted_address},
  label: "M5_ABYSS_RESULT"
)

GenServer.stop(client_one)
GenServer.stop(client_two)
GenServer.stop(client_three)
Supervisor.stop(server)
if result == :ok, do: :ok, else: System.halt(1)
