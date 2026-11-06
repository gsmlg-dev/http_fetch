# Loopback-only overload measurement. Callback gates and actual DOWN acknowledge completion.
defmodule Abyss.RuntimeStressHandler do
  @behaviour Abyss.DatagramHandler

  def init(options, _context), do: {:ok, options[:owner]}

  def handle_datagram(datagram, owner) do
    gate = make_ref()
    send(owner, {:stress_callback, self(), gate, datagram.payload})
    receive do: ({:release_callback, ^gate} -> :ok)
    {:ok, owner, [{:reply, datagram.payload}]}
  end
end

defmodule Abyss.RuntimeStressTransport do
  alias Abyss.Transport.UDP
  defdelegate listen(port, options), to: Abyss.Transport.UDP
  defdelegate sockname(socket), to: Abyss.Transport.UDP
  defdelegate setopts(socket, options), to: Abyss.Transport.UDP
  defdelegate close(socket), to: Abyss.Transport.UDP

  def send(socket, ip, port, payload) do
    gate = make_ref()
    owner = :persistent_term.get({__MODULE__, :owner})
    send(owner, {:stress_writer, self(), gate})
    receive do: ({:release_writer, ^gate} -> :ok)
    UDP.send(socket, ip, port, payload)
  end
end

defmodule Abyss.RuntimeStress do
  alias Abyss.Dispatcher.Admission
  alias Abyss.Endpoint

  @inputs 8
  @burst 256
  @payload_bytes 512
  @egress 4
  @egress_byte_limit 4096
  @send_overload 32
  @epochs 5

  def run do
    key = {Abyss.RuntimeStressTransport, :owner}
    :persistent_term.put(key, self())

    try do
      for policy <- [:per_datagram, :endpoint, :keyed] do
        baseline = :erlang.system_info(:process_count)
        high = Enum.reduce(1..@epochs, %{}, fn _, high -> epoch(policy, high) end)

        IO.puts(
          "RUNTIME_STRESS_PASS " <>
            inspect(
              Map.merge(high, %{
                policy: policy,
                epochs: @epochs,
                payload_bytes: @payload_bytes,
                offered_udp: (@inputs + @burst) * @epochs,
                offered_load: :batches_of_16_with_observed_receive_barriers,
                accepted_callbacks: @inputs * @epochs,
                ingress_application_drops: @burst * @epochs,
                offered_direct_sends: (@egress + @send_overload) * @epochs,
                direct_send_admission_rejections: @send_overload * @epochs,
                verified_wire_replies: (@inputs + @egress) * @epochs,
                kernel_drops: :unmeasured,
                baseline_processes: baseline,
                final_processes: :erlang.system_info(:process_count),
                input_item_limit: @inputs,
                input_byte_limit: 16_384,
                key_limit: 8,
                egress_entry_limit: @egress,
                egress_byte_limit: @egress_byte_limit,
                observations: :sampled_high_water_not_whole_vm_bound
              }),
              limit: :infinity
            )
        )
      end
    after
      :persistent_term.erase(key)
    end
  end

  defp epoch(policy, high) do
    {:ok, peer} = :gen_udp.open(0, [:binary, active: true, ip: {127, 0, 0, 1}])
    {:ok, {{127, 0, 0, 1}, peer_port}} = :inet.sockname(peer)
    {:ok, server} = Endpoint.start_link(options(policy))
    {:ok, {{127, 0, 0, 1}, port}} = Endpoint.local_endpoint(server)
    [owner] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    runtime = :sys.get_state(owner).runtime
    {:ok, capability} = Endpoint.capability(server)
    topology = [server, owner, runtime, capability.writer, capability.admission]
    monitors = Enum.map(topology, &{Process.monitor(&1), &1})
    sample_context = %{server: server, owner: owner, runtime: runtime, writer: capability.writer}

    try do
      {callbacks, high} = ingress_pressure(policy, peer, port, sample_context, high)
      worker_monitors = Enum.map(callbacks, fn {pid, _, _} -> {Process.monitor(pid), pid} end)
      :ok = Endpoint.pause(server)
      high = sample(sample_context, high)

      destination = %{family: :inet, addr: {127, 0, 0, 1}, port: peer_port}

      refs =
        for id <- 1..@egress do
          {:ok, ref} = Endpoint.send(capability, destination, payload(1000 + id))
          ref
        end

      for _ <- 1..@send_overload do
        {:error, :queue_limit} = Endpoint.send(capability, destination, payload(2000))
      end

      {info, high} = await_info(sample_context, high, &(&1.egress.entries == @egress))
      unit_bytes = Admission.size({{127, 0, 0, 1}, peer_port}, payload(1001))
      true = info.egress.bytes == @egress * unit_bytes

      {_, high} =
        Enum.reduce(1..@egress, {callbacks, high}, fn id, {pending, high} ->
          wire_reply(peer, port, payload(1000 + id), pending, sample_context, high)
        end)

      for ref <- refs, do: {:ok, _} = Endpoint.await(capability, ref, 1000)

      {[], high} =
        Enum.reduce(1..@inputs, {callbacks, high}, fn _, {pending, high} ->
          [{pid, gate, expected} | pending] = if pending == [], do: [callback()], else: pending
          send(pid, {:release_callback, gate})
          wire_reply(peer, port, expected, pending, sample_context, high)
        end)

      {info, high} =
        await_info(sample_context, high, &(&1.input_count == 0 and &1.egress.entries == 0))

      true = info.retained_bytes == 0
      [] = Abyss.UDPAdmission.slots(:server, server)
      :ok = Endpoint.stop(server, 1000)
      down(monitors ++ worker_monitors)
      [] = Abyss.UDPAdmission.slots(:server, server)
      high
    after
      if Process.alive?(server), do: Endpoint.stop(server, 100)
      :gen_udp.close(peer)
    end
  end

  defp ingress_pressure(policy, peer, port, sample_context, high) do
    for id <- 1..@inputs, do: offer(peer, port, payload(id))
    active = if policy == :endpoint, do: 1, else: if(policy == :keyed, do: 4, else: @inputs)
    callbacks = for _ <- 1..active, do: callback()
    {_, high} = await_info(sample_context, high, &(&1.input_count == @inputs))

    high =
      Enum.reduce(1..div(@burst, 16), high, fn batch, high ->
        last = @inputs + batch * 16
        for id <- (last - 15)..last, do: offer(peer, port, payload(id))
        {_, high} = await_info(sample_context, high, &(&1.received == last))
        high
      end)

    {info, high} = await_info(sample_context, high, &(&1.received == @inputs + @burst))
    true = info.dropped == @burst
    {callbacks, high}
  end

  defp options(policy) do
    [
      datagram_handler: Abyss.RuntimeStressHandler,
      handler_options: [owner: self()],
      execution: policy,
      route_key:
        if(policy == :keyed,
          do: fn d -> rem(:binary.decode_unsigned(binary_part(d.payload, 0, 4)), 4) end
        ),
      transport_module: Abyss.RuntimeStressTransport,
      transport_options: [ip: {127, 0, 0, 1}, recbuf: 1_048_576],
      port: 0,
      num_connections: @inputs,
      max_packet_size: @payload_bytes,
      dispatcher_max_queue: @egress,
      dispatcher_max_queue_bytes: @egress_byte_limit,
      runtime_options: [
        max_queue: @inputs,
        max_queue_bytes: 16_384,
        max_keys: 8,
        max_key_queue: @inputs,
        max_key_queue_bytes: 16_384,
        callback_timeout: 5000,
        send_timeout: 1000,
        idle_timeout: 30_000
      ]
    ]
  end

  defp payload(id), do: <<id::32, 0::size((@payload_bytes - 4) * 8)>>
  defp offer(peer, port, bytes), do: :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, bytes)

  defp callback do
    receive do
      {:stress_callback, pid, gate, bytes} -> {pid, gate, bytes}
    after
      5000 -> raise "callback readiness deadline expired"
    end
  end

  defp wire_reply(peer, port, expected, pending, context, high) do
    receive do
      {:stress_writer, pid, gate} ->
        high = sample(context, high)
        send(pid, {:release_writer, gate})
        wire_reply(peer, port, expected, pending, context, high)

      {:stress_callback, pid, gate, bytes} ->
        wire_reply(peer, port, expected, pending ++ [{pid, gate, bytes}], context, high)

      {:udp, ^peer, {127, 0, 0, 1}, ^port, ^expected} ->
        {pending, sample(context, high)}

      {:udp, ^peer, ip, actual_port, bytes} ->
        raise "unexpected reply #{inspect({ip, actual_port, bytes})}"
    after
      5000 -> raise "wire reply deadline expired"
    end
  end

  defp sample(context, high) do
    {:ok, info} = Endpoint.info(context.server)
    state = :sys.get_state(context.runtime)
    workers = Enum.map(state.workers, fn {_, worker} -> worker.pid end)
    true = info.input_count <= @inputs and info.high_items <= @inputs
    true = info.retained_bytes <= 16_384 and info.high_bytes <= 16_384
    true = info.key_count <= 8
    true = info.egress.entries <= @egress and info.egress.bytes <= @egress_byte_limit

    values = %{
      sampled_processes: :erlang.system_info(:process_count),
      sampled_owner_mailbox: mailbox(context.owner),
      sampled_runtime_mailbox: mailbox(context.runtime),
      sampled_worker_mailbox: Enum.reduce(workers, 0, &max(mailbox(&1), &2)),
      sampled_writer_mailbox: mailbox(context.writer),
      sampled_input_items: info.input_count,
      sampled_retained_bytes: info.retained_bytes,
      accounted_input_high_water: info.high_items,
      accounted_retained_high_water: info.high_bytes,
      sampled_keys: info.key_count,
      sampled_egress_entries: info.egress.entries,
      sampled_egress_bytes: info.egress.bytes
    }

    Map.merge(high, values, fn _, old, value -> max(old, value) end)
  end

  defp await_info(context, high, predicate),
    do: await_info(context, high, predicate, System.monotonic_time(:millisecond) + 5000)

  defp await_info(context, high, predicate, deadline) do
    {:ok, info} = Endpoint.info(context.server)
    high = sample(context, high)

    cond do
      predicate.(info) ->
        {info, high}

      System.monotonic_time(:millisecond) >= deadline ->
        raise "status barrier expired: #{inspect(info)}"

      true ->
        await_info(context, high, predicate, deadline)
    end
  end

  defp mailbox(pid) do
    case Process.info(pid, :message_queue_len) do
      {:message_queue_len, count} -> count
      nil -> 0
    end
  end

  defp down([]), do: :ok

  defp down(monitors) do
    receive do
      {:DOWN, ref, :process, pid, _} -> down(List.delete(monitors, {ref, pid}))
    after
      5000 -> raise "owned-process shutdown deadline expired: #{inspect(monitors)}"
    end
  end
end

Abyss.RuntimeStress.run()
