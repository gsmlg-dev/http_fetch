defmodule Quic.ClientFeatures.Relay do
  @moduledoc false
  # Test-owned UDP relay between the QUIC runtime under test and an unmodified
  # independent peer. It never parses or changes packet contents: it only
  # forwards, drops or holds-and-reverses whole datagrams, per direction, on
  # the driver's command. Long-header datagrams (the handshake) always pass;
  # the modes apply only to short-header (1-RTT) datagrams.
  #
  #   :c2s = runtime -> peer, :s2c = peer -> runtime
  #   mode :pass | :drop | {:hold, max_datagrams, max_ms}
  #
  # `late_zero_rtt(relay, delays)` instead makes the relay hold every c2s
  # datagram that starts with a 0-RTT long-header packet (header byte
  # 0b1101xxxx; the packet type bits are not header-protected) and release
  # them, in arrival order, `delay` ms after the first short-header datagram
  # of that episode was forwarded, i.e. after the handshake. One delay is
  # consumed per episode.
  #
  # A hold releases its datagrams in reverse arrival order once `max_datagrams`
  # are held or `max_ms` elapsed after the first one, then returns to :pass.

  def start(peer_port) do
    owner = self()

    pid =
      spawn_link(fn ->
        {:ok, down} = :gen_udp.open(0, [:binary, active: true, ip: {127, 0, 0, 1}])
        {:ok, up} = :gen_udp.open(0, [:binary, active: true, ip: {127, 0, 0, 1}])
        {:ok, {_, down_port}} = :inet.sockname(down)
        {:ok, {_, up_port}} = :inet.sockname(up)
        send(owner, {:relay_ready, self(), down_port, up_port})

        loop(%{
          down: down,
          up: up,
          peer: peer_port,
          client: nil,
          mode: %{c2s: :pass, s2c: :pass},
          late: %{delays: [], held: [], episodes: []},
          held: %{c2s: [], s2c: []},
          hold_ref: %{c2s: nil, s2c: nil},
          stats: %{
            c2s: %{forwarded: 0, dropped: 0, held: 0, released: 0, holds: []},
            s2c: %{forwarded: 0, dropped: 0, held: 0, released: 0, holds: []}
          }
        })
      end)

    receive do
      {:relay_ready, ^pid, down_port, up_port} ->
        %{pid: pid, port: down_port, peer_view: "127.0.0.1:#{up_port}"}
    after
      2000 -> raise("relay startup deadline")
    end
  end

  def mode(relay, direction, mode), do: call(relay, {:mode, direction, mode})
  def late_zero_rtt(relay, delays), do: call(relay, {:late, delays})
  def stats(relay), do: call(relay, :stats)

  def stop(relay) do
    stats = stats(relay)
    Process.unlink(relay.pid)
    Process.exit(relay.pid, :kill)
    stats
  end

  defp call(relay, request) do
    ref = make_ref()
    send(relay.pid, {request, self(), ref})

    receive do
      {^ref, reply} -> reply
    after
      2000 -> raise("relay call deadline")
    end
  end

  defp loop(state) do
    receive do
      {:udp, socket, _ip, port, data} when socket == state.down ->
        state |> Map.put(:client, port) |> route(:c2s, data) |> loop()

      {:udp, socket, _ip, _port, data} when socket == state.up ->
        state |> route(:s2c, data) |> loop()

      {{:mode, direction, mode}, from, ref} ->
        send(from, {ref, :ok})
        state |> release(direction) |> put_in([:mode, direction], mode) |> loop()

      {:stats, from, ref} ->
        send(from, {ref, Map.put(state.stats, :late, state.late.episodes)})
        loop(state)

      {{:late, delays}, from, ref} ->
        send(from, {ref, :ok})
        loop(put_in(state, [:late, :delays], delays))

      {:release_late, delay, held} ->
        state = held |> Enum.reverse() |> Enum.reduce(state, &forward(&2, :c2s, &1))

        episode = %{
          held: length(held),
          delay_ms: delay,
          released_ns: System.os_time(:nanosecond),
          released_us: System.monotonic_time(:microsecond)
        }

        state |> update_in([:late, :episodes], &(&1 ++ [episode])) |> loop()

      # Only the timer of the current hold may release it.
      {:release, direction, ref} ->
        if state.hold_ref[direction] == ref,
          do: state |> release(direction) |> loop(),
          else: loop(state)
    end
  end

  # A held 0-RTT episode ends with the first short-header datagram after it.
  defp route(
         %{late: %{delays: [delay | rest], held: [_ | _] = held}} = state,
         :c2s,
         <<0::1, _::bitstring>> = data
       ) do
    Process.send_after(self(), {:release_late, delay, held}, delay)
    state |> put_in([:late, :delays], rest) |> put_in([:late, :held], []) |> forward(:c2s, data)
  end

  defp route(%{late: %{delays: [_ | _]}} = state, :c2s, <<0b1101::4, _::bitstring>> = data),
    do: update_in(state, [:late, :held], &[data | &1])

  defp route(state, direction, <<0::1, _::bitstring>> = data) do
    case state.mode[direction] do
      :pass ->
        forward(state, direction, data)

      :drop ->
        update_in(state, [:stats, direction, :dropped], &(&1 + 1))

      {:hold, max, ms} ->
        state =
          if state.held[direction] == [] do
            ref = make_ref()
            Process.send_after(self(), {:release, direction, ref}, ms)
            put_in(state, [:hold_ref, direction], ref)
          else
            state
          end

        state =
          state
          |> update_in([:held, direction], &[data | &1])
          |> update_in([:stats, direction, :held], &(&1 + 1))

        if length(state.held[direction]) >= max, do: release(state, direction), else: state
    end
  end

  defp route(state, direction, data), do: forward(state, direction, data)

  defp forward(state, :c2s, data) do
    :ok = :gen_udp.send(state.up, {127, 0, 0, 1}, state.peer, data)
    update_in(state, [:stats, :c2s, :forwarded], &(&1 + 1))
  end

  defp forward(%{client: nil} = state, :s2c, _data), do: state

  defp forward(state, :s2c, data) do
    :ok = :gen_udp.send(state.down, {127, 0, 0, 1}, state.client, data)
    update_in(state, [:stats, :s2c, :forwarded], &(&1 + 1))
  end

  # The held list is newest-first, so sending it in list order reverses arrival.
  defp release(state, direction) do
    case state.held[direction] do
      [] ->
        state

      held ->
        state = %{state | mode: Map.put(state.mode, direction, :pass)}
        state = Enum.reduce(held, state, &forward(&2, direction, &1))

        state
        |> put_in([:held, direction], [])
        |> put_in([:hold_ref, direction], nil)
        |> update_in([:stats, direction, :released], &(&1 + length(held)))
        |> update_in(
          [:stats, direction, :holds],
          &(&1 ++ [%{count: length(held), released_ns: System.os_time(:nanosecond)}])
        )
    end
  end
end
