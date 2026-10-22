defmodule SSL.Lifecycle.SocketOwnerReferenceTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  test "explicit close loses public owner facts while the original owner remains alive" do
    closed_reference(:close)
  end

  test "actual owner death loses public owner facts even with original socket DOWN" do
    closed_reference(:kill)
  end

  defp closed_reference(mode) do
    native = System.monotonic_time(:millisecond) + 1_000
    parent_deadline = native + 2_000
    parent = self()

    {owner, process_monitor} =
      spawn_monitor(fn -> socket_owner(parent, native, parent_deadline) end)

    on_exit(fn -> Process.exit(owner, :kill) end)
    assert_receive {:opened, ^owner, socket}, remaining(native)
    original = :socket.monitor(socket)
    assert %{owner: ^owner} = :socket.info(socket)
    assert {:ok, ^owner} = :socket.getopt(socket, :otp, :controlling_process)

    case mode do
      :close ->
        tag = make_ref()
        send(owner, {:close, tag})
        assert_receive {^tag, :ok}, remaining(native)
        assert Process.alive?(owner)

      :kill ->
        Process.exit(owner, :kill)

        assert_receive {:DOWN, ^process_monitor, :process, ^owner, :killed},
                       remaining(parent_deadline)
    end

    assert_receive {:DOWN, ^original, :socket, ^socket, :closed}, remaining(parent_deadline)
    if mode == :close, do: assert(Process.alive?(owner))
    assert %{owner: :undefined} = :socket.info(socket)
    assert {:error, :closed} = :socket.getopt(socket, :otp, :controlling_process)
    late = :socket.monitor(socket)
    refute late == original
    assert_receive {:DOWN, ^late, :socket, ^socket, :closed}, remaining(parent_deadline)
  end

  defp socket_owner(parent, native, deadline) do
    timer = :erlang.start_timer(remaining(deadline), self(), :expiry)

    if remaining(native) > 0 do
      {:ok, socket} = :socket.open(:inet, :stream, :tcp)

      try do
        send(parent, {:opened, self(), socket})

        receive do
          {:close, tag} ->
            send(parent, {tag, :socket.close(socket)})

            receive do
              {:timeout, ^timer, :expiry} -> :ok
            end

          {:timeout, ^timer, :expiry} ->
            :ok
        end
      after
        :socket.close(socket)
      end
    end
  end

  defp remaining(deadline), do: max(0, deadline - System.monotonic_time(:millisecond))
end
