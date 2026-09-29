defmodule HTTP.HTTP2ActivationTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.ConnectionOwner

  test "initial active-once failure is returned and closes the owner" do
    {:ok, owner} =
      ConnectionOwner.start_link(
        transport: transport(fn -> {:error, :einval} end),
        socket: :socket,
        activate?: false
      )

    monitor = Process.monitor(owner)

    assert {:error, :einval} = ConnectionOwner.activate(owner)
    assert_receive {:DOWN, ^monitor, :process, ^owner, _reason}
  end

  test "rearm failure terminates the owner and reports one terminal error" do
    calls = :atomics.new(1, [])

    transport =
      transport(fn ->
        if :atomics.add_get(calls, 1, 1) == 1, do: :ok, else: {:error, :einval}
      end)

    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport, socket: :socket, activate?: false)

    assert :ok = ConnectionOwner.activate(owner)

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, [{":method", "GET"}], subscriber: self())

    monitor = Process.monitor(owner)

    send(owner, {:test_data, <<0::24, 4, 0, 0::32>>})
    assert_receive {:http2, 1, {:http2, :transport_error, :einval}}
    assert_receive {:DOWN, ^monitor, :process, ^owner, _reason}
    refute_receive {:http2, 1, {:http2, :transport_error, :einval}}, 0
  end

  defp transport(on_active) do
    %{
      send: fn _, _ -> :ok end,
      close: fn _ -> :ok end,
      setopts: fn _, opts ->
        if Keyword.get(opts, :active) == :once, do: on_active.(), else: :ok
      end,
      normalize_message: fn
        {:test_data, data}, :socket -> {:data, data}
        _, _ -> :unknown
      end
    }
  end
end
