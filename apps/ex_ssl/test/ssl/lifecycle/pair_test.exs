defmodule SSL.Lifecycle.PairTest do
  use ExUnit.Case, async: true
  alias SSL.Lifecycle

  test "both allocation-free reservations remain independently readable after pair cancellation" do
    {handle, lease, layers} = pair()
    refute elem(layers.outer, 0) == elem(layers.inner, 0)
    assert {:error, :invalid_lifecycle} = Lifecycle.descriptor({handle, lease})

    assert {:pending,
            %{
              scope: :pair,
              setup: :not_started,
              epoch: {0, 0},
              provider_resources: %{
                processes: 2,
                observers: 2,
                tcp_sockets: 0,
                data_resources: 0
              }
            }} = Lifecycle.status(handle, deadline(1_000))

    assert :ok = Lifecycle.cancel(lease, deadline(1_000))

    assert {:ok,
            %{
              scope: :pair,
              cleanup: :confirmed,
              layers: %{
                outer: %{cleanup: :confirmed, roles: 0, observed_down: 0},
                inner: %{cleanup: :confirmed, roles: 0, observed_down: 0}
              }
            } = receipt} = Lifecycle.await(handle, deadline(2_000))

    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))
  end

  test "a completed inner layer cannot discharge a live outer reservation" do
    {handle, _lease, layers} = pair()
    {inner, inner_lease} = layers.inner
    {outer, outer_lease} = layers.outer
    assert :ok = Lifecycle.cancel(inner_lease, deadline(1_000))
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(inner, deadline(2_000))
    assert {:pending, %{cleanup: :pending}} = Lifecycle.await(handle, deadline(0))

    assert {:pending,
            %{
              layers: %{outer: %{cleanup: :pending}, inner: %{cleanup: :confirmed}},
              provider_resources: %{processes: 1, observers: 1, tcp_sockets: 0}
            }} = Lifecycle.status(handle, deadline(1_000))

    assert :ok = Lifecycle.cancel(outer_lease, deadline(1_000))
    assert {:ok, _} = Lifecycle.await(outer, deadline(2_000))
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(0))
  end

  for missing <- [:outer, :inner] do
    test "loss of the #{missing} observer remains unconfirmed in the pair" do
      {handle, _lease, layers} = pair()
      {missing, _} = Map.fetch!(layers, unquote(missing))
      observer = missing.receipt.observer
      monitor = Process.monitor(observer)
      Process.exit(observer, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^observer, :killed}, 1_000

      assert {:unconfirmed, _} = Lifecycle.status(handle, deadline(1_000))
      assert {:unconfirmed, _} = Lifecycle.await(handle, deadline(0))
    end
  end

  test "pair observation does not renew the deadline for its second observer" do
    {handle, lease, layers} = pair()
    observers = for {_layer, {handle, _lease}} <- layers, do: handle.receipt.observer
    Enum.each(observers, &:erlang.suspend_process/1)

    try do
      entered = System.monotonic_time(:millisecond)
      assert {:pending, %{provider_resources: nil}} = Lifecycle.status(handle, deadline(150))
      assert System.monotonic_time(:millisecond) - entered < 250

      entered = System.monotonic_time(:millisecond)
      assert {:pending, %{cleanup: :pending}} = Lifecycle.await(handle, deadline(150))
      assert System.monotonic_time(:millisecond) - entered < 250
    after
      Enum.each(observers, &:erlang.resume_process/1)
    end

    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    assert {:ok, _} = Lifecycle.await(handle, deadline(2_000))
  end

  test "pair controls reject invalid deadlines without retiring either reservation" do
    {handle, lease, _layers} = pair()
    assert {:error, :invalid_deadline} = Lifecycle.status(handle, :infinity)
    assert {:error, :invalid_deadline} = Lifecycle.await(handle, :infinity)
    assert {:error, :invalid_deadline} = Lifecycle.cancel(lease, :infinity)
    assert {:pending, %{setup: :not_started}} = Lifecycle.status(handle)
  end

  defp pair do
    assert {:ok, handle, lease} = Lifecycle.new_pair(controller: self(), deadline: :infinity)
    assert {:ok, layers} = Lifecycle.layers({handle, lease})

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(1_000))
      Lifecycle.await(handle, deadline(2_000))
    end)

    {handle, lease, layers}
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end
