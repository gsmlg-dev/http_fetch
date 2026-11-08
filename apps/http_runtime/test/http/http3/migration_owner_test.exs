defmodule HTTP.HTTP3.MigrationOwnerTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP3.ConnectionOwner
  alias QuicHttp3.Control

  defmodule Transport do
    def open_stream(_, :bidi, _), do: {:ok, {:stream, make_ref()}}
    def send_stream(_, _, _, _), do: :ok
    def events(_, _, _), do: {:ok, Process.delete(:events) || []}
    def read(_, _, _), do: {:ok, []}
    def reset_stream(_, _, _), do: :ok
    def stop_stream(_, _, _), do: :ok

    def migrate(_connection, opts) do
      send(self(), {:transport_migrate, opts[:local], opts[:deadline]})
      Process.get(:migrate_result) || {:ok, opts[:ref]}
    end
  end

  defmodule NoMigrationTransport do
    def open_stream(_, :bidi, _), do: {:ok, {:stream, make_ref()}}
    def send_stream(_, _, _, _), do: :ok
    def events(_, _, _), do: {:ok, []}
    def read(_, _, _), do: {:ok, []}
    def reset_stream(_, _, _), do: :ok
    def stop_stream(_, _, _), do: :ok
  end

  @fields [
    {":method", "CONNECT"},
    {":scheme", "https"},
    {":authority", "example.test"},
    {":path", "/ws"}
  ]
  @local {{127, 0, 0, 1}, 0}

  defp state(opts \\ []) do
    {:ok, state} =
      ConnectionOwner.init(
        inert: true,
        creator: self(),
        session_options: [transport: Keyword.get(opts, :transport, Transport)]
      )

    {:ok, control} = Control.new(:client)
    control = %{control | received_settings?: true, peer_settings: [{8, 1}]}
    session = %{state.session | open?: true, connection: %{endpoint: nil}, control: control}

    %{
      state
      | lifecycle: :ready,
        watchdog: self(),
        session: session,
        exclusive?: Keyword.get(opts, :exclusive?, true)
    }
  end

  defp open(state, subscriber \\ self()) do
    tag = make_ref()
    generation = make_ref()
    opts = [purpose: :extended_connect, protocol: "websocket", deadline_at: now() + 1000]

    {:noreply, state} =
      ConnectionOwner.handle_call(
        {:open, @fields, :stream, subscriber, generation, opts},
        {self(), tag},
        state
      )

    assert_receive {^tag, {:ok, ref}}
    {state, ref, generation}
  end

  defp migrate(state, ref, caller \\ self()) do
    tag = make_ref()

    {tag,
     ConnectionOwner.handle_call({:migrate, ref, @local, now() + 1000}, {caller, tag}, state)}
  end

  test "exclusive sole subscriber migration is admitted and its outcome is routed once" do
    {state, ref, generation} = open(state())
    {tag, {:noreply, state}} = migrate(state, ref)
    assert_receive {:transport_migrate, @local, {:abs_ms, deadline}}
    assert is_integer(deadline)
    assert_receive {^tag, {:ok, migration}}
    assert %{ref: ^migration, request: ^ref} = state.migration

    assert {_, {:reply, {:error, :migration_busy}, _}} = migrate(state, ref)

    Process.put(:events, [{:migration, migration, {:ok, {{127, 0, 0, 1}, 4001}}}])
    assert {:noreply, state} = ConnectionOwner.handle_info(:tick, state)

    assert_receive {:http3, ^generation, ^ref,
                    {:migration, ^migration, {:ok, {{127, 0, 0, 1}, 4001}}}}

    assert state.migration == nil

    # A stale or foreign outcome is not delivered.
    Process.put(:events, [{:migration, make_ref(), {:error, :validation_timeout}}])
    assert {:noreply, _state} = ConnectionOwner.handle_info(:tick, state)
    refute_received {:http3, _, _, {:migration, _, _}}
  end

  test "engine refusal is returned to the caller without recording a migration" do
    {state, ref, _generation} = open(state())
    Process.put(:migrate_result, {:error, :peer_disabled_migration})
    {tag, {:noreply, state}} = migrate(state, ref)
    assert_receive {^tag, {:error, :peer_disabled_migration}}
    assert state.migration == nil
  end

  test "pooled shared owners refuse migration before reaching the engine" do
    {state, ref, _generation} = open(state(exclusive?: false))

    assert {_, {:reply, {:error, :not_exclusive_owner}, _}} = migrate(state, ref)
    refute_received {:transport_migrate, _, _}
  end

  test "an owner dialled through a shared resumption endpoint refuses migration" do
    {state, ref, _generation} = open(state())
    state = %{state | resumption: %{early: false}}

    assert {_, {:reply, {:error, :shared_endpoint}, _}} = migrate(state, ref)
    refute_received {:transport_migrate, _, _}
  end

  test "only the sole subscriber of a ready owner may migrate" do
    {state, ref, _generation} = open(state())
    other = spawn(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> send(other, :stop) end)

    assert {_, {:reply, {:error, :unknown_request}, _}} = migrate(state, ref, other)
    assert {_, {:reply, {:error, :unknown_request}, _}} = migrate(state, make_ref())

    {shared, _sibling, _} = open(state, other)
    assert {_, {:reply, {:error, :not_exclusive_owner}, _}} = migrate(shared, ref)

    assert {_, {:reply, {:error, :not_ready}, _}} = migrate(%{state | lifecycle: :draining}, ref)
    refute_received {:transport_migrate, _, _}
  end

  test "a transport without migration rejects the admitted request explicitly" do
    {state, ref, _generation} = open(state(transport: NoMigrationTransport))
    {tag, {:noreply, state}} = migrate(state, ref)
    assert_receive {^tag, {:error, :migration_unsupported}}
    assert state.migration == nil
  end

  defp now, do: System.monotonic_time(:millisecond)
end
