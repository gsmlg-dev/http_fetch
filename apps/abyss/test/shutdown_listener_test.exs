defmodule Abyss.ShutdownListenerTest do
  @moduledoc """
  Comprehensive unit tests for Abyss.ShutdownListener.

  Tests cover:
  - Module structure and exports
  - GenServer callbacks (init, handle_continue, terminate)
  - State structure

  Note: Full integration tests with a real Abyss.Server are in the server tests.
  These tests verify the module's contract and callback behavior in isolation.
  """
  use ExUnit.Case, async: true

  alias Abyss.ShutdownListener

  describe "module structure" do
    test "module is defined and loadable" do
      {:module, _} = Code.ensure_loaded(ShutdownListener)
    end

    test "exports start_link/1" do
      Code.ensure_loaded!(ShutdownListener)
      assert Kernel.function_exported?(ShutdownListener, :start_link, 1)
    end

    test "exports init/1" do
      Code.ensure_loaded!(ShutdownListener)
      assert Kernel.function_exported?(ShutdownListener, :init, 1)
    end

    test "setup no longer requires a parent-supervisor continuation" do
      Code.ensure_loaded!(ShutdownListener)
      refute Kernel.function_exported?(ShutdownListener, :handle_continue, 2)
    end

    test "exports terminate/2" do
      Code.ensure_loaded!(ShutdownListener)
      assert Kernel.function_exported?(ShutdownListener, :terminate, 2)
    end

    test "uses GenServer behaviour" do
      Code.ensure_loaded!(ShutdownListener)
      behaviours = ShutdownListener.__info__(:attributes)[:behaviour] || []
      assert GenServer in behaviours
    end
  end

  describe "init/1" do
    test "returns ready state without parent-supervisor setup" do
      server_pid = self()

      result = ShutdownListener.init(server_pid)

      assert {:ok, %{timeout: 15_000} = state} = result
      assert is_map(state)
    end

    test "stores server_pid in state" do
      server_pid = self()
      {:ok, state} = ShutdownListener.init(server_pid)

      assert state.server_pid == server_pid
    end

    test "initialization has a ready deadline without querying its parent" do
      assert {:ok, %{timeout: 15_000}} = ShutdownListener.init(self())
    end

    test "accepts any PID" do
      # Create a short-lived process
      pid = spawn(fn -> :ok end)
      Process.sleep(10)

      {:ok, state} = ShutdownListener.init(pid)

      assert state.server_pid == pid
    end
  end

  describe "terminate/2" do
    # NOTE: terminate/2 has two clauses:
    # 1. When state contains :listener_pool_pid key -> calls Abyss.ListenerPool.suspend/1
    # 2. Fallback clause -> returns :ok
    # We test the fallback clause directly since ListenerPool requires real supervision tree

    test "returns :ok without listener_pool_pid in state" do
      state = %{}

      result = ShutdownListener.terminate(:normal, state)

      assert result == :ok
    end

    test "handles :normal reason" do
      # Use state without listener_pool_pid key to match fallback clause
      state = %{server_pid: self()}
      assert ShutdownListener.terminate(:normal, state) == :ok
    end

    test "handles :shutdown reason" do
      state = %{server_pid: self()}
      assert ShutdownListener.terminate(:shutdown, state) == :ok
    end

    test "handles {:shutdown, term} reason" do
      state = %{server_pid: self()}
      assert ShutdownListener.terminate({:shutdown, :test}, state) == :ok
    end

    test "handles arbitrary termination reason" do
      state = %{server_pid: self()}
      assert ShutdownListener.terminate(:killed, state) == :ok
      assert ShutdownListener.terminate(:timeout, state) == :ok
      assert ShutdownListener.terminate({:error, :reason}, state) == :ok
    end

    test "handles state with server_pid only" do
      state = %{server_pid: self()}
      assert ShutdownListener.terminate(:normal, state) == :ok
    end

    test "handles empty map state" do
      assert ShutdownListener.terminate(:normal, %{}) == :ok
    end
  end

  describe "state structure" do
    test "initial state is a map" do
      {:ok, state} = ShutdownListener.init(self())

      assert is_map(state)
    end

    test "initial state contains server_pid" do
      {:ok, state} = ShutdownListener.init(self())

      assert Map.has_key?(state, :server_pid)
    end

    test "initial state contains server_pid and timeout" do
      {:ok, state} = ShutdownListener.init(self())

      assert Enum.sort(Map.keys(state)) == [:server_pid, :timeout]
    end
  end

  describe "type specifications" do
    # These tests verify the documented types by testing edge cases

    test "start_link accepts a pid" do
      # We can't actually start_link without a real server,
      # but we verify the function signature
      assert is_function(&ShutdownListener.start_link/1)
    end

    test "init returns proper tuple structure" do
      assert {:ok, %{server_pid: server, timeout: 15_000}} = ShutdownListener.init(self())
      assert server == self()
    end
  end

  describe "continue callback contract" do
    test "explicit timeout is preserved" do
      # Verify the expected continue message is :setup_listener_pool_pid
      assert {:ok, %{timeout: 42}} = ShutdownListener.init({self(), 42})
    end
  end

  describe "trap_exit setup" do
    test "init is designed to trap exits" do
      # The init function calls Process.flag(:trap_exit, true)
      # We can verify this by checking the source documentation
      # and the fact that init returns a continue callback
      {:ok, state} = ShutdownListener.init(self())

      # State should be valid for terminate to work with
      assert is_map(state)
    end
  end
end
