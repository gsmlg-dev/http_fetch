defmodule HTTP.WebSocket.DiagnosticsTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Connection
  alias HTTP.WebSocket.Event.Open

  @timeout 5_000

  setup do
    observer = fn event, owner ->
      send(owner, {:raw_log, event})
      :ignore
    end

    :ok = :logger.add_primary_filter(__MODULE__, {observer, self()})
    on_exit(fn -> :logger.remove_primary_filter(__MODULE__) end)
    :ok
  end

  @tag :integration
  test "actual OTP status hides opening URL and private TLS options" do
    secret = "opening-diagnostic-secret"
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    owner = self()

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, _request} = :gen_tcp.recv(socket, 0, @timeout)
        send(owner, {:upgrade_pending, self()})
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, @timeout)
        send(owner, {:peer_closed, self()})
      end)

    on_exit(fn -> :gen_tcp.close(listener) end)

    ws =
      WebSocket.new("ws://127.0.0.1:#{port}/?token=#{secret}", [],
        ssl: [keyfile: "/run/secrets/#{secret}"],
        opening_timeout: 30_000
      )

    monitor = Process.monitor(ws.pid)
    assert_receive {:upgrade_pending, ^peer}, @timeout
    status = :sys.get_status(ws.pid)
    refute inspect(status, limit: :infinity) =~ secret
    assert inspect(status) =~ "ready_state"
    assert WebSocket.ready_state(ws) == WebSocket.connecting()
    assert :ok = WebSocket.close(ws)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, @timeout
    assert_receive {:peer_closed, ^peer}, @timeout
  end

  @tag :integration
  test "actual termination reports and monitored reason hide private exit and pending input" do
    ws = open_connection("exit-diagnostic-secret")
    monitor = Process.monitor(ws.pid)
    :ok = :sys.log(ws.pid, true)
    send(ws.pid, {:recent_input, "recent-diagnostic-secret"})
    _ = :sys.get_state(ws.pid)

    rendered =
      capture_log(fn ->
        :ok = :sys.suspend(ws.pid)
        send(ws.pid, {:EXIT, self(), {:private, "exit-diagnostic-secret"}})
        send(ws.pid, {:private_pending, "pending-diagnostic-secret"})
        :ok = :sys.resume(ws.pid)
        assert_receive {:DOWN, ^monitor, :process, _, :shutdown}, @timeout
        await_child_removed(ws.pid, System.monotonic_time(:millisecond) + @timeout)
        assert_receive {:raw_log, %{meta: %{pid: pid}} = report} when pid == ws.pid, @timeout
        refute inspect(report, limit: :infinity) =~ "diagnostic-secret"
        assert match?({:report, %{label: {:gen_server, :terminate}}}, report.msg)
        assert_no_private_reports()
      end)

    refute rendered =~ "diagnostic-secret"
    assert rendered =~ "terminating"
    assert_receive :websocket_server_closed, @timeout
  end

  test "status callback validates every summary field and drops all other values" do
    secret = "callback-diagnostic-secret"

    private_state =
      Map.new(Map.from_struct(%Connection{}), fn {key, _value} -> {key, secret} end)

    input = %{
      state: private_state,
      message: {:request, secret},
      reason: {:error, secret},
      log: [{:in, secret}],
      future_field: secret
    }

    output = Connection.format_status(input)
    assert Map.keys(output) == Map.keys(input)
    assert output.message == :redacted
    assert output.reason == :redacted
    assert output.log == []
    assert output.future_field == :redacted
    assert Enum.all?(Map.values(output.state), &is_nil/1)
    refute inspect(output, limit: :infinity) =~ secret
    assert Connection.format_status(%{state: secret}) == %{state: :redacted}

    valid = %Connection{
      http_version: :http1,
      ready_state: WebSocket.open(),
      binary_type: :blob,
      fallback?: false,
      raw_bytes: 12,
      buffered_amount: 34,
      pending_send_frames: 2,
      control_frames: 1
    }

    assert Connection.format_status(%{state: valid}).state == %{
             http_version: :http1,
             ready_state: WebSocket.open(),
             binary_type: :blob,
             fallback?: false,
             raw_bytes: 12,
             buffered_amount: 34,
             pending_send_frames: 2,
             control_frames: 1
           }

    malformed = %{
      valid
      | ready_state: -1,
        raw_bytes: -1,
        buffered_amount: 1.5,
        control_frames: true
    }

    summary = Connection.format_status(%{state: malformed}).state
    assert summary.ready_state == nil
    assert summary.raw_bytes == nil
    assert summary.buffered_amount == nil
    assert summary.control_frames == nil
  end

  @tag :integration
  test "default OTP status hides parser and delivery queues without changing state" do
    ws = open_connection("status-diagnostic-secret")

    private =
      :sys.replace_state(ws.pid, fn state ->
        %{
          state
          | parser: %{state.parser | buffer: "parser-diagnostic-secret"},
            raw_queue: :queue.from_list(["raw-diagnostic-secret"]),
            delivery: %{state.delivery | queue: :queue.from_list(["delivery-diagnostic-secret"])}
        }
      end)

    status = :sys.get_status(ws.pid)
    refute inspect(status, limit: :infinity) =~ "diagnostic-secret"
    assert :sys.get_state(ws.pid) == private
    # Restore the parser and queues before exercising ordinary traffic.
    :sys.replace_state(ws.pid, fn state ->
      %{
        state
        | parser: %{state.parser | buffer: ""},
          raw_queue: :queue.new(),
          delivery: %{state.delivery | queue: :queue.new()}
      }
    end)

    assert :ok = WebSocket.send(ws, "hello")
    assert_receive {WebSocket, ^ws, %WebSocket.Event.Message{data: "echo:hello"}}, @timeout
    monitor = Process.monitor(ws.pid)
    assert :ok = WebSocket.close(ws)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, @timeout
  end

  defmodule FailingTransport do
    @moduledoc false

    def normalize_message({:callback_exception, secret}, _socket),
      do: :erlang.error({:private_callback, secret}, [secret])

    def normalize_message(_message, _socket), do: :unknown

    def close({socket, kind, secret}) do
      :gen_tcp.close(socket)

      case kind do
        :error -> :erlang.error({:private_cleanup, secret}, [secret])
        :throw -> throw({:private_cleanup, secret})
        :exit -> exit({:private_cleanup, secret})
        :ok -> :ok
      end
    end
  end

  @tag :integration
  test "callback exception arguments are absent from raw and rendered crash reports" do
    ws = open_connection("exception-diagnostic-secret")
    install_transport(ws, :ok, "cleanup-diagnostic-secret")

    assert_private_termination(ws, fn ->
      send(ws.pid, {:callback_exception, "exception-diagnostic-secret"})
    end)
  end

  for kind <- [:error, :throw, :exit],
      reason <- [:normal, {:private, "reason-diagnostic-secret"}] do
    @tag :integration
    test "cleanup #{kind} during #{inspect(reason)} termination is safe" do
      ws = open_connection("cleanup-url-diagnostic-secret")
      install_transport(ws, unquote(kind), "cleanup-diagnostic-secret")

      assert_private_termination(ws, fn ->
        # A separate caller permits stop/3 to observe the normalized shutdown.
        spawn(fn ->
          try do
            GenServer.stop(ws.pid, unquote(Macro.escape(reason)))
          catch
            :exit, _reason -> :ok
          end
        end)
      end)
    end
  end

  defp install_transport(ws, kind, secret) do
    :sys.replace_state(ws.pid, fn state ->
      %{state | transport: FailingTransport, socket: {state.socket, kind, secret}}
    end)
  end

  defp assert_private_termination(ws, trigger) do
    monitor = Process.monitor(ws.pid)

    rendered =
      capture_log(fn ->
        trigger.()
        assert_receive {:DOWN, ^monitor, :process, _, :shutdown}, @timeout
        await_child_removed(ws.pid, System.monotonic_time(:millisecond) + @timeout)
        assert_receive {:raw_log, %{meta: %{pid: pid}} = report} when pid == ws.pid, @timeout
        assert match?({:report, %{label: {:gen_server, :terminate}}}, report.msg)
        refute inspect(report, limit: :infinity) =~ "diagnostic-secret"
        assert_no_private_reports()
      end)

    assert rendered =~ "terminating"
    refute rendered =~ "diagnostic-secret"
    assert_receive :websocket_server_closed, @timeout
  end

  defp await_child_removed(pid, deadline) do
    children = DynamicSupervisor.which_children(WebSocket.ConnectionSupervisor)

    if Enum.any?(children, fn {_id, child, _type, _modules} -> child == pid end) do
      assert System.monotonic_time(:millisecond) < deadline
      await_child_removed(pid, deadline)
    end
  end

  defp assert_no_private_reports do
    receive do
      {:raw_log, report} ->
        refute inspect(report, limit: :infinity) =~ "diagnostic-secret"
        assert_no_private_reports()
    after
      0 -> :ok
    end
  end

  defp open_connection(secret) do
    {:ok, _peer, port} = HTTPWebSocket.TestServer.start_link()
    ws = WebSocket.new("ws://127.0.0.1:#{port}/?token=#{secret}")
    on_exit(fn -> if Process.alive?(ws.pid), do: Process.exit(ws.pid, :kill) end)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    ws
  end
end
