defmodule HTTP.WebTransport.OperationTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport
  alias HTTP.WebTransport.{FakeBackend, Operation}

  test "expired admission cannot open a stream; duplicate ref returns retained result" do
    transport = WebTransport.new("https://example.com/wt", backend: FakeBackend)
    assert :ok = WebTransport.await_ready(transport, 1_000)
    ref = make_ref()

    request =
      {:operation, ref, System.monotonic_time(:millisecond) - 1,
       {:create_unidirectional_stream, []}}

    assert {:error, :deadline_exceeded} = GenServer.call(transport.pid, request)
    assert :sys.get_state(transport.pid).streams == %{}
    assert {:error, :deadline_exceeded} = WebTransport.operation_status(transport, ref)
    assert {:error, :deadline_exceeded} = GenServer.call(transport.pid, request)

    ref = make_ref()

    request =
      {:operation, ref, System.monotonic_time(:millisecond) + 1_000,
       {:create_unidirectional_stream, []}}

    assert {:ok, stream} = GenServer.call(transport.pid, request)
    assert {:ok, ^stream} = GenServer.call(transport.pid, request)
    assert map_size(:sys.get_state(transport.pid).streams) == 1
  end

  test "caller timeout reports indeterminate ref and permits outcome reconciliation" do
    transport =
      WebTransport.new("https://example.com/wt",
        backend: __MODULE__.BlockingBackend,
        owner: self()
      )

    assert :ok = WebTransport.await_ready(transport, 1_000)
    caller = self()

    spawn(fn ->
      send(caller, {:result, Operation.call(transport.pid, {:send_datagram, "a", []}, 20)})
    end)

    assert_receive {:backend_started, backend}
    assert_receive {:result, {:error, {:indeterminate_operation, ref}}}
    send(backend, :continue)
    assert :ok = WebTransport.operation_status(transport, ref)
  end

  test "backend cleanup occurs once across close, duplicate failure and termination" do
    transport = WebTransport.new("https://example.com/wt", backend: __MODULE__.BlockingBackend)
    assert :ok = WebTransport.await_ready(transport, 1_000)
    assert :ok = WebTransport.close(transport)
    assert :ok = WebTransport.close(transport)
    send(transport.pid, {:webtransport_failed, self(), :late})
    assert WebTransport.state(transport) == :closed
    GenServer.stop(transport.pid)
    assert_receive {:backend_closed, _}
    refute_received {:backend_closed, _}
  end

  test "cleanup errors are retained and returned without replaying backend close" do
    transport =
      WebTransport.new("https://example.com/wt", backend: __MODULE__.FailingCloseBackend)

    assert :ok = WebTransport.await_ready(transport, 1_000)
    assert {:error, {:cleanup_failed, :receipt_pending}} = WebTransport.close(transport)
    assert_receive :close_attempt
    assert {:error, {:cleanup_failed, :receipt_pending}} = WebTransport.close(transport)
    refute_received :close_attempt
    assert :sys.get_state(transport.pid).backend_close_result == {:error, :receipt_pending}
  end

  defmodule FailingCloseBackend do
    @behaviour HTTP.WebTransport.Transport
    defdelegate connect(uri, options), to: HTTP.WebTransport.OperationTest.BlockingBackend

    def close(owner, _info) do
      send(owner, :close_attempt)
      {:error, :receipt_pending}
    end

    defdelegate get_stats(ref), to: FakeBackend
    defdelegate open_bidirectional_stream(ref, options), to: FakeBackend
    defdelegate open_unidirectional_stream(ref, options), to: FakeBackend
    defdelegate send_datagram(ref, bytes, options), to: FakeBackend
    defdelegate recv_stream(ref, timeout), to: FakeBackend
    defdelegate send_stream(ref, data, options), to: FakeBackend
    defdelegate close_send_stream(ref), to: FakeBackend
    defdelegate abort_send_stream(ref, code), to: FakeBackend
    defdelegate cancel_receive_stream(ref, code), to: FakeBackend
  end

  defmodule BlockingBackend do
    @behaviour HTTP.WebTransport.Transport
    def connect(uri, options) do
      {:ok, _ref, info} = FakeBackend.connect(uri, options)
      {:ok, options.owner, info}
    end

    def send_datagram(owner, _bytes, _options) do
      send(owner, {:backend_started, self()})

      receive do
        :continue -> :ok
      after
        1_000 -> {:error, :backend_timeout}
      end
    end

    def close(owner, info) do
      send(owner, {:backend_closed, info})
      :ok
    end

    defdelegate get_stats(ref), to: FakeBackend
    defdelegate open_bidirectional_stream(ref, options), to: FakeBackend
    defdelegate open_unidirectional_stream(ref, options), to: FakeBackend
    defdelegate recv_stream(ref, timeout), to: FakeBackend
    defdelegate send_stream(ref, data, options), to: FakeBackend
    defdelegate close_send_stream(ref), to: FakeBackend
    defdelegate abort_send_stream(ref, code), to: FakeBackend
    defdelegate cancel_receive_stream(ref, code), to: FakeBackend
  end
end
