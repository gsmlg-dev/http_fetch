defmodule HTTP.ResponseStreamAckPolicyTest do
  use ExUnit.Case, async: false

  setup do
    old = Application.get_env(:http_fetch, :streaming_timeout)
    Application.put_env(:http_fetch, :streaming_timeout, 100)

    on_exit(fn ->
      if old == nil,
        do: Application.delete_env(:http_fetch, :streaming_timeout),
        else: Application.put_env(:http_fetch, :streaming_timeout, old)
    end)

    :ok
  end

  test "infinite ACK policy retains a bounded chunk beyond the global timeout" do
    stream = start_stream(ack_timeout: :infinity)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "paced", :infinity) end)
    assert_receive {:stream_chunk, ^stream, "paced", ref}
    refute_receive {:stream_error, ^stream, _}, 250
    assert Process.alive?(producer.pid)
    send(stream, {:stream_chunk_ack, ref})
    assert :ok = Task.await(producer)
    HTTP.Stream.finish(stream)
    assert_receive {:stream_end, ^stream}
  end

  test "finite ACK policy replaces the global timeout" do
    stream = start_stream(ack_timeout: 350)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "paced", :infinity) end)
    assert_receive {:stream_chunk, ^stream, "paced", _ref}
    refute_receive {:stream_error, ^stream, _}, 200
    assert_receive {:stream_error, ^stream, :timeout}, 400
    assert {:error, :timeout} = Task.await(producer)
  end

  test "reader controls and stale ACKs cannot renew a finite pending ACK deadline" do
    stream = start_stream(ack_timeout: 150)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "paced", :infinity) end)
    assert_receive {:stream_chunk, ^stream, "paced", _ref}
    reader = self()
    controls = spawn(fn -> send_controls(stream, reader) end)
    on_exit(fn -> send(controls, :stop) end)
    assert_receive {:stream_error, ^stream, :timeout}, 350
    assert {:error, :timeout} = Task.await(producer)
    send(controls, :stop)
  end

  test "buffered chunks awaiting a reader use the explicit ACK budget" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], ack_timeout: :infinity, telemetry: false)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "buffered", :infinity) end)
    refute_receive {:stream_error, ^stream, _}, 250
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "buffered", ref}
    send(stream, {:stream_chunk_ack, ref})
    assert :ok = Task.await(producer)
    HTTP.Stream.finish(stream)
    assert_receive {:stream_end, ^stream}
  end

  test "nil retains the finite global ACK limit" do
    stream = start_stream(ack_timeout: nil)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "paced", :infinity) end)
    assert_receive {:stream_chunk, ^stream, "paced", _ref}
    assert_receive {:stream_error, ^stream, :timeout}, 500
    assert {:error, :timeout} = Task.await(producer)
  end

  test "infinite ACK policy does not disable an explicit finite network idle clock" do
    stream = start_stream(ack_timeout: :infinity, idle_timeout: 150)
    assert_receive {:stream_error, ^stream, :timeout}, 500
  end

  test "valid ACK progress starts a fresh delivery budget for the next chunk" do
    stream = start_stream(ack_timeout: 350)

    for chunk <- ["one", "two"] do
      producer = Task.async(fn -> HTTP.Stream.chunk(stream, chunk, :infinity) end)
      assert_receive {:stream_chunk, ^stream, ^chunk, ref}
      refute_receive {:stream_error, ^stream, _}, 200
      send(stream, {:stream_chunk_ack, ref})
      assert :ok = Task.await(producer)
    end

    HTTP.Stream.finish(stream)
    assert_receive {:stream_end, ^stream}
  end

  test "a queued finish cannot suppress a finite outstanding ACK deadline" do
    stream = start_stream(ack_timeout: 150)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "last", :infinity) end)
    assert_receive {:stream_chunk, ^stream, "last", _ref}
    HTTP.Stream.finish(stream)
    assert_receive {:stream_error, ^stream, :timeout}, 500
    assert {:error, :timeout} = Task.await(producer)
  end

  test "reader death interrupts an infinite ACK wait" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], ack_timeout: :infinity, telemetry: false)
    monitor = Process.monitor(stream)
    owner = self()

    reader =
      spawn(fn ->
        send(stream, {:read_chunk, self(), :ack})

        receive do
          {:stream_chunk, ^stream, _, _} -> send(owner, :reader_received)
        end

        receive do
          :stop -> :ok
        end
      end)

    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "paced", :infinity) end)
    assert_receive :reader_received
    send(reader, :stop)
    assert {:error, {:reader_down, :normal}} = Task.await(producer)
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}
  end

  defp start_stream(opts) do
    {:ok, stream} =
      HTTP.Stream.start_link(
        0,
        [],
        Keyword.merge([idle_timeout: :infinity, telemetry: false], opts)
      )

    send(stream, {:read_chunk, self(), :ack})
    stream
  end

  defp send_controls(stream, reader) do
    receive do
      :stop -> :ok
    after
      20 ->
        send(stream, {:read_chunk, reader, :ack})
        send(stream, {:stream_chunk_ack, make_ref()})
        send_controls(stream, reader)
    end
  end
end
