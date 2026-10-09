defmodule HTTP.StreamTest do
  use ExUnit.Case, async: false

  test "exits after flushing a completed stream to its reader" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    monitor_ref = Process.monitor(stream)

    send(stream, {:read_chunk, self()})
    HTTP.Stream.chunk(stream, "hello")
    HTTP.Stream.finish(stream)

    assert_receive {:stream_chunk, ^stream, "hello"}
    assert_receive {:stream_end, ^stream}
    assert_receive {:DOWN, ^monitor_ref, :process, ^stream, :normal}
    refute_receive {:stream_error, ^stream, :timeout}, 50
  end

  test "ack readers apply backpressure until chunks are acknowledged" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    send(stream, {:read_chunk, self(), :ack})

    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "hello", 1_000) end)

    assert_receive {:stream_chunk, ^stream, "hello", ack_ref}
    refute Task.yield(producer, 50)

    send(stream, {:stream_chunk_ack, ack_ref})
    assert Task.await(producer) == :ok

    HTTP.Stream.finish(stream)
    assert_receive {:stream_end, ^stream}
  end

  test "completed empty streams wait for a late reader" do
    previous_timeout = Application.get_env(:http_fetch, :streaming_timeout)
    Application.put_env(:http_fetch, :streaming_timeout, 10)

    on_exit(fn ->
      if is_nil(previous_timeout) do
        Application.delete_env(:http_fetch, :streaming_timeout)
      else
        Application.put_env(:http_fetch, :streaming_timeout, previous_timeout)
      end
    end)

    {:ok, stream} = HTTP.Stream.start_link(0)
    monitor_ref = Process.monitor(stream)

    HTTP.Stream.finish(stream)
    refute_receive {:DOWN, ^monitor_ref, :process, ^stream, :normal}, 30

    send(stream, {:read_chunk, self()})

    assert_receive {:stream_end, ^stream}
    assert_receive {:DOWN, ^monitor_ref, :process, ^stream, :normal}
  end

  test "terminal errors bypass an outstanding reader ACK and release producer" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    send(stream, {:read_chunk, self(), :ack})
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "pending", 1_000) end)
    assert_receive {:stream_chunk, ^stream, "pending", _ref}
    HTTP.Stream.error(stream, :reset)
    assert_receive {:stream_error, ^stream, :reset}
    assert {:error, :reset} = Task.await(producer)
  end

  test "reader death releases a blocked producer and terminates stream" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    parent = self()

    reader =
      spawn(fn ->
        send(stream, {:read_chunk, self(), :ack})

        receive do
          {:stream_chunk, ^stream, "pending", _ref} -> send(parent, :reader_received)
        end

        receive do
          :stop -> :ok
        end
      end)

    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "pending", 1_000) end)
    assert_receive :reader_received
    monitor = Process.monitor(stream)
    send(reader, :stop)
    assert {:error, {:reader_down, :normal}} = Task.await(producer)
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}
  end

  test "completion trailers wait for the outstanding body acknowledgement" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    send(stream, {:read_chunk, self(), :ack})
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "data") end)
    assert_receive {:stream_chunk, ^stream, "data", ref}
    assert :ok = HTTP.Stream.finish(stream, [{"X-Checksum", "one"}, {"X-Checksum", "two"}])
    refute_receive {:stream_trailers, ^stream, _}, 0
    send(stream, {:stream_chunk_ack, ref})
    assert :ok = Task.await(producer)
    assert_receive {:stream_trailers, ^stream, headers}
    assert headers.headers == [{"X-Checksum", "one"}, {"X-Checksum", "two"}]
    assert_receive {:stream_end, ^stream}
  end

  test "invalid completion trailers do not terminate the stream" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    send(stream, {:read_chunk, self(), :ack})
    assert {:error, :invalid_trailer} = HTTP.Stream.finish(stream, [{"Bad Field", "one"}])
    assert {:error, {:forbidden_trailer, "host"}} = HTTP.Stream.finish(stream, [{"Host", "one"}])

    assert {:error, :trailers_too_large} =
             HTTP.Stream.finish(stream, List.duplicate({"X", "one"}, 129))

    assert {:error, :trailers_too_large} =
             HTTP.Stream.finish(stream, [{"X", String.duplicate("a", 65_530)}])

    refute_receive {:stream_end, ^stream}, 0
    assert :ok = HTTP.Stream.finish(stream, [])
    assert_receive {:stream_end, ^stream}
  end
end
