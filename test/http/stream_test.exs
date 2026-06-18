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
end
