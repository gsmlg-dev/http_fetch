defmodule HTTP.StreamWriterTest do
  use ExUnit.Case, async: false

  alias HTTP.Stream.Writer

  test "many chunks create one producer monitor and preserve consumer credit" do
    parent = self()
    :erlang.trace_pattern({:erlang, :monitor, 2}, true, [:local])

    producer =
      spawn(fn ->
        receive do
          :start -> :ok
        end

        {:ok, stream, writer} = HTTP.Stream.start_writer(0, [], telemetry: false)
        send(parent, {:stream, stream})

        for _ <- 1..500 do
          :ok = Writer.chunk(writer, "chunk", 2_000)
        end

        HTTP.Stream.finish(stream)
        Writer.close(writer)
        send(parent, :complete)
      end)

    :erlang.trace(producer, true, [:call, {:tracer, self()}])
    on_exit(fn -> :erlang.trace_pattern({:erlang, :monitor, 2}, false, [:local]) end)
    send(producer, :start)
    assert_receive {:stream, stream}
    send(stream, {:read_chunk, self(), :ack})

    for _ <- 1..500 do
      assert_receive {:stream_chunk, ^stream, "chunk", ref}, 2_000
      refute_receive {:stream_chunk, ^stream, _, _}, 0
      send(stream, {:stream_chunk_ack, ref})
    end

    assert_receive :complete, 2_000
    assert_receive {:stream_end, ^stream}
    delivered = :erlang.trace_delivered(producer)
    assert_receive {:trace_delivered, ^producer, ^delivered}
    assert_receive {:trace, ^producer, :call, {:erlang, :monitor, [:process, ^stream]}}
    refute_receive {:trace, ^producer, :call, {:erlang, :monitor, [:process, ^stream]}}, 0
  end

  test "timeout closes credit and retains the submitted chunk until stream stop" do
    {:ok, stream, writer} = HTTP.Stream.start_writer(0, [], telemetry: false)
    send(stream, {:read_chunk, self(), :ack})
    assert {:error, :timeout} = Writer.chunk(writer, "pending", 0)
    assert {:error, :writer_closed} = Writer.chunk(writer, "again", 0)
    assert_receive {:stream_chunk, ^stream, "pending", ref}
    send(stream, {:stream_chunk_ack, ref})
    assert_receive {:stream_error, ^stream, :timeout}
    Writer.close(writer)
  end

  test "wrong producer and stale token cannot replace a pending chunk" do
    {:ok, stream, writer} = HTTP.Stream.start_writer(0, [], telemetry: false)
    task = Task.async(fn -> Writer.chunk(writer, "wrong", 0) end)
    assert {:error, :wrong_writer} = Task.await(task)
    ref = make_ref()
    send(stream, {:writer_chunk, self(), make_ref(), ref, "stale"})
    assert_receive {:chunk_error, ^ref, :writer_closed}
    send(stream, {:read_chunk, self()})
    assert :ok = Writer.chunk(writer, "right", 1_000)
    assert_receive {:stream_chunk, ^stream, "right"}
    HTTP.Stream.finish(stream)
    assert_receive {:stream_end, ^stream}
    Writer.close(writer)
  end

  for reason <- [:normal, :boom] do
    test "producer termination #{reason} without finish delivers an error to a late reader" do
      parent = self()

      producer =
        spawn(fn ->
          {:ok, stream, _writer} = HTTP.Stream.start_writer(0, [], telemetry: false)
          send(parent, {:stream, stream})

          receive do
            :stop -> exit(unquote(reason))
          end
        end)

      assert_receive {:stream, stream}
      ready = make_ref()
      send(stream, {:request_lifecycle, nil, self(), ready})
      assert_receive {:request_lifecycle_attached, ^ready}
      monitor = Process.monitor(producer)
      send(producer, :stop)
      assert_receive {:DOWN, ^monitor, :process, ^producer, unquote(reason)}
      send(stream, {:read_chunk, self(), :ack})
      assert_receive {:stream_error, ^stream, {:writer_down, unquote(reason)}}
    end
  end

  test "abort and deadline close session credit; stream termination is reported" do
    for {event, reason} <- [abort: :aborted, deadline: :request_timeout] do
      {:ok, stream, writer} = HTTP.Stream.start_writer(0, [], telemetry: false)
      send(self(), event)
      assert {:error, ^reason} = Writer.chunk(writer, "pending", 1_000)
      assert {:error, :writer_closed} = Writer.chunk(writer, "again", 0)
      send(stream, {:read_chunk, self()})
      assert_receive {:stream_error, ^stream, ^reason}
      Writer.close(writer)
    end

    {:ok, stream, writer} = HTTP.Stream.start_writer(0, [], telemetry: false)
    HTTP.Stream.stop(stream, :aborted)
    assert {:error, {:stream_down, :normal}} = Writer.chunk(writer, "pending", 1_000)
    Writer.close(writer)
  end
end
