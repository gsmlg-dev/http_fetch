defmodule HTTP.ResponseStreamIdlePolicyTest do
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

  test "explicit infinite network wait survives the legacy timer and receives later bytes" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], idle_timeout: :infinity, telemetry: false)
    send(stream, {:read_chunk, self(), :ack})
    refute_receive {:stream_error, ^stream, _}, 250
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "later") end)
    assert_receive {:stream_chunk, ^stream, "later", ref}, 1_000
    send(stream, {:stream_chunk_ack, ref})
    assert :ok = Task.await(producer)
    HTTP.Stream.finish(stream)
    assert_receive {:stream_end, ^stream}, 1_000
  end

  test "explicit finite network wait replaces the legacy timer" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], idle_timeout: 350, telemetry: false)
    send(stream, {:read_chunk, self(), :ack})
    refute_receive {:stream_error, ^stream, _}, 200
    assert_receive {:stream_error, ^stream, :timeout}, 500
  end

  test "reader controls and stale acknowledgements cannot extend a finite network wait" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], idle_timeout: 150, telemetry: false)
    send(stream, {:read_chunk, self(), :ack})
    reader = self()
    controls = spawn(fn -> send_controls(stream, reader) end)

    on_exit(fn ->
      send(controls, :stop)
      HTTP.Stream.stop(stream, :fixture_cleanup)
    end)

    assert_receive {:stream_error, ^stream, :timeout}, 350
    monitor = Process.monitor(controls)
    send(controls, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^controls, :normal}, 1_000
  end

  test "compressed input renews network idle even before decoded output is available" do
    {:ok, stream} = HTTP.Stream.start_link(0, ["gzip"], idle_timeout: 500, telemetry: false)
    send(stream, {:read_chunk, self(), :ack})
    <<header::binary-size(10), tail::binary>> = :zlib.gzip("decoded")
    Process.send_after(self(), :send_compressed_header, 300)
    assert_receive :send_compressed_header, 1_000
    assert :ok = HTTP.Stream.chunk(stream, header)
    refute_receive {:stream_chunk, ^stream, _, _}, 0
    Process.send_after(self(), :send_compressed_tail, 300)
    assert_receive :send_compressed_tail, 1_000
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, tail) end)
    assert_receive {:stream_chunk, ^stream, "decoded", ref}, 1_000
    send(stream, {:stream_chunk_ack, ref})
    assert :ok = Task.await(producer)
    HTTP.Stream.finish(stream)
    assert_receive {:stream_end, ^stream}, 1_000
  end

  test "infinite network policy does not disable acknowledgement safety" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], idle_timeout: :infinity, telemetry: false)
    send(stream, {:read_chunk, self(), :ack})
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "unacknowledged", 1_000) end)
    assert_receive {:stream_chunk, ^stream, "unacknowledged", _ref}, 1_000
    assert {:error, :timeout} = Task.await(producer)
    assert_receive {:stream_error, ^stream, :timeout}, 1_000
  end

  test "legacy response reader timeout stops its stream" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], idle_timeout: :infinity, telemetry: false)
    monitor = Process.monitor(stream)
    response = HTTP.Response.new(stream: stream)

    assert_raise RuntimeError, "stream read failed: :timeout", fn ->
      HTTP.Response.read_all(response)
    end

    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
  end

  for reader <- [:read_all, :write_to] do
    if reader == :write_to, do: @tag(:integration)

    test "#{reader} observes stream DOWN without an infinite receive or leaked monitor" do
      stream =
        spawn(fn ->
          receive do
            {:read_chunk, _reader, :ack} -> exit(:fixture_stream_failure)
          end
        end)

      response = HTTP.Response.with_stream_body(HTTP.Response.new(), stream, :infinity)
      monitors = Process.info(self(), :monitors)

      case unquote(reader) do
        :read_all ->
          assert_raise RuntimeError,
                       "stream read failed: {:stream_down, :fixture_stream_failure}",
                       fn ->
                         HTTP.Response.read_all(response)
                       end

        :write_to ->
          path =
            Path.join(System.tmp_dir!(), "stream-idle-down-#{System.unique_integer([:positive])}")

          on_exit(fn -> File.rm(path) end)

          assert {:error, {:stream_down, :fixture_stream_failure}} =
                   HTTP.Response.write_to(response, path)
      end

      assert Process.info(self(), :monitors) == monitors
    end

    if reader == :write_to, do: @tag(:integration)

    test "#{reader} removes its monitor after a terminal event from a still-live stream" do
      stream =
        spawn(fn ->
          receive do
            {:read_chunk, reader, :ack} -> send(reader, {:stream_end, self()})
          end

          receive do
            :stop -> :ok
          end
        end)

      on_exit(fn -> send(stream, :stop) end)
      response = HTTP.Response.with_stream_body(HTTP.Response.new(), stream, :infinity)
      monitors = Process.info(self(), :monitors)

      case unquote(reader) do
        :read_all ->
          assert HTTP.Response.read_all(response) == ""

        :write_to ->
          path =
            Path.join(System.tmp_dir!(), "stream-idle-end-#{System.unique_integer([:positive])}")

          on_exit(fn -> File.rm(path) end)
          assert :ok = HTTP.Response.write_to(response, path)
      end

      assert Process.alive?(stream)
      assert Process.info(self(), :monitors) == monitors
    end
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
