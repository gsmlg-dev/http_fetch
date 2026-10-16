defmodule HTTP.UploadFinalizationTest do
  use ExUnit.Case, async: false

  alias HTTP.HTTP1.Upload

  defmodule GatedTransport do
    def send(test, bytes) do
      Kernel.send(test, {:native_write, self(), IO.iodata_to_binary(bytes)})

      receive do
        :release_write -> :ok
        :stop_write -> exit(:normal)
      end
    end
  end

  setup do
    previous = Application.fetch_env(:http_fetch, :streaming_timeout)
    Application.put_env(:http_fetch, :streaming_timeout, 250)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:http_fetch, :streaming_timeout, value)
        :error -> Application.delete_env(:http_fetch, :streaming_timeout)
      end
    end)

    :ok
  end

  test "final-write eligibility is visible while its native send is still blocked" do
    {:ok, stream} = HTTP.Stream.start_link(4, [], telemetry: false)
    upload = Upload.start(GatedTransport, self(), stream, 4, :infinity)
    assert Upload.completion_deadline(upload) == nil
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "data") end)
    assert_receive {:native_write, worker, "data"}
    assert worker == upload.pid
    assert is_integer(Upload.completion_deadline(upload))
    assert Task.yield(producer, 0) == nil
    send(worker, :release_write)
    assert Task.await(producer) == :ok
    HTTP.Stream.finish(stream)
    token = upload.token
    assert_receive {:http1_upload, ^token, :ok}
    Upload.completed(upload)
  end

  test "zero-length eligibility is visible before a blocked header send returns" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], telemetry: false)
    upload = Upload.start(GatedTransport, self(), stream, 0, :infinity, %HTTP.Headers{}, "HEAD")
    assert_receive {:native_write, worker, "HEAD"}
    assert is_integer(Upload.completion_deadline(upload))
    send(worker, :release_write)
    HTTP.Stream.finish(stream)
    token = upload.token
    assert_receive {:http1_upload, ^token, :ok}
    Upload.completed(upload)
  end

  test "a final send consuming the source budget cannot be accepted without response headers" do
    {:ok, stream} =
      HTTP.Stream.start_link(4, [],
        telemetry: false,
        idle_timeout: :infinity,
        ack_timeout: :infinity
      )

    # Keep the stream's own clock independent of the earlier upload deadline.
    upload = Upload.start(GatedTransport, self(), stream, 4, :infinity)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "data", :infinity) end)
    assert_receive {:native_write, worker, "data"}
    deadline = Upload.completion_deadline(upload)
    assert is_integer(deadline)

    timer =
      Process.send_after(
        self(),
        :release_due,
        max(deadline - System.monotonic_time(:millisecond) + 20, 0)
      )

    assert is_reference(timer)
    assert_receive :release_due, 1_000
    send(worker, :release_write)
    token = upload.token
    assert_receive {:http1_upload, ^token, {:error, :timeout}}, 1_000
    assert Task.await(producer) == :ok
    assert Upload.stop(upload, :timeout, System.monotonic_time(:millisecond) + 1_000) == :ok
  end

  test "stop confirms a dead writer even after its original DOWN was consumed" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], telemetry: false)
    upload = Upload.start(GatedTransport, self(), stream, 0, :infinity, %HTTP.Headers{}, "HEAD")
    assert_receive {:native_write, worker, "HEAD"}
    monitor = upload.monitor
    send(worker, :stop_write)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}
    assert {:monitors, before_monitors} = Process.info(self(), :monitors)
    stopper = Task.async(fn -> Upload.stop(upload, :aborted, :infinity) end)
    assert Task.await(stopper, 1_000) == :ok
    assert Process.info(self(), :monitors) == {:monitors, before_monitors}
    refute Process.alive?(stream)
  end
end
