defmodule HTTP.HTTP1.UploadTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP1.Upload

  defmodule BlockedTransport do
    def send(test_pid, data) do
      Kernel.send(test_pid, {:blocked_write, self(), IO.iodata_to_binary(data)})

      receive do
        :release_write -> :ok
      end
    end
  end

  test "blocked writes hold one bounded source chunk until acknowledgement and stop confirms cleanup" do
    {:ok, source} = HTTP.Stream.start_link(0)
    deadline = System.monotonic_time(:millisecond) + 2_000
    upload = Upload.start(BlockedTransport, self(), source, nil, deadline)
    chunk = :binary.copy("x", 65_536)
    producer = Task.async(fn -> HTTP.Stream.chunk(source, chunk) end)
    assert_receive {:blocked_write, worker, wire}, 1_000
    assert worker == upload.pid
    assert wire == ["10000\r\n", chunk, "\r\n"] |> IO.iodata_to_binary()
    assert Task.yield(producer, 0) == nil
    assert {:message_queue_len, 0} = Process.info(worker, :message_queue_len)

    assert :ok = Upload.stop(upload, :early_response, deadline)
    refute Process.alive?(worker)
    refute Process.alive?(source)
    assert {:error, _reason} = Task.await(producer)
  end

  test "source chunks above the byte bound fail before any write" do
    {:ok, source} = HTTP.Stream.start_link(0)
    deadline = System.monotonic_time(:millisecond) + 2_000
    upload = Upload.start(BlockedTransport, self(), source, nil, deadline)
    token = upload.token
    producer = Task.async(fn -> HTTP.Stream.chunk(source, :binary.copy("x", 65_537)) end)
    assert_receive {:http1_upload, ^token, {:error, :buffer_limit}}, 1_000
    refute_receive {:blocked_write, _, _}
    assert :ok = Upload.stop(upload, :buffer_limit, deadline)
    assert {:error, _reason} = Task.await(producer)
    refute Process.alive?(source)
  end

  test "owner death tears down a blocked writer and its source" do
    test_pid = self()
    {:ok, source} = HTTP.Stream.start_link(0)
    source_monitor = Process.monitor(source)

    owner =
      spawn(fn ->
        upload =
          Upload.start(
            BlockedTransport,
            test_pid,
            source,
            nil,
            System.monotonic_time(:millisecond) + 2_000
          )

        send(test_pid, {:upload_worker, upload.pid})

        receive do
          :never -> :ok
        end
      end)

    assert_receive {:upload_worker, worker}
    worker_monitor = Process.monitor(worker)
    producer = Task.async(fn -> HTTP.Stream.chunk(source, "pending") end)
    assert_receive {:blocked_write, ^worker, _}, 1_000
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^worker_monitor, :process, ^worker, :killed}, 1_000
    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1_000
    assert {:error, _reason} = Task.await(producer)
  end
end
