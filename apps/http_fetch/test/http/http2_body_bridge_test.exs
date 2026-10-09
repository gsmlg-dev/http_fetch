defmodule HTTP.HTTP2BodyBridgeTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.BodyBridge

  defp fake_stream(test_pid) do
    spawn(fn ->
      receive do
        {:read_chunk, bridge, :ack} ->
          send(test_pid, {:read, bridge})
          fake_stream_loop(test_pid, bridge)
      end
    end)
  end

  defp fake_stream_loop(test_pid, bridge) do
    receive do
      {:send_chunk, chunk} ->
        ref = make_ref()
        send(bridge, {:stream_chunk, self(), chunk, ref})
        send(test_pid, {:chunk_ref, ref})
        fake_stream_loop(test_pid, bridge)

      :eof ->
        send(bridge, {:stream_end, self()})

      {:read_chunk, ^bridge, :ack} ->
        send(test_pid, {:read, bridge})
        fake_stream_loop(test_pid, bridge)
    end
  end

  test "does not read without credit and forwards one acknowledged chunk" do
    stream = fake_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, self(), max_chunk_bytes: 8)
    refute_receive {:read, ^bridge}, 20
    assert :ok = BodyBridge.credit(bridge, 8)
    assert_receive {:read, ^bridge}
    send(stream, {:send_chunk, "hello"})
    assert_receive {:body_chunk, ^bridge, "hello", ref}, 500

    assert %{buffered_bytes: 5, max_buffer_bytes: 65_536, peak_buffered_bytes: 5} =
             BodyBridge.status(bridge)

    assert :ok = BodyBridge.ack(bridge, ref)
    assert %{buffered_bytes: 0, inflight: nil, peak_buffered_bytes: 5} = BodyBridge.status(bridge)
    assert_receive {:read, ^bridge}
  end

  test "fixed-length credit withholds producer acknowledgement until every slice is sent" do
    {:ok, stream} = HTTP.Stream.start_link(6)

    {:ok, bridge} =
      BodyBridge.start_link(stream, self(), content_length: 6, max_chunk_bytes: 3)

    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "abcdef") end)
    :ok = BodyBridge.credit(bridge, 3)
    assert_receive {:body_chunk, ^bridge, "abc", first}
    assert Task.yield(producer, 0) == nil
    :ok = BodyBridge.ack(bridge, first)
    assert_receive {:body_chunk, ^bridge, "def", second}
    assert Task.yield(producer, 0) == nil
    :ok = BodyBridge.ack(bridge, second)
    assert Task.await(producer) == :ok
    HTTP.Stream.finish(stream)
    assert_receive {:body_eof, ^bridge}
  end

  test "fixed-length cancellation fails the waiting producer" do
    {:ok, stream} = HTTP.Stream.start_link(6)
    {:ok, bridge} = BodyBridge.start_link(stream, self(), content_length: 6)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "abcdef") end)
    :ok = BodyBridge.credit(bridge, 3)
    assert_receive {:body_chunk, ^bridge, "abc", _ref}
    :ok = BodyBridge.cancel(bridge)
    assert Task.await(producer) == {:error, :cancelled}
    assert_receive {:body_error, ^bridge, :cancelled}
    refute_receive {:body_eof, ^bridge}
  end

  test "credit pauses after one chunk and EOF is delivered once" do
    stream = fake_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, self(), max_chunk_bytes: 8)
    :ok = BodyBridge.credit(bridge, 5)
    assert_receive {:read, ^bridge}
    send(stream, {:send_chunk, "12345"})
    assert_receive {:body_chunk, ^bridge, "12345", ref}, 500
    refute_receive {:read, ^bridge}, 20
    :ok = BodyBridge.ack(bridge, ref)
    assert_receive {:read, ^bridge}
    send(stream, :eof)
    assert_receive {:body_eof, ^bridge}, 500
    assert BodyBridge.status(bridge).eof?
  end

  test "splits a source chunk into bounded owner chunks and acknowledges its source once" do
    stream = fake_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, self(), max_chunk_bytes: 4, max_buffer_bytes: 8)
    :ok = BodyBridge.credit(bridge, 4)
    assert_receive {:read, ^bridge}
    send(stream, {:send_chunk, "12345678"})
    assert_receive {:body_chunk, ^bridge, "1234", first}, 500
    assert %{buffered_bytes: 8, peak_buffered_bytes: 8, credit: 0} = BodyBridge.status(bridge)
    refute_receive {:read, ^bridge}, 20
    assert :ok = BodyBridge.ack(bridge, first)
    assert_receive {:body_chunk, ^bridge, "5678", second}, 500
    assert second != first
    refute_receive {:read, ^bridge}, 20
    assert :ok = BodyBridge.ack(bridge, second)
    assert %{buffered_bytes: 0, peak_buffered_bytes: 8} = BodyBridge.status(bridge)
    assert_receive {:read, ^bridge}
  end

  test "caps admitted credit and rejects source chunks larger than the buffer" do
    stream = fake_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, self(), max_chunk_bytes: 4, max_buffer_bytes: 8)
    assert :ok = BodyBridge.credit(bridge, 100)
    assert :ok = BodyBridge.credit(bridge, 100)
    assert %{credit: 8} = BodyBridge.status(bridge)
    assert_receive {:read, ^bridge}
    refute_receive {:read, ^bridge}, 20
    send(stream, {:send_chunk, "123456789"})
    assert_receive {:body_error, ^bridge, :buffer_limit}, 500
    assert BodyBridge.status(bridge).stopped?
  end

  test "an intentional early response does not fail the owner" do
    stream = fake_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, self())
    assert :ok = BodyBridge.early_response(bridge)
    assert BodyBridge.status(bridge).stopped?
    refute_receive {:body_error, ^bridge, _reason}, 20
  end

  test "owner release stops the bridge without a body error" do
    stream = fake_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, self())
    monitor = Process.monitor(bridge)
    GenServer.cast(bridge, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^bridge, :normal}
    refute_receive {:body_error, ^bridge, _reason}, 20
  end

  test "early response releases an outstanding HTTP.Stream producer" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    {:ok, bridge} = BodyBridge.start_link(stream, self())

    producer =
      Task.async(fn ->
        first = HTTP.Stream.chunk(stream, "one")
        second = HTTP.Stream.chunk(stream, "two")
        {first, second}
      end)

    assert :ok = BodyBridge.credit(bridge, 3)
    assert_receive {:body_chunk, ^bridge, "one", _ref}
    assert :ok = BodyBridge.early_response(bridge)
    assert {{:error, :early_response}, {:error, _reason}} = Task.await(producer, 1_000)
    refute_receive {:body_error, ^bridge, _reason}, 20
  end

  test "upload trailers fail explicitly instead of being discarded" do
    {:ok, stream} = HTTP.Stream.start_link(0)
    {:ok, bridge} = BodyBridge.start_link(stream, self())
    assert :ok = BodyBridge.credit(bridge, 1)
    assert :ok = HTTP.Stream.finish(stream, [{"X-Checksum", "one"}])
    assert_receive {:body_error, ^bridge, :request_trailers_unsupported}, 1_000
    assert BodyBridge.status(bridge).stopped?
    refute_receive {:body_eof, ^bridge}, 0
  end
end
