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
    refute_receive {:read, ^bridge}, 20
    :ok = BodyBridge.credit(bridge, 1)
    assert_receive {:read, ^bridge}
    send(stream, :eof)
    assert_receive {:body_eof, ^bridge}, 500
    assert BodyBridge.status(bridge).eof?
  end

  test "oversized chunks and early responses stop the bridge" do
    stream = fake_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, self(), max_chunk_bytes: 4)
    :ok = BodyBridge.credit(bridge, 4)
    assert_receive {:read, ^bridge}
    send(stream, {:send_chunk, "12345"})
    assert_receive {:body_error, ^bridge, :chunk_too_large}, 500
    assert BodyBridge.status(bridge).stopped?
  end
end
