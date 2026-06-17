defmodule E2E.StreamingTest do
  @moduledoc """
  Exercises the >5MB streaming path in `HTTP.fetch`.

  The test server's `/stream-large` returns 6 MiB, which is above
  `HTTP.Config.streaming_threshold()`. Streaming responses have
  `body: nil, stream: pid` in `HTTP.Response` and must be consumed via
  `HTTP.Response.read_all/1` or `HTTP.Response.write_to/2`.

  These tests also assert that the streaming telemetry events fire.
  """
  use ExUnit.Case, async: false

  @moduletag :e2e
  @moduletag timeout: 60_000

  @streaming_threshold HTTP.Config.streaming_threshold()
  @expected_size 6 * 1024 * 1024

  alias E2E.ResponseView

  setup do
    # Capture telemetry events from the streaming subsystem.
    test_pid = self()
    handler_id = "e2e_streaming_#{System.unique_integer([:positive])}"

    :telemetry.attach_many(
      handler_id,
      [
        [:http_fetch, :streaming, :start],
        [:http_fetch, :streaming, :chunk],
        [:http_fetch, :streaming, :stop]
      ],
      fn event_name, measurements, _metadata, _config ->
        send(test_pid, {:telemetry, event_name, measurements})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    :ok
  end

  defp drain_telemetry do
    drain = fn drain, acc ->
      receive do
        {:telemetry, _, _} = msg -> drain.(drain, [msg | acc])
      after
        50 -> acc
      end
    end

    drain.(drain, [])
  end

  test "response is large enough to cross the streaming threshold" do
    assert @expected_size > @streaming_threshold
  end

  test "the >5MB response is streamed instead of buffered" do
    resp = E2E.Server.url("/stream-large") |> HTTP.fetch() |> HTTP.Promise.await()
    assert %HTTP.Response{} = resp
    assert resp.status == 200
    assert resp.body == nil
    assert is_pid(resp.stream)
  end

  # TODO(upstream): gsmlg-dev/http_fetch#10
  test "streamed response has body=nil and a stream pid" do
    resp = E2E.Server.url("/stream-large") |> HTTP.fetch() |> HTTP.Promise.await()
    assert %HTTP.Response{body: nil, stream: stream} = resp
    assert is_pid(stream)
    assert resp.status == 200
  end

  test "read_all/1 returns the full body" do
    resp = E2E.Server.url("/stream-large") |> HTTP.fetch() |> HTTP.Promise.await()
    body = HTTP.Response.read_all(resp)
    assert byte_size(body) == @expected_size
  end

  test "write_to/2 streams the body to a file" do
    tmp = Briefly.create!(directory: true, prefix: "stream_")
    out = Path.join(tmp, "out.bin")

    resp = E2E.Server.url("/stream-large") |> HTTP.fetch() |> HTTP.Promise.await()
    :ok = HTTP.Response.write_to(resp, out)

    assert File.stat!(out).size == @expected_size
  end

  # TODO(upstream): gsmlg-dev/http_fetch#10
  test "emits :streaming, :start, :chunk (>=1), and :stop telemetry events" do
    _ = E2E.Server.url("/stream-large") |> HTTP.fetch() |> HTTP.Promise.await()
    # Wait briefly for the stream to flush any tail events.
    Process.sleep(100)
    events = drain_telemetry() |> Enum.map(fn {:telemetry, name, _} -> name end)

    assert [:http_fetch, :streaming, :start] in events
    assert [:http_fetch, :streaming, :stop] in events
    chunk_count = Enum.count(events, &(&1 == [:http_fetch, :streaming, :chunk]))
    assert chunk_count >= 1
  end
end
