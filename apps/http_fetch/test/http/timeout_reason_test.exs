defmodule HTTP.TimeoutReasonTest do
  use ExUnit.Case, async: false

  # Request deadline expiry is reported as `:timeout` wherever a Fetch user can
  # observe it; `:request_timeout` stays an internal lifecycle atom.
  defmodule InternalDeadlineAdapter do
    @behaviour HTTP.Adapter

    @impl true
    def prepare(_request, result), do: {:ok, result}

    @impl true
    def execute(_request, :error, _signal), do: {:error, :request_timeout}

    def execute(_request, :stream, _signal) do
      {:ok, stream} = HTTP.Stream.start_link(0, [], response_body: true, telemetry: false)
      Process.unlink(stream)
      HTTP.Stream.error(stream, :request_timeout)
      HTTP.Response.new(status: 200, body: stream)
    end
  end

  defp fetch(result, opts \\ []) do
    "http://deadline.test/"
    |> HTTP.fetch([adapter: {InternalDeadlineAdapter, result}] ++ opts)
    |> HTTP.Promise.await(5_000)
  end

  test "a request deadline resolves the promise with :timeout" do
    assert fetch(:error) == {:error, :timeout}
  end

  test "structured errors carry :timeout as their reason" do
    assert {:error, %HTTP.RequestError{reason: :timeout}} =
             fetch(:error, error_mode: :structured)
  end

  test "request exception telemetry reports :timeout" do
    ref = make_ref()
    parent = self()
    id = {__MODULE__, ref}

    :telemetry.attach(
      id,
      [:http_fetch, :request, :exception],
      fn _event, _measurements, metadata, _ -> send(parent, {ref, metadata.error}) end,
      nil
    )

    try do
      assert fetch(:error) == {:error, :timeout}
      assert_receive {^ref, :timeout}
    after
      :telemetry.detach(id)
    end
  end

  test "a response stream stopped by the deadline reports :timeout" do
    response = fetch(:stream)
    stream = response.body
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_error, ^stream, :timeout}

    assert {:error, :timeout} = HTTP.Response.json(fetch(:stream))
  end

  test "a deadline stop delivered to a waiting response reader reports :timeout" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], response_body: true, telemetry: false)
    send(stream, {:read_chunk, self(), :ack})
    HTTP.Stream.stop(stream, :request_timeout)
    assert_receive {:stream_error, ^stream, :timeout}
  end

  test "Fetch's own response producer and upload reader keep the internal reason" do
    {:ok, response} = HTTP.Stream.start_link(0, [], response_body: true, telemetry: false)
    producer = Task.async(fn -> HTTP.Stream.chunk(response, "pending", 5_000) end)
    Process.sleep(50)
    HTTP.Stream.stop(response, :request_timeout)
    assert {:error, :request_timeout} = Task.await(producer)

    {:ok, upload} = HTTP.Stream.start_link(0, [], telemetry: false)
    send(upload, {:read_chunk, self(), :ack})
    HTTP.Stream.stop(upload, :request_timeout)
    assert_receive {:stream_error, ^upload, :request_timeout}
  end

  test "an upload chunk pending when the deadline stops the stream reports :timeout" do
    {:ok, stream} = HTTP.Stream.start_link(0, [], telemetry: false)
    producer = Task.async(fn -> HTTP.Stream.chunk(stream, "pending", 5_000) end)
    # The unread chunk stays pending until the lifecycle stops the stream.
    Process.sleep(50)
    HTTP.Stream.stop(stream, :request_timeout)
    assert {:error, :timeout} = Task.await(producer)
  end
end
