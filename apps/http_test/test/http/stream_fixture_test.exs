defmodule HTTP.Test.StreamFixtureTest do
  use ExUnit.Case, async: true

  defp fetch(name, opts \\ []) do
    HTTP.fetch(
      "http://mock.invalid/stream",
      Keyword.merge([adapter: {HTTP.Test, name}, redirect: :manual], opts)
    )
  end

  defp down(pid) do
    monitor = Process.monitor(pid)
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1_500
  end

  test "ACK gates producer progress and preserves trailers before stream end" do
    owner = self()

    HTTP.Test.expect(:stream, fn _ ->
      HTTP.Test.stream(["first", {:gate, owner, :second}, "second"],
        observer: owner,
        trailers: [{"x-last", "a"}, {"x-last", "b"}]
      )
    end)

    promise = fetch(:stream)
    response = HTTP.Promise.await(promise)
    assert_receive {:http_test_stream, stream, producer}
    assert response.body == stream
    assert response.body == stream
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "first", ack}, 1_000
    refute_receive {:http_test_gate, :second, _, _}, 25
    send(stream, {:stream_chunk_ack, ack})
    assert_receive {:http_test_gate, :second, ^producer, gate}, 1_000
    send(producer, {:http_test_release, gate})
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "second", ack2}, 1_000
    send(stream, {:stream_chunk_ack, ack2})
    assert_receive {:stream_trailers, ^stream, trailers}, 1_000
    assert HTTP.Headers.to_list(trailers) == [{"x-last", "a"}, {"x-last", "b"}]
    assert_receive {:stream_end, ^stream}, 1_000
    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_500) == :ok
    assert HTTP.Test.verify!() == :ok
  end

  test "wait timeout keeps response-header worker live until gate release" do
    owner = self()

    HTTP.Test.expect(:headers, fn _ ->
      HTTP.Test.gate(owner, :headers, fn -> HTTP.Test.text("ready") end)
    end)

    promise = fetch(:headers)
    assert_receive {:http_test_gate, :headers, worker, ref}
    assert HTTP.Promise.await(promise, 0) == {:error, :await_timeout}
    assert Process.alive?(worker)
    send(worker, {:http_test_release, ref})
    assert HTTP.Promise.await(promise).body == "ready"
    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_500) == :ok
    assert HTTP.Test.verify!() == :ok
  end

  test "request deadline remains distinct from cancellation" do
    owner = self()

    HTTP.Test.expect(:deadline, fn _ ->
      HTTP.Test.gate(owner, :deadline, fn -> HTTP.Test.status(200) end)
    end)

    promise = fetch(:deadline, timeout: 100)
    assert_receive {:http_test_gate, :deadline, _, _}
    assert HTTP.Promise.await(promise, 1_500) == {:error, :request_timeout}
    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_500) == :ok
    assert HTTP.Test.verify!() == :ok
  end

  test "pre-aborted requests do not execute callbacks" do
    owner = self()

    HTTP.Test.stub(:aborted, fn _ ->
      send(owner, :callback_executed)
      HTTP.Test.status(200)
    end)

    signal = HTTP.AbortController.new()
    HTTP.AbortController.abort(signal)
    promise = fetch(:aborted, signal: signal)
    assert HTTP.Promise.await(promise) == {:error, :aborted}
    refute_receive :callback_executed
    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_500) == :ok
    assert HTTP.Test.verify!() == :ok
  end

  test "pre-aborted default-follow uploads remain registered for owner cleanup" do
    owner = self()
    {:ok, upload} = HTTP.Stream.from_enumerable(["unread"])

    HTTP.Test.stub(:aborted_upload, fn _ ->
      send(owner, :upload_callback_executed)
      HTTP.Test.status(200)
    end)

    signal = HTTP.AbortController.new()
    HTTP.AbortController.abort(signal)

    promise =
      fetch(:aborted_upload,
        redirect: :follow,
        method: :post,
        body: upload,
        duplex: "half",
        signal: signal
      )

    assert HTTP.Promise.await(promise) == {:error, :aborted}
    assert HTTP.Test.verify!() == :ok
    down(upload)
    refute_receive :upload_callback_executed

    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise)) ==
             {:error, {:unsupported_completion, :redirect}}
  end

  test "AbortController cancels a waiting header gate" do
    owner = self()

    HTTP.Test.expect(:headers, fn _ ->
      HTTP.Test.gate(owner, :headers, fn -> HTTP.Test.status(200) end)
    end)

    signal = HTTP.AbortController.new()
    promise = fetch(:headers, signal: signal)
    assert_receive {:http_test_gate, :headers, _, _}
    HTTP.AbortController.abort(signal)
    assert HTTP.Promise.await(promise) == {:error, :aborted}
    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_500) == :ok
    assert HTTP.Test.verify!() == :ok
  end

  test "AbortController remains connected to response stream after Promise worker exits" do
    owner = self()

    HTTP.Test.expect(:stream, fn _ ->
      HTTP.Test.stream(["held", {:gate, owner, :after_ack}], observer: owner)
    end)

    signal = HTTP.AbortController.new()
    promise = fetch(:stream, signal: signal)
    response = HTTP.Promise.await(promise)
    assert_receive {:http_test_stream, stream, producer}
    assert response.body == stream
    down(promise.task.pid)
    HTTP.AbortController.abort(signal)
    down(stream)
    down(producer)
    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_500) == :ok
    assert HTTP.Test.verify!() == :ok
  end

  test "failed upload attachment rejects the request before executing its callback" do
    owner = self()

    upload =
      spawn(fn ->
        receive do
          {:request_lifecycle, _, _, _} ->
            receive do
              {:request_lifecycle_stop, _} -> :ok
            end
        end
      end)

    HTTP.Test.expect(:invalid_upload, fn _ ->
      send(owner, :upload_callback_executed)
      HTTP.Test.status(200)
    end)

    promise =
      fetch(:invalid_upload, redirect: :follow, method: :post, body: upload, duplex: "half")

    assert HTTP.Promise.await(promise, 2_000) == {:error, :stream_attachment_timeout}
    refute_receive :upload_callback_executed
    down(upload)
    assert HTTP.Test.verify!() == :ok
  end

  test "completion cancellation settles response and upload resources" do
    owner = self()
    {:ok, upload} = HTTP.Stream.from_enumerable(["upload"])

    HTTP.Test.expect(:upload, fn request ->
      assert request.body == upload
      HTTP.Test.stream(["held"], observer: owner)
    end)

    promise = fetch(:upload, method: :post, body: upload, duplex: "half")
    assert %HTTP.Response{} = HTTP.Promise.await(promise)
    assert_receive {:http_test_stream, stream, producer}
    handle = HTTP.Promise.completion(promise)
    assert HTTP.RequestCompletion.abort_and_await(handle, 1_500) == :ok
    down(upload)
    down(stream)
    down(producer)
    assert HTTP.Test.verify!() == :ok
  end

  test "midstream intentional failure follows acknowledged data and cleans producer" do
    owner = self()

    HTTP.Test.expect(:error, fn _ ->
      HTTP.Test.stream(["first", {:error, :fixture_failure}], observer: owner)
    end)

    promise = fetch(:error)
    response = HTTP.Promise.await(promise)
    assert_receive {:http_test_stream, stream, producer}
    send(response.body, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "first", ack}, 1_000
    send(stream, {:stream_chunk_ack, ack})
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_error, ^stream, :fixture_failure}, 1_000
    down(producer)
    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_500) == :ok
    assert HTTP.Test.verify!() == :ok
  end

  test "follow candidate discards simulated response resources without second claim" do
    owner = self()

    HTTP.Test.expect(:redirect, fn _ ->
      HTTP.Test.stream(["hidden"], status: 302, headers: [{"location", "/next"}], observer: owner)
    end)

    promise = fetch(:redirect, redirect: :follow)
    assert HTTP.Promise.await(promise) == {:error, {:unsupported_test_policy, :redirect_follow}}
    assert_receive {:http_test_stream, stream, producer}
    down(stream)
    down(producer)

    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(promise)) ==
             {:error, {:unsupported_completion, :redirect}}

    assert HTTP.Test.verify!() == :ok
  end

  test "owner teardown cleans default-follow resources without fabricating completion" do
    parent = self()

    owner =
      spawn(fn ->
        HTTP.Test.stub(:held, fn _ -> HTTP.Test.stream(["held"], observer: parent) end)
        promise = fetch(:held, redirect: :follow)
        response = HTTP.Promise.await(promise)
        send(parent, {:response, response, HTTP.Promise.completion(promise)})
      end)

    assert_receive {:http_test_stream, stream, producer}
    assert_receive {:response, _, completion}
    down(owner)
    down(stream)
    down(producer)

    assert HTTP.RequestCompletion.await(completion) ==
             {:error, {:unsupported_completion, :redirect}}
  end
end
