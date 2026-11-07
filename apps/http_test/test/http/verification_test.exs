defmodule HTTP.Test.VerificationTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog

  test "callback assertion survives a caught Promise exit and verification keeps stacktrace" do
    HTTP.Test.expect(:assertion, fn _ ->
      assert false, "fixture assertion"
      HTTP.Test.status(200)
    end)

    capture_log(fn ->
      promise =
        HTTP.fetch("http://mock.invalid/", adapter: {HTTP.Test, :assertion}, redirect: :manual)

      assert catch_exit(HTTP.Promise.await(promise))
    end)

    error = assert_raise HTTP.Test.VerificationError, &HTTP.Test.verify!/0

    assert [
             {:callback_failure, :error, %ExUnit.AssertionError{message: "fixture assertion"},
              stacktrace}
           ] = error.failures

    assert Enum.any?(stacktrace, fn {module, _, _, _} -> module == __MODULE__ end)
  end

  test "unawaited callback exceptions are retained after owner exit" do
    parent = self()

    capture_log(fn ->
      owner =
        spawn(fn ->
          token = HTTP.Test.Registry.token(self())
          HTTP.Test.Registry.retain(token)
          HTTP.Test.expect(:failure, fn _ -> raise "unawaited failure" end)
          promise = HTTP.fetch("https://mock.invalid/", adapter: {HTTP.Test, :failure})
          monitor = Process.monitor(promise.task.pid)

          receive do
            {:DOWN, ^monitor, :process, _, _} -> send(parent, {:token, token})
          end
        end)

      monitor = Process.monitor(owner)
      assert_receive {:token, token}, 1_500
      assert_receive {:DOWN, ^monitor, :process, ^owner, _}, 1_500

      assert {:error,
              [{:callback_failure, :error, %RuntimeError{message: "unawaited failure"}, [_ | _]}]} =
               HTTP.Test.finalize(token, true)

      assert {:error, :missing_verification_record} = HTTP.Test.finalize(token, true)
    end)
  end

  test "abnormal callback exit is a test failure even when the request was never awaited" do
    HTTP.Test.expect(:exit, fn _ -> exit(:fixture_exit) end)

    capture_log(fn ->
      promise = HTTP.fetch("http://mock.invalid/", adapter: {HTTP.Test, :exit})
      monitor = Process.monitor(promise.task.pid)
      assert_receive {:DOWN, ^monitor, :process, _, _}, 1_500
    end)

    error = assert_raise HTTP.Test.VerificationError, &HTTP.Test.verify!/0
    assert [{:callback_failure, :exit, :fixture_exit, [_ | _]}] = error.failures
  end

  test "callback failure still settles streams and producers before verification raises" do
    parent = self()

    HTTP.Test.expect(:stream_failure, fn _ ->
      HTTP.Test.stream(["held"], observer: parent)
      raise "after creating stream"
    end)

    capture_log(fn ->
      promise =
        HTTP.fetch("http://mock.invalid/",
          adapter: {HTTP.Test, :stream_failure},
          redirect: :manual
        )

      assert catch_exit(HTTP.Promise.await(promise))
    end)

    assert_receive {:http_test_stream, stream, producer}
    assert_raise HTTP.Test.VerificationError, &HTTP.Test.verify!/0

    for pid <- [stream, producer] do
      monitor = Process.monitor(pid)
      assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1_500
    end
  end

  test "unexpected guardian death cannot certify cleanup or leave response resources live" do
    parent = self()
    HTTP.Test.expect(:guardian_failure, fn _ -> HTTP.Test.stream(["held"], observer: parent) end)
    signal = HTTP.AbortController.new()

    promise =
      HTTP.fetch("http://mock.invalid/", adapter: {HTTP.Test, :guardian_failure}, signal: signal)

    assert %HTTP.Response{} = HTTP.Promise.await(promise)
    assert_receive {:http_test_stream, stream, producer}
    guardian = Agent.get(signal, & &1.request_id)
    monitor = Process.monitor(guardian)
    Process.exit(guardian, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^guardian, :killed}, 1_500

    try do
      error = assert_raise HTTP.Test.VerificationError, &HTTP.Test.verify!/0
      assert Enum.any?(error.failures, &match?({:guardian_exit, :killed}, &1))

      for pid <- [stream, producer] do
        ref = Process.monitor(pid)
        assert_receive {:DOWN, ^ref, :process, ^pid, _}, 1_500
      end
    after
      for pid <- [stream, producer], Process.alive?(pid), do: Process.exit(pid, :kill)
    end
  end

  test "forced worker death is retained as callback failure" do
    parent = self()

    HTTP.Test.expect(:killed, fn _ ->
      send(parent, {:callback, self()})

      receive do
        :never -> HTTP.Test.status(200)
      end
    end)

    promise = HTTP.fetch("http://mock.invalid/", adapter: {HTTP.Test, :killed})
    assert_receive {:callback, worker}
    Process.exit(worker, :kill)
    monitor = Process.monitor(promise.task.pid)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 1_500
    error = assert_raise HTTP.Test.VerificationError, &HTTP.Test.verify!/0
    assert Enum.any?(error.failures, &match?({:callback_exit, _, _}, &1))
  end
end
