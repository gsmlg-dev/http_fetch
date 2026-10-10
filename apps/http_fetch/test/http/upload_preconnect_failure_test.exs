defmodule HTTP.UploadPreconnectFailureTest do
  use ExUnit.Case, async: true

  for route <- [:proxy, :reuse] do
    test "#{route} refusal terminates an upload and wakes its pending producer" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, {_, port}} = :inet.sockname(listener)
      :ok = :gen_tcp.close(listener)
      {:ok, stream} = HTTP.Stream.start_link(0)
      monitor = Process.monitor(stream)
      :erlang.trace(stream, true, [:receive])
      producer = Task.async(fn -> HTTP.Stream.chunk(stream, "payload", 5_000) end)
      assert_receive {:trace, ^stream, :receive, {:chunk, _, _, "payload"}}, 1_000

      options =
        case unquote(route) do
          :proxy -> [proxy: {:http, "127.0.0.1", port, []}]
          :reuse -> [http1_reuse: true]
        end

      promise =
        HTTP.fetch(
          "http://127.0.0.1:#{port}/upload",
          options ++
            [
              method: :post,
              body: stream,
              duplex: "half",
              request_mode: :proxy,
              http_version: :http1,
              redirect: :manual,
              telemetry: false,
              connect_timeout: 500,
              timeout: 1_000
            ]
        )

      assert {:error, :econnrefused} = HTTP.Promise.await(promise, 2_000)
      assert {:error, reason} = Task.await(producer, 1_000)
      refute reason == :timeout
      assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
      assert {:error, {:stream_down, :noproc}} = HTTP.Stream.chunk(stream, "late", 100)
    end
  end
end
