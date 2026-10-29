defmodule HTTP.HTTP2LateOwnerMonitorTest do
  use ExUnit.Case, async: true

  defmodule Owner do
    use GenServer, restart: :temporary

    def start_link(options), do: GenServer.start_link(__MODULE__, options)
    def init(options), do: {:ok, options}

    def handle_call({:open_stream, _headers, options}, _from, state) do
      subscriber = Keyword.fetch!(options, :subscriber)
      owner = self()

      # Keep the requester suspended until this owner exits. The owner sends
      # the call reply before exiting, so GenServer.call receives that reply
      # before its DOWN signal, but the subsequent monitor sees a dead owner.
      suspender =
        spawn_link(fn ->
          monitor = Process.monitor(owner)
          true = :erlang.suspend_process(subscriber)
          send(owner, {:request_suspended, self()})

          receive do
            {:DOWN, ^monitor, :process, ^owner, _reason} ->
              :erlang.resume_process(subscriber)
          end
        end)

      receive do
        {:request_suspended, ^suspender} -> :ok
      end

      if state == :complete do
        send(subscriber, {:http2, 1, {:http2, :headers, [{":status", "200"}], 4}})
        send(subscriber, {:http2, 1, {:http2, :data, "ok", 1}})
      end

      {:stop, :normal, {:ok, %{id: 1, ref: make_ref()}}, state}
    end
  end

  defmodule Pool do
    use GenServer

    def start_link(owner), do: GenServer.start_link(__MODULE__, owner)
    def init(owner), do: {:ok, %{owner: owner, reservations: 0}}

    def handle_call({:try_reserve, _key, _deadline}, _from, state) do
      {:reply, {:ok, state.owner, make_ref()}, %{state | reservations: state.reservations + 1}}
    end

    def handle_call({:release, _key, _reservation}, _from, state), do: {:reply, :ok, state}
    def handle_call(:reservations, _from, state), do: {:reply, state.reservations, state}
  end

  test "queued END_STREAM survives installing the owner monitor after owner exit" do
    pool = pool(:complete)

    assert %HTTP.Response{status: 200, stream: stream} = response = request(pool, "/queued")
    assert is_pid(stream)
    assert HTTP.Response.read_all(response) == "ok"
    assert GenServer.call(pool, :reservations) == 1
  end

  test "an owner already gone without queued response data still fails without replay" do
    pool = pool(:empty)

    assert {:error, {:request_process_down, :noproc}} = request(pool, "/empty")
    assert GenServer.call(pool, :reservations) == 1
  end

  defp request(pool, path) do
    HTTP.SocketClient.request(%HTTP.Request{
      url: URI.parse("http://example.test" <> path),
      transport_options: [http_version: :h2c, http2_pool: pool, timeout: 1_000]
    })
  end

  defp pool(outcome) do
    owner = start_supervised!({Owner, outcome})
    start_supervised!({Pool, owner})
  end
end
