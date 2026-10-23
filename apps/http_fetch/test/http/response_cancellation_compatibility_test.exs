defmodule HTTP.ResponseCancellationCompatibilityTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.{AbortController, Promise, RequestCompletion, Response}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  for {name, reason} <- [abort: :aborted, deadline: :request_timeout] do
    test "untracked H2 #{name} retains its error after the peer observes cancellation" do
      parent = self()

      {url, peer} =
        Peer.start(parent, fn socket ->
          {id, true} = Peer.request(socket)
          :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
          await_reset(socket, id)
          send(parent, {:cancellation_reset, self()})
        end)

      on_exit(fn -> if Process.alive?(peer), do: Process.exit(peer, :kill) end)
      controller = AbortController.new()

      promise =
        HTTP.fetch(url,
          http_version: :h2c,
          http2_profile: :native_v1,
          stream_response: true,
          signal: controller,
          timeout: 1_000
        )

      assert {:error, {:unsupported_completion, :redirect}} =
               RequestCompletion.await(Promise.completion(promise), 0)

      assert %Response{body: stream, status: 200} = Promise.await(promise, 2_000)
      on_exit(fn -> HTTP.Stream.stop(stream, :fixture_cleanup) end)
      if unquote(name) == :abort, do: assert(:ok = AbortController.abort(controller))
      assert_receive {:cancellation_reset, ^peer}, 2_000
      send(stream, {:read_chunk, self(), :ack})
      assert_receive {:stream_error, ^stream, unquote(reason)}, 1_000
      refute_receive {:stream_error, ^stream, _}, 0
      refute_receive {:stream_end, ^stream}, 0
      assert_receive {:peer_complete, ^peer}, 1_000
      monitor = Process.monitor(peer)
      send(peer, :close)
      assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}, 1_000
    end
  end

  defp await_reset(socket, id) do
    case Peer.recv(socket) do
      {3, _, ^id, _} -> :ok
      _ -> await_reset(socket, id)
    end
  end
end
