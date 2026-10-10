defmodule HTTP.HTTP2HeaderFragmentLimitTest do
  use ExUnit.Case, async: false

  alias HTTP.{Promise, RequestCompletion}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  defp fetch(url, opts \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          http_version: :h2c,
          http2_scope: "fragment-limit-#{System.unique_integer([:positive])}",
          stream_response: true,
          decode_body: false,
          request_mode: :proxy,
          redirect: :manual,
          timeout: 5_000
        ],
        opts
      )
    )
  end

  test "empty initial and final fragments fit exactly 256 frames on real wire" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            Peer.frame(1, 1, id, <<>>),
            List.duplicate(Peer.frame(9, 0, id, <<>>), 253),
            Peer.frame(9, 0, id, <<0x88>>),
            Peer.frame(9, 4, id, <<>>)
          ])
      end)

    promise = fetch(url, http2_reuse: false)
    assert %HTTP.Response{status: 200} = response = Promise.await(promise)
    assert HTTP.Response.read_all(response) == ""
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert_receive {:peer_complete, ^peer}, 2_000
    send(peer, :close)
  end

  test "empty fragment 257 closes a dedicated connection and confirms public cleanup" do
    parent = self()

    {url, peer} =
      Peer.start(parent, fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, excessive_block(id))
        assert_closed(socket)
        send(parent, :dedicated_closed)
      end)

    promise = fetch(url, http2_reuse: false)
    assert {:error, {:transport_error, :header_block_too_fragmented}} = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(promise), 0)
    assert_receive :dedicated_closed, 2_000
    assert_receive {:peer_complete, ^peer}, 2_000
    send(peer, :close)
  end

  test "connection error settles its sibling, preserves another connection and allows replacement" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    peer =
      Task.async(fn ->
        socket = accept(listener)
        {offender, true} = Peer.request(socket)
        send(parent, :offender_ready)
        {sibling, true} = Peer.request(socket)
        assert sibling > offender
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, sibling, <<0x88>>))
        send(parent, {:shared_requests, self(), offender, sibling})

        receive do
          :attack -> :ok
        after
          5_000 -> flunk("missing attack barrier")
        end

        # Separate deliveries exercise the persistent count, not only one buffer.
        :ok = :gen_tcp.send(socket, Peer.frame(1, 0, offender, <<>>))
        :ok = :gen_tcp.send(socket, List.duplicate(Peer.frame(9, 0, offender, <<>>), 255))
        :ok = :gen_tcp.send(socket, Peer.frame(9, 0, offender, <<>>))
        assert_closed(socket)
        send(parent, :shared_closed)

        replacement = accept(listener)
        {id, true} = Peer.request(replacement)
        assert id == 1
        :ok = Peer.response(replacement, id, "replacement")

        receive do
          :close -> :gen_tcp.close(replacement)
        after
          5_000 -> flunk("missing replacement close barrier")
        end

        :gen_tcp.close(listener)
      end)

    {healthy_url, healthy_peer} =
      Peer.start(parent, fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))

        receive do
          :finish -> :ok
        after
          5_000 -> flunk("missing healthy finish barrier")
        end

        :ok = :gen_tcp.send(socket, Peer.frame(0, 1, id, "healthy"))
      end)

    scope = "shared-fragment-#{System.unique_integer([:positive])}"
    url = "http://127.0.0.1:#{port}/test"
    first = fetch(url, http2_scope: scope)
    assert_receive :offender_ready, 2_000
    second = fetch(url, http2_scope: scope)
    assert %HTTP.Response{stream: sibling_stream} = Promise.await(second)
    assert_receive {:shared_requests, _, _, _}, 2_000
    healthy = fetch(healthy_url)
    assert %HTTP.Response{} = healthy_response = Promise.await(healthy)
    send(sibling_stream, {:read_chunk, self()})
    send(peer.pid, :attack)

    assert {:error, {:transport_error, :header_block_too_fragmented}} = Promise.await(first)

    assert_receive {:stream_error, ^sibling_stream,
                    {:transport_error, :header_block_too_fragmented}},
                   2_000

    for promise <- [first, second] do
      # Loss of a shared owner cannot certify its reservation release. The
      # public handle conservatively reports that fact instead of hanging.
      assert {:error, :cleanup_unconfirmed} =
               RequestCompletion.await(Promise.completion(promise), 1_000)
    end

    assert_receive :shared_closed, 2_000
    assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(healthy), 0)
    send(healthy_peer, :finish)
    assert HTTP.Response.read_all(healthy_response) == "healthy"
    assert :ok = RequestCompletion.await(Promise.completion(healthy), 1_000)

    replacement = fetch(url, http2_scope: scope)
    assert HTTP.Response.read_all(Promise.await(replacement)) == "replacement"
    assert :ok = RequestCompletion.await(Promise.completion(replacement), 1_000)
    send(peer.pid, :close)
    assert :ok = Task.await(peer)
    assert_receive {:peer_complete, ^healthy_peer}, 2_000
    send(healthy_peer, :close)
  end

  defp excessive_block(id),
    do: [Peer.frame(1, 0, id, <<>>), List.duplicate(Peer.frame(9, 0, id, <<>>), 256)]

  defp accept(listener) do
    {:ok, socket} = :gen_tcp.accept(listener, 5_000)
    assert {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), 2_000)
    :ok = :gen_tcp.send(socket, Peer.frame(4, 0, 0, <<>>))
    socket
  end

  defp assert_closed(socket) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, _control_frames} -> assert_closed(socket)
      result -> assert result == {:error, :closed}
    end
  end
end
