defmodule HTTP.ManagedCapacityContractTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Frames

  @fixtures Path.expand("../support/fixtures", __DIR__)

  for protocol <- [:h2c, :http2] do
    test "#{protocol} draining capacity rejects before bytes and permits explicit replacement" do
      protocol = unquote(protocol)
      transport = transport(protocol)
      {origin, listener} = listener(protocol)
      {other_origin, other_listener} = listener(protocol)
      parent = self()

      peer =
        Task.async(fn ->
          socket = accept(listener, transport)
          first_id = request(socket, transport)

          :ok =
            transport.send(socket, [
              Frames.frame(1, 4, first_id, <<0x88>>),
              Frames.frame(7, 0, 0, <<0::1, first_id::31, 0::32>>),
              Frames.frame(6, 0, 0, "capacity")
            ])

          await_ping(socket, transport)
          send(parent, :goaway_processed)
          await_command(:check_rejection)
          assert {:error, :timeout} = transport.recv(socket, 0, 100)
          assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
          send(parent, :no_rejected_request_bytes)
          await_command(:finish)
          :ok = transport.send(socket, Frames.frame(0, 1, first_id, "held"))
          assert_closed(socket, transport)
          send(parent, :drained_owner_closed)

          replacement = accept(listener, transport)
          id = request(replacement, transport)
          respond(replacement, transport, id, "replacement")
          assert_closed(replacement, transport)
        end)

      sibling_peer =
        Task.async(fn ->
          socket = accept(other_listener, transport)
          for _ <- 1..2, do: respond(socket, transport, request(socket, transport), "sibling")
          assert_closed(socket, transport)
        end)

      scope = open(origin, protocol)
      sibling_scope = open(other_origin, protocol)
      first = fetch(origin, scope)
      assert %Response{} = held = Promise.await(first, 3_000)
      assert_receive :goaway_processed, 3_000

      assert {:ok, %{connections: 1, active_requests: 1, pending: 0}} =
               ManagedTransport.snapshot(scope, 100)

      rejected = fetch(origin, scope)
      assert {:error, {:transport_scope_capacity, :connections}} = Promise.await(rejected, 1_000)
      assert :ok = RequestCompletion.await(Promise.completion(rejected), 1_000)
      send(peer.pid, :check_rejection)
      assert_receive :no_rejected_request_bytes, 1_000
      assert drain(fetch(other_origin, sibling_scope)) == "sibling"

      send(peer.pid, :finish)
      assert Response.read_all(held) == "held"
      assert :ok = RequestCompletion.await(Promise.completion(first), 3_000)
      assert_receive :drained_owner_closed, 3_000
      wait_empty(scope, System.monotonic_time(:millisecond) + 3_000)
      assert drain(fetch(origin, scope)) == "replacement"
      assert drain(fetch(other_origin, sibling_scope)) == "sibling"

      for current <- [scope, sibling_scope] do
        assert {:ok, receipt} = ManagedTransport.retire(current)
        assert :ok = ManagedTransport.await_retired(receipt, 3_000)
      end

      assert :ok = Task.await(peer, 3_000)
      assert :ok = Task.await(sibling_peer, 3_000)
    end
  end

  defp transport(:h2c), do: :gen_tcp
  defp transport(:http2), do: :ssl

  defp listener(protocol) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    scheme = if protocol == :h2c, do: "http", else: "https"
    {"#{scheme}://localhost:#{port}", listener}
  end

  defp accept(listener, transport) do
    {:ok, socket} = :gen_tcp.accept(listener, 3_000)

    socket =
      if transport == :ssl do
        {:ok, socket} =
          :ssl.handshake(socket,
            certfile: Path.join(@fixtures, "localhost.pem"),
            keyfile: Path.join(@fixtures, "localhost.key"),
            alpn_preferred_protocols: ["h2"],
            active: false
          )

        socket
      else
        socket
      end

    assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = transport.recv(socket, 24, 3_000)
    :ok = transport.send(socket, Frames.frame(4, 0, 0, <<>>))
    socket
  end

  defp frame(socket, transport) do
    {:ok, <<length::24, type, flags, _::1, id::31>>} = transport.recv(socket, 9, 3_000)
    payload = if length == 0, do: <<>>, else: elem(transport.recv(socket, length, 3_000), 1)
    {type, flags, id, payload}
  end

  defp request(socket, transport) do
    case frame(socket, transport) do
      {1, _, id, _} -> id
      _ -> request(socket, transport)
    end
  end

  defp await_ping(socket, transport) do
    case frame(socket, transport) do
      {6, 1, 0, "capacity"} -> :ok
      {1, _, _, _} -> flunk("unexpected request before GOAWAY barrier")
      _ -> await_ping(socket, transport)
    end
  end

  defp respond(socket, transport, id, body) do
    transport.send(socket, [Frames.frame(1, 4, id, <<0x88>>), Frames.frame(0, 1, id, body)])
  end

  defp assert_closed(socket, transport) do
    case transport.recv(socket, 0, 3_000) do
      {:ok, _} ->
        assert_closed(socket, transport)

      result ->
        assert result == {:error, :closed}
        :ok
    end
  end

  defp await_command(command) do
    receive do
      ^command -> :ok
    after
      3_000 -> flunk("missing #{command} barrier")
    end
  end

  defp open(origin, protocol) do
    assert {:ok, scope} =
             ManagedTransport.open(
               origin: origin,
               connect_address: {127, 0, 0, 1},
               http_version: protocol,
               max_connections: 1,
               max_requests: 32,
               max_pending: 0,
               ssl:
                 if(protocol == :h2c,
                   do: [],
                   else: [
                     verify: :verify_peer,
                     cacertfile: Path.join(@fixtures, "localhost-ca.pem")
                   ]
                 )
             )

    scope
  end

  defp fetch(origin, scope) do
    HTTP.fetch(origin <> "/capacity",
      transport_scope: scope,
      stream_response: true,
      decode_body: false,
      redirect: :manual,
      timeout: 5_000
    )
  end

  defp drain(promise) do
    assert %Response{} = response = Promise.await(promise, 3_000)
    body = Response.read_all(response)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 3_000)
    body
  end

  defp wait_empty(scope, deadline) do
    case ManagedTransport.snapshot(scope, 100) do
      {:ok, %{connections: 0, active_requests: 0}} ->
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline
        wait_empty(scope, deadline)
    end
  end
end
