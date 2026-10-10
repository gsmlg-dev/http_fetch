defmodule HTTP.ManagedH2NotificationBoundsTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Frames
  @fixtures Path.expand("../support/fixtures", __DIR__)

  for protocol <- [:h2c, :http2], scenario <- [:informational, :settings] do
    test "#{protocol} #{scenario} flood keeps siblings progressing with finite retirement and no replay" do
      run(unquote(protocol), unquote(scenario))
    end
  end

  defp run(protocol, scenario) do
    transport = transport(protocol)
    {origin, listener} = listener(protocol)
    {other_origin, other_listener} = listener(protocol)
    parent = self()

    peer =
      Task.async(fn ->
        socket = accept(listener, transport)
        first = request(socket, transport)
        if scenario == :settings, do: transport.send(socket, Frames.frame(1, 4, first, <<0x88>>))
        send(parent, :first_request)
        sibling = request(socket, transport)

        :ok =
          transport.send(socket, [
            Frames.frame(1, 4, sibling, <<0x88>>),
            Frames.frame(6, 0, 0, "prelude!")
          ])

        await_ping(socket, transport, "prelude!")
        send(parent, :siblings_ready)
        await_command(:flood)

        flood =
          case scenario do
            :informational -> :binary.copy(Frames.frame(1, 4, first, <<0x08, 3, "103">>), 4_096)
            :settings -> :binary.copy(Frames.frame(4, 0, 0, <<>>), 4_096)
          end

        :ok = transport.send(socket, [flood, Frames.frame(6, 0, 0, "bounded!")])
        counts = await_ping(socket, transport, "bounded!")

        assert counts ==
                 if(scenario == :settings,
                   do: %{settings: 4_096, resets: 0},
                   else: %{settings: 0, resets: 1}
                 )

        send(parent, {:flood_processed, counts})
        await_command(:finish)
        if scenario == :settings, do: transport.send(socket, Frames.frame(0, 1, first, "first"))
        :ok = transport.send(socket, Frames.frame(0, 1, sibling, "survived"))
        assert_closed(socket, transport)
        assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
        :ok
      end)

    independent =
      Task.async(fn ->
        socket = accept(other_listener, transport)
        for _ <- 1..2, do: respond(socket, transport, request(socket, transport), "independent")
        assert_closed(socket, transport)
      end)

    scope = open(origin, protocol)
    other = open(other_origin, protocol)
    first = fetch(origin, scope)
    assert_receive :first_request, 3_000
    held = if scenario == :settings, do: Promise.await(first, 3_000)
    sibling = fetch(origin, scope)
    assert %Response{} = response = Promise.await(sibling, 3_000)
    assert_receive :siblings_ready, 3_000
    assert drain(fetch(other_origin, other)) == "independent"
    send(peer.pid, :flood)
    assert_receive {:flood_processed, _}, 3_000

    if scenario == :informational do
      assert {:error, :http2_informational_limit} = Promise.await(first, 3_000)
      assert :ok = RequestCompletion.await(Promise.completion(first), 3_000)
    end

    assert {:ok, %{connections: 1, pending: 0}} = ManagedTransport.snapshot(scope, 100)
    assert drain(fetch(other_origin, other)) == "independent"
    send(peer.pid, :finish)
    if scenario == :settings, do: assert(Response.read_all(held) == "first")
    assert Response.read_all(response) == "survived"

    for promise <- [first, sibling],
        do: assert(:ok == RequestCompletion.await(Promise.completion(promise), 3_000))

    for current <- [scope, other] do
      assert {:ok, receipt} = ManagedTransport.retire(current)
      assert :ok = ManagedTransport.await_retired(receipt, 3_000)
    end

    assert :ok = Task.await(peer, 3_000)
    assert :ok = Task.await(independent, 3_000)
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
      {1, _, id, _} ->
        id

      {4, 0, 0, _} ->
        :ok = transport.send(socket, Frames.frame(4, 1, 0, <<>>))
        request(socket, transport)

      _ ->
        request(socket, transport)
    end
  end

  defp await_ping(socket, transport, payload, counts \\ %{settings: 0, resets: 0}) do
    case frame(socket, transport) do
      {6, 1, 0, ^payload} ->
        counts

      {4, 1, 0, _} ->
        await_ping(socket, transport, payload, %{counts | settings: counts.settings + 1})

      {3, _, _, _} ->
        await_ping(socket, transport, payload, %{counts | resets: counts.resets + 1})

      {1, _, _, _} ->
        flunk("peer observed an unexpected request/replay")

      _ ->
        await_ping(socket, transport, payload, counts)
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
end
