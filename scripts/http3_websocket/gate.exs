defmodule HTTP3WebSocketGate do
  alias HTTP.WebSocket, as: WS
  alias HTTP.WebSocket.Event.{Open, Message, Close, Error}

  def run do
    {:ok, _} = Application.ensure_all_started(:http_web_socket)
    port = System.fetch_env!("HTTP3_PEER_PORT") |> String.to_integer()

    options = [
      http_version: :http3,
      opening_timeout: 5_000,
      close_timeout: 3_000,
      write_timeout: 3_000,
      ssl: [
        cacertfile: "apps/elixir_quic/test/fixtures/tls/root.pem",
        reference_identity: {:dns_id, "example.test"}
      ]
    ]

    if System.get_env("HTTP3_SETTINGS_REFUSAL") == "1" do
      %WS{} = refused = WS.new("wss://127.0.0.1:#{port}/echo", [], options)
      %Error{reason: :extended_connect_not_supported} = event(refused)
      %Close{was_clean: false} = event(refused)
      IO.puts("independent SETTINGS refusal without fallback: PASS")
      System.halt(0)
    end

    if System.get_env("HTTP3_SETTINGS_HELD") == "1" do
      %WS{} = cancelled = WS.new("wss://127.0.0.1:#{port}/echo", [], options)
      owner = await_owner(now() + 4000)
      :ok = WS.close(cancelled)
      %Close{was_clean: false} = event(cancelled)
      await_empty(owner, now() + 4000)

      %WS{} =
        expired =
        WS.new("wss://127.0.0.1:#{port}/echo", [], Keyword.put(options, :opening_timeout, 1000))

      %Error{reason: :opening_timeout} = event(expired)
      %Close{was_clean: false} = event(expired)
      await_empty(owner, now() + 4000)

      IO.puts(
        "independent held SETTINGS: no CONNECT bytes, cancellation/deadline/owner cleanup: PASS"
      )

      System.halt(0)
    end

    socket = open(port, "/echo", options)
    true = WS.http_version(socket) == :http3
    :ok = WS.send(socket, "h3-exact-text")
    %Message{data: "h3-exact-text"} = event(socket)
    :ok = WS.send(socket, WS.array_buffer(<<0, 1, 255, 128>>))
    %Message{data: %HTTP.Blob{} = blob} = event(socket)
    true = HTTP.Blob.to_binary(blob) == <<0, 1, 255, 128>>
    large = :binary.copy(<<0, 1, 2, 255>>, 65_536)
    :ok = WS.send(socket, WS.array_buffer(large))
    %Message{data: %HTTP.Blob{data: ^large}} = event(socket)
    close(socket)
    IO.puts("RFC9220 independent exact text/binary and local Close: PASS")

    fragment = open(port, "/fragment", options)
    %Message{data: "frag-complete"} = event(fragment)
    close(fragment)
    remote = open(port, "/close-fin", options)
    %Close{code: 1000, reason: "peer-close", was_clean: true} = event(remote)
    IO.puts("independent fragmented message and Close+FIN ordering: PASS")

    ping = open(port, "/ping", options)
    %Message{data: "pong:proof"} = event(ping)
    close(ping)
    IO.puts("independent Ping/automatic Pong: PASS")

    for {path, protocols} <- [{"/refuse", []}, {"/protocol", ["chat"]}] do
      %WS{} = socket = WS.new("wss://127.0.0.1:#{port}" <> path, protocols, options)
      %Error{} = event(socket)
      %Close{was_clean: false} = event(socket)
    end

    limited = open(port, "/oversize", Keyword.put(options, :max_message_size, 128))
    %Error{} = event(limited)
    %Close{} = event(limited)
    bad = open(port, "/bad-frame", options)
    %Error{} = event(bad)
    %Close{} = event(bad)
    IO.puts("independent refusal/subprotocol/oversize/malformed frame: PASS")

    acknowledged =
      open(
        port,
        "/echo",
        Keyword.merge(options, delivery: :ack, max_message_size: 128, max_queue_bytes: 263)
      )

    :ok = WS.send(acknowledged, "first")

    first_ref =
      receive do
        {WS, ^acknowledged, %Message{data: "first"}, ref} -> ref
      after
        5000 -> raise "first ACK-mode message timeout"
      end

    :ok = WS.send(acknowledged, "second")
    await_buffered(acknowledged, now() + 4000)
    :ok = WS.acknowledge(acknowledged, make_ref())

    receive do
      {WS, ^acknowledged, %Message{}, _} -> raise "message bypassed ACK credit"
    after
      0 -> :ok
    end

    :ok = WS.acknowledge(acknowledged, first_ref)
    %Message{data: "second"} = event(acknowledged)
    close(acknowledged)
    IO.puts("independent tiny message budget and opaque ACK credit: PASS")

    for trust <- [
          Keyword.put(options[:ssl], :reference_identity, {:dns_id, "wrong.test"}),
          [
            cacertfile: "apps/ex_ssl/test/fixtures/pkix/root.pem",
            reference_identity: {:dns_id, "example.test"}
          ]
        ] do
      %WS{} =
        rejected_tls =
        WS.new("wss://127.0.0.1:#{port}/echo", [], Keyword.put(options, :ssl, trust))

      %Error{} = event(rejected_tls)
      %Close{was_clean: false} = event(rejected_tls)
    end

    IO.puts("independent wrong-name and untrusted-CA rejection before Open: PASS")

    identity = open(port, "/identity", options)
    %Message{data: peer_id} = event(identity)

    sibling = fn ->
      promise =
        HTTP.fetch("https://127.0.0.1:#{port}/identity", http_version: :http3, ssl: options[:ssl])

      %HTTP.Response{} = response = HTTP.Promise.await(promise, 5_000)

      if HTTP.Response.text(response) != peer_id,
        do: raise("pooled sibling changed connection identity")
    end

    sibling.()
    close(identity)
    sibling.()
    IO.puts("ordinary H3 sibling survives tunnel close on same independent connection: PASS")
  end

  defp open(port, path, options) do
    %WS{} = socket = WS.new("wss://127.0.0.1:#{port}" <> path, [], options)
    %Open{} = event(socket)
    socket
  end

  defp close(socket) do
    :ok = WS.close(socket, 1000, "done")
    %Close{code: 1000, was_clean: true} = event(socket)

    {:error, {:unsupported_completion, :http3}} =
      HTTP.ClientCompletion.await(WS.completion(socket), 2_000)
  end

  defp await_buffered(socket, deadline) do
    cond do
      WS.status(socket).raw_bytes > 0 or WS.status(socket).queued_events > 1 ->
        :ok

      now() >= deadline ->
        raise "ACK pause did not retain second message in bounded state"

      true ->
        receive do
        after
          5 -> await_buffered(socket, deadline)
        end
    end
  end

  defp await_owner(deadline) do
    owners = Map.keys(:sys.get_state(:http_fetch_http3_pool).owners)

    owner =
      Enum.find(owners, fn owner ->
        state = :sys.get_state(owner)
        state.lifecycle == :ready and not state.session.control.received_settings?
      end)

    cond do
      owner ->
        owner

      now() >= deadline ->
        raise "SETTINGS-wait owner readiness timeout"

      true ->
        receive do
        after
          5 -> await_owner(deadline)
        end
    end
  end

  defp await_empty(owner, deadline) do
    state = :sys.get_state(owner)

    cond do
      state.requests == %{} and state.queue == [] and state.pending == nil and
          state.session.requests == %{} ->
        :ok

      now() >= deadline ->
        raise "native owner cancellation did not settle"

      true ->
        receive do
        after
          5 -> await_empty(owner, deadline)
        end
    end
  end

  defp now, do: System.monotonic_time(:millisecond)

  defp event(socket) do
    receive do
      {WS, ^socket, event} ->
        event

      {WS, ^socket, event, ref} ->
        WS.acknowledge(socket, ref)
        event
    after
      8_000 -> raise "event timeout: #{inspect(WS.status(socket))}"
    end
  end
end

HTTP3WebSocketGate.run()
