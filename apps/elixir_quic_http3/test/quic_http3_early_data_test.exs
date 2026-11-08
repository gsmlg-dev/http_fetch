defmodule QuicHttp3.EarlyDataTest do
  use ExUnit.Case, async: true
  alias QuicHttp3.{Frame, Session, Settings}

  defmodule Transport do
    def connect(_, _, _), do: {:ok, :connection}
    def ready(_, _), do: Process.get(:ready, :pending)
    def info(_), do: Process.get(:info, {:ok, %{resumption: %{early_data: :pending}}})

    def open_stream(_, kind, opts) do
      id = Process.get(:next_id, 0)
      Process.put(:next_id, id + 1)
      record({:open, kind, opts[:early_data]})
      {:ok, {:stream, kind, id}}
    end

    def send_stream(stream, bytes, fin, opts) do
      record({:send, stream, bytes, fin, opts[:early_data]})
      {:ok, make_ref()}
    end

    def events(_, _, _), do: Process.get(:events, {:ok, []})

    def read(_, _, _) do
      result = Process.get(:read, {:ok, []})
      Process.put(:read, {:ok, []})
      result
    end

    def stop_stream(_, _, _), do: :ok
    def reset_stream(_, _, _), do: {:ok, make_ref()}
    def cleanup(_), do: :ok
    def close(_, _, _, _), do: :ok

    defp record(call), do: send(Process.get(:owner), call)
  end

  @get [{":method", "GET"}, {":scheme", "https"}, {":authority", "a.test"}, {":path", "/"}]
  @remembered [{1, 0}, {6, 4_096}, {7, 0}, {8, 1}]

  setup do
    Process.put(:owner, self())
    {:ok, session} = Session.new(transport: Transport)
    {:ok, session} = Session.connect(session, {127, 0, 0, 1}, 443, [])
    {:ok, session: session}
  end

  test "admits safe requests as replayable 0-RTT stream operations", %{session: session} do
    assert Session.early_offered?(session)
    assert {:ok, session, ref} = Session.request(session, @get, "", early_data: @remembered)
    assert_received {:open, :bidi, :replayable}
    assert_received {:send, {:stream, :bidi, 0}, _headers, true, :replayable}
    refute session.open?
    refute Session.early_data?(session, ref)
  end

  test "rejects unsafe, body-bearing and oversized early requests", %{session: session} do
    post = List.keyreplace(@get, ":method", 0, {":method", "POST"})

    assert {:error, _, :early_data_unsafe_request} =
             Session.request(session, post, "", early_data: @remembered)

    assert {:error, _, :early_data_unsafe_request} =
             Session.request(session, @get, "body", early_data: @remembered)

    large = @get ++ [{"x-large", String.duplicate("a", 5_000)}]

    assert {:error, _, :peer_field_section_limit} =
             Session.request(session, large, "", early_data: @remembered)

    assert {:error, _, :not_open} = Session.request(session, @get, "", [])
    Process.put(:ready, :ready)

    assert {:error, _, :early_data_unavailable} =
             Session.request(session, @get, "", early_data: @remembered)

    refute_received {:open, _, _}
  end

  test "accepted 0-RTT keeps the request and binds remembered SETTINGS", %{session: session} do
    {:ok, session, ref} = Session.request(session, @get, "", early_data: @remembered)
    Process.put(:ready, :ready)
    Process.put(:info, {:ok, %{resumption: %{early_data: :accepted}}})
    assert {:ok, session} = Session.open(session)
    assert Session.early_data?(session, ref)
    assert Map.has_key?(session.requests, ref)
    refute_received {:open, :bidi, nil}

    assert {:error, _, {:http3_error, :connection, 0x109, :remembered_settings_reduced}} =
             peer_settings(session, [{1, 0}, {6, 2_048}, {7, 0}, {8, 1}])

    assert {:error, _, {:http3_error, :connection, 0x109, :remembered_settings_reduced}} =
             peer_settings(session, [{6, 4_096}])

    assert {:ok, _session, events} = peer_settings(session, [{6, 8_192}, {8, 1}])
    assert {:settings, [{6, 8_192}, {8, 1}]} in events
  end

  test "rejected 0-RTT re-sends each early request once after the handshake", %{
    session: session
  } do
    {:ok, session, first} = Session.request(session, @get, "", early_data: @remembered)
    {:ok, session, second} = Session.request(session, @get, "", early_data: @remembered)
    flush()
    Process.put(:ready, :ready)
    Process.put(:info, {:ok, %{resumption: %{early_data: :rejected}}})
    assert {:ok, session} = Session.open(session)

    assert [{:open, :bidi, nil}, {:open, :bidi, nil}] =
             for({:open, :bidi, _} = m <- flush(), do: m)

    assert %{stream: {:stream, :bidi, a}} = session.requests[first]
    assert %{stream: {:stream, :bidi, b}} = session.requests[second]
    assert a > 1 and b > a
    refute Session.early_data?(session, first)

    # A peer SETTINGS frame is not bound by remembered values after rejection.
    assert {:ok, _session, _events} = peer_settings(session, [])
  end

  defp peer_settings(session, settings) do
    peer = {:stream, :peer_control}
    Process.put(:events, {:ok, [{:stream_open, peer, :uni}, {:readable, peer}]})
    payload = <<0>> <> Frame.encode!(:settings, Settings.encode!(settings))
    Process.put(:read, {:ok, [{:data, 3, payload}]})
    Session.poll(session, 8)
  end

  defp flush(acc \\ []) do
    receive do
      message -> flush([message | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
