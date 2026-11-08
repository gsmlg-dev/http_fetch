defmodule Quic.ReliablePrefixIntegrationTest do
  # Two in-repo endpoints: a peer STOP_SENDING on a stream opened with a
  # declared `reliable_prefix` is answered with RESET_STREAM_AT when reliable
  # reset is negotiated, and with an ordinary RESET_STREAM otherwise.
  use ExUnit.Case, async: true
  @moduletag :integration
  alias Quic.Endpoint

  defp credentials do
    fixture = Path.expand("../fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-prefix"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-prefix"]
     ]}
  end

  defp connected(server_reset?) do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen(tls: server_tls, reliable_reset: server_reset?)
    {:ok, client} = Quic.client(tls: client_tls, reliable_reset: true)
    on_exit(fn -> Enum.each([server, client], &stop_endpoint/1) end)
    {:ok, connection} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2_000
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    {connection, accepted}
  end

  defp stop_prefixed_stream(connection, accepted) do
    {:ok, stream} = Quic.open_stream(connection, :uni, reliable_prefix: 6)
    {:ok, _} = Quic.send_stream(stream, "header-tail", false)
    incoming = await_stream(accepted)
    assert {:ok, _} = Quic.stop_stream(incoming, 77)
    {stream, incoming}
  end

  test "negotiated reliable reset answers peer STOP_SENDING with RESET_STREAM_AT" do
    {connection, accepted} = connected(true)
    {:ok, %{reliable_reset: %{negotiated: true}}} = Quic.info(connection)
    {stream, incoming} = stop_prefixed_stream(connection, accepted)

    assert eventually(fn ->
             match?(%{send_reset: 77, send_reliable: 6}, stream_state(connection, stream.id))
           end)

    # The peer observed RESET_STREAM_AT: its reliable size is the declared prefix.
    assert eventually(fn ->
             match?(%{reset: 77, recv_reliable: 6}, stream_state(accepted, incoming.id))
           end)

    assert {:error, :stopped} = Quic.send_stream(stream, "more", false)
  end

  test "without peer support the prefixed stream keeps the ordinary RESET_STREAM" do
    {connection, accepted} = connected(false)
    {:ok, %{reliable_reset: %{negotiated: false}}} = Quic.info(connection)
    {stream, incoming} = stop_prefixed_stream(connection, accepted)

    assert eventually(fn ->
             match?(%{send_reset: 77, send_reliable: nil}, stream_state(connection, stream.id))
           end)

    assert eventually(fn ->
             match?(%{reset: 77, recv_reliable: nil}, stream_state(accepted, incoming.id))
           end)
  end

  test "an invalid reliable prefix is rejected without opening a stream" do
    {connection, _accepted} = connected(true)

    assert {:error, :invalid_reliable_prefix} =
             Quic.open_stream(connection, :bidi, reliable_prefix: -1)

    assert {:ok, %{id: 0}} = Quic.open_stream(connection, :bidi, reliable_prefix: 0)
  end

  defp await_stream(accepted, deadline \\ System.monotonic_time(:millisecond) + 2_000) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(accepted)

    case Enum.find(events, &match?({:stream_open, _, :uni}, &1)) do
      {:stream_open, stream, :uni} ->
        stream

      nil ->
        Process.sleep(5)
        await_stream(accepted, deadline)
    end
  end

  defp stream_state(connection, id) do
    {_phase, data} = :sys.get_state(connection.id)
    data.scheduler.streams.streams[id]
  end

  defp stop_endpoint(pid) do
    GenServer.stop(pid)
  catch
    :exit, _ -> :ok
  end

  defp eventually(fun, n \\ 400)
  defp eventually(_, 0), do: false

  defp eventually(fun, n) do
    if fun.() do
      true
    else
      Process.sleep(5)
      eventually(fun, n - 1)
    end
  end
end
