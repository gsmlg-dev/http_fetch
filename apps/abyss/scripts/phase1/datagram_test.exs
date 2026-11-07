# Explicit QUIC consumer regression: ordinary Abyss tests do not load engines.
{:ok, _} = Application.ensure_all_started(:abyss)
{:ok, _} = Application.ensure_all_started(:elixir_quic)
ExUnit.start(autorun: false)

defmodule Abyss.QUICDatagramTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  @alpn "abyss-datagram-v1"
  @limits [max_frame_size: 1200, max_items: 64, max_buffer_bytes: 65_536]

  defmodule Handler do
    @behaviour Abyss.QUIC.Handler

    def init(connection, metadata, {owner, control}) do
      send(owner, {:bound, connection, metadata, self()})
      {:ok, {connection, owner, control}}
    end

    def handle_event(:tick, {connection, _owner, control} = state) do
      request =
        Agent.get_and_update(control, fn
          [request | rest] -> {request, rest}
          [] -> {nil, []}
        end)

      if request do
        {caller, ref, operation} = request
        send(caller, {ref, operation.(connection)})
      end

      {:ok, state}
    end

    def handle_event(event, {_connection, owner, _control} = state) do
      send(owner, {:event, self(), event})
      {:ok, state}
    end
  end

  test "public DATAGRAM calls preserve payloads, operation references and stream progress" do
    {client, server, worker, control, metadata} = pair(@limits, @limits)
    assert metadata.alpn == @alpn
    assert metadata.datagram == %{send_max_bytes: 1197, receive_max_bytes: 1197}
    boundary = :binary.copy(<<0xAB>>, metadata.datagram.send_max_bytes)
    payloads = [<<>>, "same", "same", boundary]

    for payload <- payloads do
      assert {:ok, _} = Quic.send_datagram(client, payload)
    end

    await_info(server, &(&1.resources.datagram_ready_items == 4))
    assert_receive {:event, ^worker, :datagram_readable}, 2000
    assert {:error, :not_consumer} = Abyss.QUIC.read_datagrams(server)
    read_ref = make_ref()
    assert {:ok, received} = call(control, &Abyss.QUIC.read_datagrams(&1, 2, ref: read_ref))
    assert length(received) == 2
    assert {:ok, ^received} = call(control, &Abyss.QUIC.read_datagrams(&1, 2, ref: read_ref))

    assert %{status: :completed, result: {:ok, ^received}} =
             Abyss.QUIC.operation_status(server, read_ref)

    assert_receive {:event, ^worker, :datagram_readable}, 2000
    assert {:ok, rest} = call(control, &Abyss.QUIC.read_datagrams/1)
    assert Enum.frequencies(received ++ rest) == Enum.frequencies(payloads)

    ref = make_ref()
    assert {:ok, ^ref} = Abyss.QUIC.send_datagram(server, "reply", ref: ref)
    assert {:ok, ^ref} = Abyss.QUIC.send_datagram(server, "reply", ref: ref)
    assert {:error, :operation_ref_conflict} = Abyss.QUIC.send_datagram(server, "other", ref: ref)
    assert %{result: {:ok, ^ref}} = Abyss.QUIC.operation_status(server, ref)
    assert {:ok, _} = Abyss.QUIC.send_datagram(server, <<>>)
    assert {:ok, _} = Abyss.QUIC.send_datagram(server, boundary)
    await_info(client, &(&1.resources.datagram_ready_items == 3))
    assert {:ok, received} = Quic.read_datagrams(client)
    assert Enum.frequencies(received) == Enum.frequencies(["reply", <<>>, boundary])

    assert {:error, :datagram_too_large} =
             Abyss.QUIC.send_datagram(server, boundary <> <<0>>)

    assert {:error, :deadline_expired} = Abyss.QUIC.send_datagram(server, "late", deadline: 0)
    stale = %{server | generation: make_ref()}
    assert {:error, :stale_handle} = Abyss.QUIC.send_datagram(stale, "stale")
    assert {:error, :stale_handle} = call(control, fn _ -> Abyss.QUIC.read_datagrams(stale) end)

    assert {:ok, stream} = Quic.open_stream(client, :bidi)
    assert {:ok, _} = Quic.send_stream(stream, "reliable", true)
    assert_receive {:event, ^worker, {:stream_open, incoming, :bidi}}, 2000
    assert_receive {:event, ^worker, {:readable, ^incoming}}, 2000

    assert {:ok, [{:data, _, "reliable"}, {:fin, _}]} =
             call(control, fn _ -> Abyss.QUIC.read(incoming, 1024) end)
  end

  test "default listeners reject DATAGRAM operations without peer negotiation" do
    {_client, server, _worker, control, metadata} = pair(nil, nil)
    assert metadata.datagram == %{send_max_bytes: 0, receive_max_bytes: 0}
    assert {:error, :datagram_unsupported} = Abyss.QUIC.send_datagram(server, "disabled")
    assert {:error, :datagram_unsupported} = call(control, &Abyss.QUIC.read_datagrams/1)
  end

  test "receive negotiation remains directional" do
    {client, server, _worker, control, metadata} = pair(nil, @limits)
    assert metadata.datagram == %{send_max_bytes: 1197, receive_max_bytes: 0}
    assert {:error, :datagram_unsupported} = Quic.send_datagram(client, "disabled")
    assert {:error, :datagram_unsupported} = call(control, &Abyss.QUIC.read_datagrams/1)
    assert {:ok, _} = Abyss.QUIC.send_datagram(server, "one-way")
    await_info(client, &(&1.resources.datagram_ready_items == 1))
    assert {:ok, ["one-way"]} = Quic.read_datagrams(client)
  end

  test "server receive support does not require peer receive support" do
    {client, server, _worker, control, metadata} = pair(@limits, nil)
    assert metadata.datagram == %{send_max_bytes: 0, receive_max_bytes: 1197}
    assert {:error, :datagram_unsupported} = Abyss.QUIC.send_datagram(server, "disabled")
    assert {:ok, _} = Quic.send_datagram(client, "receive-only")
    await_info(server, &(&1.resources.datagram_ready_items == 1))
    assert {:ok, ["receive-only"]} = call(control, &Abyss.QUIC.read_datagrams/1)
  end

  for {name, limits} <- [
        items: [max_frame_size: 1200, max_items: 1, max_buffer_bytes: 8],
        bytes: [max_frame_size: 1200, max_items: 2, max_buffer_bytes: 4]
      ] do
    test "receive #{name} overflow drops whole messages and retains admitted bytes" do
      {client, server, _worker, control, _metadata} = pair(unquote(limits), @limits)
      assert {:ok, _} = Quic.send_datagram(client, "abcd")
      await_info(server, &(&1.resources.datagram_ready_items == 1))
      assert {:ok, _} = Quic.send_datagram(client, "efgh")
      await_info(server, &(&1.resources.datagram_drops == 1))
      assert {:ok, ["abcd"]} = call(control, &Abyss.QUIC.read_datagrams/1)

      assert {:ok, %{resources: %{datagram_ready_bytes: 0, datagram_drops: 1}}} =
               Abyss.QUIC.info(server)
    end
  end

  defp pair(server_limits, client_limits) do
    control = start_supervised!({Agent, fn -> [] end})

    listener =
      start_supervised!(
        {Abyss.QUIC,
         [
           handler: {Handler, {self(), control}},
           alpn: [@alpn],
           tls: server_tls(),
           poll_interval: 1,
           quic_options: options(server_limits)
         ]}
      )

    client =
      start_supervised!(%{
        id: :client,
        start: {Quic, :client, [[acceptor: self(), tls: client_tls()] ++ options(client_limits)]}
      })

    assert {:ok, local} = Abyss.QUIC.local(listener)
    assert {:ok, outgoing} = Quic.connect(client, local)
    assert :ok = Quic.attach(outgoing, self())
    assert_receive {:quic_ready, ^outgoing, _}, 2000
    assert_receive {:bound, incoming, metadata, worker}, 2000
    {outgoing, incoming, worker, control, metadata}
  end

  defp options(nil), do: []
  defp options(limits), do: [datagram: limits]

  defp call(control, operation) do
    ref = make_ref()
    caller = self()
    Agent.update(control, &(&1 ++ [{caller, ref, operation}]))
    assert_receive {^ref, result}, 2000
    result
  end

  defp await_info(connection, predicate),
    do: await_info(connection, predicate, System.monotonic_time(:millisecond) + 2000)

  defp await_info(connection, predicate, deadline) do
    assert {:ok, info} = Quic.info(connection)

    unless predicate.(info) do
      assert System.monotonic_time(:millisecond) < deadline,
             "traffic condition timed out: #{inspect(info)}"

      receive do
      after
        1 -> :ok
      end

      await_info(connection, predicate, deadline)
    end
  end

  defp server_tls do
    [{type, key, :not_encrypted}] = :public_key.pem_decode(File.read!(fixture("leaf-key.pem")))
    [cert: [cert("leaf.pem")], key: {type, key}]
  end

  defp client_tls,
    do: [
      cacerts: [cert("root.pem")],
      reference_identity: {:dns_id, "example.test"},
      alpn: [@alpn]
    ]

  defp cert(name) do
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(File.read!(fixture(name)))
    der
  end

  defp fixture(name), do: Path.expand("../../test/fixtures/quic/server_flight/#{name}", __DIR__)
end

result = ExUnit.run()
if result.failures > 0 or result.excluded > 0, do: System.halt(1)
IO.puts("ABYSS_QUIC_DATAGRAM_TEST_PASS")
