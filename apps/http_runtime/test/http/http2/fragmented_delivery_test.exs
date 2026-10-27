defmodule HTTP.HTTP2.FragmentedDeliveryTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{ConnectionOwner, Frame, HPACK}

  test "byte streams retain separate receive fragments until bounded FIFO consumption" do
    {owner, id} = stream()
    fragments(owner, id, 255)
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:data, 1, id, "z"))

    assert Process.alive?(owner)
    refute_receive {:http2, ^id, {:http2, :stream_error, _}}, 0
    assert %{buffered_receive_bytes: 256} = ConnectionOwner.status(owner)

    sibling = open(owner)

    assert :ok =
             ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 5, sibling, <<0x88>>))

    assert_receive {:http2, ^sibling, {:http2, :headers, [{":status", "200"}], 5}}

    for _ <- 1..64 do
      assert_receive {:http2, ^id, {:http2, :data, "x", 0}}
    end

    refute_receive {:http2, ^id, _}, 0
    assert :queue.len(:sys.get_state(owner).streams[id].deliveries) <= 128
    assert :ok = ConnectionOwner.acknowledge(owner, id)
    assert_receive {:http2, ^id, {:http2, :data, rest, 1}}
    assert rest == String.duplicate("x", 191) <> "z"
    assert %{buffered_receive_bytes: 255} = ConnectionOwner.status(owner)

    for _ <- 1..64, do: assert(:ok = ConnectionOwner.acknowledge(owner, id))
    assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
    assert {:error, :unknown_delivery} = ConnectionOwner.acknowledge(owner, id)
  end

  test "padding remains charged until its coalesced delivery is consumed" do
    {owner, id} = stream()
    fragments(owner, id, 64)

    for _ <- 1..128 do
      assert :ok =
               ConnectionOwner.receive_bytes(
                 owner,
                 Frame.encode(:data, 8, id, <<3, "x", 0, 0, 0>>)
               )
    end

    assert %{buffered_receive_bytes: 704} = ConnectionOwner.status(owner)
    for _ <- 1..64, do: assert_receive({:http2, ^id, {:http2, :data, "x", 0}})
    assert :ok = ConnectionOwner.acknowledge(owner, id)
    assert_receive {:http2, ^id, {:http2, :data, bytes, 8}}
    assert bytes == String.duplicate("x", 128)
    for _ <- 1..63, do: assert(:ok = ConnectionOwner.acknowledge(owner, id))
    assert %{buffered_receive_bytes: 640} = ConnectionOwner.status(owner)
    assert :ok = ConnectionOwner.acknowledge(owner, id)
    assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
  end

  test "ordinary response deliveries retain their original finite count limit" do
    {owner, id} = stream(false)
    fragments(owner, id, 129)
    assert_receive {:http2, ^id, {:http2, :stream_error, :delivery_buffer_full}}
    assert :ok = ConnectionOwner.release_stream(owner, id)
    assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
    assert Process.alive?(owner)
  end

  test "deferred delivery cannot enlarge the advertised stream receive window" do
    {owner, id} = stream()
    fragments(owner, id, 64)

    for size <- [16_384, 16_384, 16_384, 16_319] do
      bytes = String.duplicate("x", size)
      assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:data, 0, id, bytes))
    end

    assert %{buffered_receive_bytes: 65_535} = ConnectionOwner.status(owner)

    assert {:error, :flow_control_error} =
             ConnectionOwner.receive_bytes(owner, Frame.encode(:data, 0, id, "x"))

    assert %{buffered_receive_bytes: 65_535} = ConnectionOwner.status(owner)
    assert :ok = ConnectionOwner.release_stream(owner, id)
    assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
  end

  for terminal <- [:trailers, :reset] do
    test "retained fragments precede #{terminal} while a sibling remains healthy" do
      {owner, id} = stream()
      fragments(owner, id, 256)

      case unquote(terminal) do
        :trailers ->
          {_, block} = HPACK.encode_headers(HPACK.new_encoder(), [{"x-tail", "yes"}])
          assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 5, id, block))

        :reset ->
          assert :ok =
                   ConnectionOwner.receive_bytes(
                     owner,
                     Frame.encode(:rst_stream, 0, id, <<8::32>>)
                   )
      end

      for _ <- 1..64 do
        assert_receive {:http2, ^id, {:http2, :data, "x", 0}}
      end

      assert_receive {:http2, ^id, {:http2, :data, rest, 0}}
      assert rest == String.duplicate("x", 192)

      case unquote(terminal) do
        :trailers -> assert_receive {:http2, ^id, {:http2, :headers, [{"x-tail", "yes"}], 5}}
        :reset -> assert_receive {:http2, ^id, {:http2, :reset, 8}}
      end

      for _ <- 1..65, do: assert(:ok = ConnectionOwner.acknowledge(owner, id))
      assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
      sibling = open(owner)

      assert :ok =
               ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 5, sibling, <<0x88>>))

      assert_receive {:http2, ^sibling, {:http2, :headers, [{":status", "200"}], 5}}
      assert Process.alive?(owner)
    end
  end

  for terminal <- [:peer_closed, {:peer_error, :closed}] do
    test "retained fragments precede transport terminal #{inspect(terminal)}" do
      {owner, id} = stream()
      monitor = Process.monitor(owner)
      fragments(owner, id, 256)
      send(owner, unquote(Macro.escape(terminal)))

      for _ <- 1..64, do: assert_receive({:http2, ^id, {:http2, :data, "x", 0}})
      assert_receive {:http2, ^id, {:http2, :data, rest, 0}}
      assert rest == String.duplicate("x", 192)

      case unquote(Macro.escape(terminal)) do
        :peer_closed ->
          assert_receive {:http2, ^id, {:http2, :transport_closed}}

        {:peer_error, :closed} ->
          assert_receive {:http2, ^id, {:http2, :transport_error, :closed}}
      end

      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    end
  end

  defp fragments(owner, id, count) do
    for _ <- 1..count,
        do: assert(:ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:data, 0, id, "x")))
  end

  defp stream(byte_stream? \\ true) do
    transport = %{
      send: fn _, _ -> :ok end,
      normalize_message: fn
        :peer_closed, _ -> :closed
        {:peer_error, reason}, _ -> {:error, reason}
        _, _ -> :unknown
      end
    }

    owner =
      start_supervised!({ConnectionOwner, transport: transport, activate?: false})

    assert :ok = ConnectionOwner.activate(owner)
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, <<>>))
    id = open(owner, byte_stream?)
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 4, id, <<0x88>>))
    assert_receive {:http2, ^id, {:http2, :headers, [{":status", "200"}], 4}}
    {owner, id}
  end

  defp open(owner, byte_stream? \\ true) do
    assert {:ok, %{id: id}} =
             ConnectionOwner.open_stream(owner, [{":method", "GET"}], byte_stream: byte_stream?)

    id
  end
end
