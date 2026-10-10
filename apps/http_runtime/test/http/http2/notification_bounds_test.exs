defmodule HTTP.HTTP2.NotificationBoundsTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{ConnectionOwner, Frame, HPACK, Pool}

  @informational <<0x08, 3, "103">>

  test "128 informational heads succeed and head 129 resets only its stream across deliveries" do
    owner = owner()
    first = open(owner)
    sibling = open(owner)

    for _ <- 1..128 do
      assert :ok =
               ConnectionOwner.receive_bytes(
                 owner,
                 Frame.encode(:headers, 4, first, @informational)
               )

      assert_receive {:http2, ^first, {:http2, :headers, [{":status", "103"}], 4}}
    end

    assert :ok =
             ConnectionOwner.receive_bytes(
               owner,
               Frame.encode(:headers, 4, first, @informational)
             )

    assert_receive {:http2, ^first, {:http2, :stream_error, :http2_informational_limit}}

    for _ <- 1..16 do
      assert :ok =
               ConnectionOwner.receive_bytes(
                 owner,
                 Frame.encode(:headers, 4, first, @informational)
               )
    end

    refute_receive {:http2, ^first, _}

    assert :ok =
             ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 5, sibling, <<0x88>>))

    assert_receive {:http2, ^sibling, {:http2, :headers, [{":status", "200"}], 5}}
    assert Process.alive?(owner)
  end

  test "a single 4096-head delivery cannot accumulate more than the lifetime allowance" do
    owner = owner()
    id = open(owner)
    batch = :binary.copy(Frame.encode(:headers, 4, id, @informational), 4_096)
    assert :ok = ConnectionOwner.receive_bytes(owner, batch)
    assert_receive {:http2, ^id, {:http2, :stream_error, :http2_informational_limit}}
    assert {:messages, messages} = Process.info(self(), :messages)
    headers = Enum.filter(messages, &match?({:http2, ^id, {:http2, :headers, _, _}}, &1))
    assert length(headers) <= 128
    refute_receive {:http2, ^id, {:http2, :stream_error, _}}
  end

  test "an unread subscriber mailbox has the same finite lifetime admission" do
    parent = self()

    subscriber =
      spawn_link(fn ->
        receive do
          :inspect ->
            send(parent, {:backlog, Process.info(self(), :messages)})
        end
      end)

    owner = owner()
    id = open(owner, subscriber)

    for _ <- 1..4_096,
        do: ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 4, id, @informational))

    send(subscriber, :inspect)
    assert_receive {:backlog, {:messages, messages}}, 3_000
    assert Enum.count(messages, &match?({:http2, ^id, {:http2, :headers, _, _}}, &1)) == 128
    assert Enum.count(messages, &match?({:http2, ^id, {:http2, :stream_error, _}}, &1)) == 1
  end

  test "informational metadata boundary is enforced before enqueue" do
    owner = owner()
    id = open(owner)
    # Two heads each charge 1 name byte + 32735 value bytes + 32 = 32768.
    {encoder, block} =
      HPACK.encode_headers(HPACK.new_encoder(), [
        {":status", "103"},
        {"x", String.duplicate("v", 32_735)}
      ])

    {_, next} =
      HPACK.encode_headers(encoder, [{":status", "103"}, {"x", String.duplicate("v", 32_735)}])

    assert :ok = ConnectionOwner.receive_bytes(owner, headers_frames(id, block))
    assert_receive {:http2, ^id, {:http2, :headers, _, 4}}
    assert :ok = ConnectionOwner.receive_bytes(owner, headers_frames(id, next))
    assert_receive {:http2, ^id, {:http2, :headers, _, 4}}
    {_, over} = HPACK.encode_headers(HPACK.new_encoder(), [{":status", "103"}, {"x", ""}])
    assert :ok = ConnectionOwner.receive_bytes(owner, headers_frames(id, over))
    assert_receive {:http2, ^id, {:http2, :stream_error, :http2_informational_limit}}
    refute_receive {:http2, ^id, {:http2, :headers, _, _}}
  end

  test "SETTINGS coalesces one outstanding snapshot and stale ACK cannot renew it" do
    owner = owner()
    send(owner, {:http2_pool, self(), :key})
    ConnectionOwner.status(owner)

    for index <- 1..4_096 do
      settings = if rem(index, 2) == 0, do: <<>>, else: <<3::16, 7::32>>
      assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, settings))
    end

    assert {:messages, messages} = Process.info(self(), :messages)

    assert [{:"$gen_cast", {:owner_snapshot, :key, ^owner, token, {true, false, 100}}}] =
             Enum.filter(messages, &match?({:"$gen_cast", _}, &1))

    assert_receive {:"$gen_cast", {:owner_snapshot, :key, ^owner, ^token, _}}
    send(owner, {:http2_capacity_ack, self(), make_ref()})
    ConnectionOwner.status(owner)
    refute_receive {:"$gen_cast", _}
    send(owner, {:http2_capacity_ack, self(), token})
    ConnectionOwner.status(owner)
    assert_receive {:"$gen_cast", {:owner_snapshot, :key, ^owner, latest_token, {true, false, 7}}}
    send(owner, {:http2_capacity_ack, self(), token})
    ConnectionOwner.status(owner)
    refute_receive {:"$gen_cast", _}
    send(owner, {:http2_capacity_ack, self(), latest_token})
    ConnectionOwner.status(owner)
    for _ <- 1..16, do: ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, <<>>))
    refute_receive {:"$gen_cast", _}
  end

  test "real pool applies and acknowledges the latest coalesced snapshot" do
    owner = owner()
    pool = start_supervised!({Pool, idle_timeout: 0})
    assert :ok = Pool.register(pool, :key, owner)
    :sys.suspend(pool)

    try do
      assert :ok =
               ConnectionOwner.receive_bytes(
                 owner,
                 Frame.encode(:settings, 0, 0, <<3::16, 5::32>>)
               )

      assert :ok =
               ConnectionOwner.receive_bytes(
                 owner,
                 Frame.encode(:settings, 0, 0, <<3::16, 2::32>>)
               )
    after
      :sys.resume(pool)
    end

    wait_capacity(pool, owner, 2, System.monotonic_time(:millisecond) + 3_000)
  end

  test "repeated GOAWAY notifies once and preserves drain timer while decreasing cutoff is enforced" do
    owner = owner()
    first = open(owner)
    last = open(owner)
    send(owner, {:http2_pool, self(), :key})
    ConnectionOwner.status(owner)
    assert_receive {:"$gen_cast", _}

    assert :ok =
             ConnectionOwner.receive_bytes(
               owner,
               Frame.encode(:goaway, 0, 0, <<0::1, last::31, 0::32>>)
             )

    assert_receive {:"$gen_cast", {:owner_draining, :key, ^owner}}
    assert_receive {:http2, ^first, {:http2, :goaway, ^last, 0}}
    assert_receive {:http2, ^last, {:http2, :goaway, ^last, 0}}
    timer = :sys.get_state(owner).drain_timer
    batch = :binary.copy(Frame.encode(:goaway, 0, 0, <<0::1, last::31, 0::32>>), 4_096)
    assert :ok = ConnectionOwner.receive_bytes(owner, batch)
    assert :sys.get_state(owner).drain_timer == timer
    refute_receive {:"$gen_cast", _}
    refute_receive {:http2, _, {:http2, :goaway, _, _}}

    assert :ok =
             ConnectionOwner.receive_bytes(
               owner,
               Frame.encode(:goaway, 0, 0, <<0::1, first::31, 0::32>>)
             )

    assert_receive {:http2, ^last, {:http2, :stream_error, {:goaway, ^first, 0, :unprocessed}}}
    assert :sys.get_state(owner).drain_timer == timer
  end

  test "raw HPACK literals own backing in output and dynamic table" do
    value = String.duplicate("x", 512)
    # Incremental indexing, literal name, non-Huffman value of 512 bytes.
    block = <<0x40, 1, "x", 127, 129, 3, value::binary>>
    carrier = block <> :binary.copy(<<0>>, 2 * 1_048_576)
    borrowed = binary_part(carrier, 0, byte_size(block))
    assert :binary.referenced_byte_size(borrowed) > byte_size(borrowed)
    assert {:ok, decoder, [{"x", ^value}]} = HPACK.decode(HPACK.new_decoder(), borrowed)

    for {name, retained} <- decoder.dynamic do
      assert :binary.referenced_byte_size(name) == byte_size(name)
      assert :binary.referenced_byte_size(retained) == byte_size(retained)
    end
  end

  test "128 informational notifications and one final are admitted in a single delivery" do
    owner = owner()
    id = open(owner)
    batch = :binary.copy(Frame.encode(:headers, 4, id, @informational), 128)

    assert :ok =
             ConnectionOwner.receive_bytes(
               owner,
               batch <> Frame.encode(:headers, 5, id, <<0x88>>)
             )

    for _ <- 1..128,
        do: assert_receive({:http2, ^id, {:http2, :headers, [{":status", "103"}], 4}})

    assert_receive {:http2, ^id, {:http2, :headers, [{":status", "200"}], 5}}
  end

  test "rejected and closed-stream headers still advance the shared dynamic decoder" do
    owner = owner()
    first = open(owner)
    sibling = open(owner)

    assert :ok =
             ConnectionOwner.receive_bytes(
               owner,
               :binary.copy(Frame.encode(:headers, 4, first, @informational), 128)
             )

    {encoder, rejected} =
      HPACK.encode_headers(HPACK.new_encoder(), [{":status", "103"}, {"x", "rejected"}],
        indexing: :incremental
      )

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 4, first, rejected))
    assert_receive {:http2, ^first, {:http2, :stream_error, :http2_informational_limit}}

    {encoder, closed} =
      HPACK.encode_headers(encoder, [{":status", "103"}, {"x", "closed"}], indexing: :incremental)

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 4, first, closed))

    {_, final} =
      HPACK.encode_headers(encoder, [{":status", "200"}, {"x", "closed"}], indexing: :incremental)

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 5, sibling, final))

    assert_receive {:http2, ^sibling,
                    {:http2, :headers, [{":status", "200"}, {"x", "closed"}], 5}}
  end

  test "partial header fragments own their binary backing" do
    owner = owner()
    id = open(owner)
    encoded = Frame.encode(:headers, 0, id, String.duplicate("x", 512))
    carrier = encoded <> :binary.copy(<<0>>, 2 * 1_048_576)
    borrowed = binary_part(carrier, 0, byte_size(encoded))
    assert :binary.referenced_byte_size(borrowed) > byte_size(borrowed)
    assert :ok = ConnectionOwner.receive_bytes(owner, borrowed)
    assert [fragment] = :sys.get_state(owner).connection.header_block.fragments
    assert :binary.referenced_byte_size(fragment) == byte_size(fragment)
  end

  test "binding after SETTINGS reports current policy once and duplicate binding retains its token" do
    owner = owner()

    assert :ok =
             ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, <<3::16, 4::32>>))

    send(owner, {:http2_pool, self(), :key})
    ConnectionOwner.status(owner)
    assert_receive {:"$gen_cast", {:owner_snapshot, :key, ^owner, token, {true, false, 4}}}
    send(owner, {:http2_pool, self(), :key})
    ConnectionOwner.status(owner)
    refute_receive {:"$gen_cast", _}
    assert :sys.get_state(owner).capacity_inflight == {token, {true, false, 4}}
  end

  test "unknown-owner snapshot is rejected without retaining orphan state" do
    pool = start_supervised!({Pool, idle_timeout: 0})
    token = make_ref()
    GenServer.cast(pool, {:owner_snapshot, :missing, self(), token, {true, false, 1}})
    assert_receive {:http2_capacity_rejected, ^pool, ^token}
    assert Pool.stats(pool) == %{}
  end

  defp headers_frames(id, block) do
    if byte_size(block) <= 16_384 do
      Frame.encode(:headers, 4, id, block)
    else
      <<first::binary-size(16_384), rest::binary>> = block
      Frame.encode(:headers, 0, id, first) <> Frame.encode(:continuation, 4, id, rest)
    end
  end

  defp owner do
    owner =
      start_supervised!(
        {ConnectionOwner, transport: %{send: fn _, _ -> :ok end}, activate?: false}
      )

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, <<>>))
    owner
  end

  defp open(owner, subscriber \\ self()) do
    assert {:ok, %{id: id}} =
             ConnectionOwner.open_stream(owner, [{":method", "GET"}], subscriber: subscriber)

    id
  end

  defp wait_capacity(pool, owner, expected, deadline) do
    state = :sys.get_state(pool)

    if state.entries.key.connections[owner].max_streams == expected do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline
      wait_capacity(pool, owner, expected, deadline)
    end
  end
end
