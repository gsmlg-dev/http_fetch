defmodule HTTP.HTTP2.HeaderFragmentLimitTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{ConnectionOwner, Frame}

  defp owner do
    {:ok, owner} =
      ConnectionOwner.start_link(transport: %{send: fn _, _ -> :ok end}, activate?: false)

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, <<>>))
    assert {:ok, %{id: id}} = ConnectionOwner.open_stream(owner, [{":method", "GET"}])
    {owner, id}
  end

  test "256 total fragments permit empty initial and final frames" do
    {owner, id} = owner()
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 1, id, <<>>))

    for _ <- 1..253 do
      assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:continuation, 0, id, <<>>))
    end

    assert :ok =
             ConnectionOwner.receive_bytes(owner, Frame.encode(:continuation, 0, id, <<0x88>>))

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:continuation, 4, id, <<>>))
    assert_receive {:http2, ^id, {:http2, :headers, [{":status", "200"}], 5}}
  end

  for {payload, final_flags} <- [{<<>>, 0}, {<<>>, 4}, {<<0x88>>, 0}, {<<0x88>>, 4}] do
    test "rejects fragment 257 before retaining or decoding #{inspect(payload)} flags #{final_flags}" do
      {owner, id} = owner()
      assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 0, id, <<>>))

      for _ <- 1..255 do
        assert :ok =
                 ConnectionOwner.receive_bytes(owner, Frame.encode(:continuation, 0, id, <<>>))
      end

      assert {:error, :header_block_too_fragmented} =
               ConnectionOwner.receive_bytes(
                 owner,
                 Frame.encode(:continuation, unquote(final_flags), id, unquote(payload))
               )

      refute_receive {:http2, ^id, {:http2, :headers, _, _}}
    end
  end

  test "nonempty fragments have the same finite count policy" do
    {owner, id} = owner()
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 0, id, <<0x88>>))

    for _ <- 1..255 do
      assert :ok =
               ConnectionOwner.receive_bytes(owner, Frame.encode(:continuation, 0, id, <<0x88>>))
    end

    assert {:error, :header_block_too_fragmented} =
             ConnectionOwner.receive_bytes(owner, Frame.encode(:continuation, 4, id, <<0x88>>))
  end
end
