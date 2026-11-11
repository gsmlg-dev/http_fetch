defmodule HTTP.H3.ExtensionsTest do
  use ExUnit.Case, async: true
  alias HTTP.H3.{Capsule, Datagram, Settings, Varint}
  alias HTTP.H3.WebTransport.Draft17

  test "draft17 setting is explicit and cannot substitute legacy setting" do
    assert Settings.wt_enabled() == 0x2C7CF000
    assert Settings.wt_enabled_draft17() == 0x20B8933B
    assert {:ok, bytes} = Settings.encode(wt_enabled_draft17: 1)
    assert {:ok, [{0x20B8933B, 1}]} = Settings.decode(bytes)
    assert {:error, _} = Settings.validate(wt_enabled_draft17: 2)

    assert {:error, :webtransport_draft17_not_enabled} =
             Draft17.validate_server_settings([{Settings.wt_enabled(), 1}, {8, 1}, {51, 1}])

    assert :ok = Draft17.validate_server_settings(Draft17.client_settings() ++ [{8, 1}])
  end

  test "capsules tolerate bytewise framing, skip unknowns and reject finite overflow" do
    {:ok, unknown} = Capsule.encode(31, :binary.copy("x", 100))
    {:ok, close} = Capsule.encode(0x2843, <<0, 0, 0, 42, "bye">>)

    {state, events} =
      Enum.reduce(:binary.bin_to_list(unknown <> close), {Capsule.new(), []}, fn byte,
                                                                                 {state, acc} ->
        assert {:ok, state, events} = Capsule.feed(state, <<byte>>)
        assert Capsule.retained_bytes(state) <= 15
        {state, acc ++ events}
      end)

    assert events == [{:capsule, 0x2843, <<0, 0, 0, 42, "bye">>}]
    assert :ok = Capsule.finish(state)

    assert {:error, :capsule_too_large} =
             Capsule.feed(Capsule.new(), Varint.encode!(0x2843) <> Varint.encode!(65_537))

    # Unknown capsules are skipped without retention, so their size is not bounded.
    large = Varint.encode!(31) <> Varint.encode!(70_000)
    assert {:ok, state, []} = Capsule.feed(Capsule.new(), large <> :binary.copy("x", 40_000))
    assert Capsule.retained_bytes(state) == 0

    assert {:ok, state, [{:capsule, 0x2843, "z"}]} =
             Capsule.feed(
               state,
               :binary.copy("y", 30_000) <> Varint.encode!(0x2843) <> <<1, "z">>
             )

    assert :ok = Capsule.finish(state)

    assert {:ok, state, []} = Capsule.feed(Capsule.new(), <<0x40>>)
    assert {:error, :truncated_capsule} = Capsule.finish(state)
  end

  test "quarter-stream association includes overhead and preserves empty datagrams" do
    assert {:ok, <<1>>} = Datagram.encode(4, "", 1)
    assert {:ok, 4, ""} = Datagram.decode(<<1>>, 1)
    assert {:error, :datagram_too_large} = Datagram.encode(256, "x", 2)
    assert {:error, :invalid_session_id} = Datagram.encode(3, "", 4)

    assert {:error, :invalid_datagram_association} =
             Datagram.decode(Varint.encode!(1_152_921_504_606_846_976), 8)

    assert {:error, :invalid_datagram_association} = Datagram.decode(<<0x40>>, 8)
  end

  test "draft17 application errors skip HTTP3 reserved codes and validate close/drain" do
    for code <- [0, 29, 30, 31, 0xFFFFFFFF] do
      assert {:ok, wire} = Draft17.application_error(code)
      assert {:ok, ^code} = Draft17.decode_application_error(wire)
    end

    assert {:error, :invalid_application_error} = Draft17.application_error(0x100000000)
    assert {:ok, bytes} = Draft17.close_capsule(42, "bye")
    assert {:ok, _, [capsule]} = Capsule.feed(Capsule.new(), bytes)
    assert {:ok, {:close, 42, "bye"}} = Draft17.decode_capsule(capsule)

    assert {:error, :invalid_close_reason} =
             Draft17.decode_capsule({:capsule, 0x2843, <<0::32, 255>>})

    assert {:error, :invalid_close_reason} = Draft17.close_capsule(0, :binary.copy("x", 1025))
    assert {:ok, :drain} = Draft17.decode_capsule({:capsule, 0x78AE, ""})
    assert {:error, :invalid_drain_capsule} = Draft17.decode_capsule({:capsule, 0x78AE, "x"})
  end

  test "WT prefixes use actual CONNECT stream IDs and tolerate split varints" do
    for kind <- [:uni, :bidi] do
      assert {:ok, bytes} = Draft17.prefix(kind, 256)

      for size <- 0..(byte_size(bytes) - 1),
          do: assert(:more == Draft17.decode_prefix(kind, binary_part(bytes, 0, size)))

      assert {:ok, 256, "payload"} = Draft17.decode_prefix(kind, bytes <> "payload")
      assert {:error, :invalid_session_id} = Draft17.prefix(kind, 3)
    end
  end
end
