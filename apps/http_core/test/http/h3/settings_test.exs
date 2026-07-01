defmodule HTTP.H3.SettingsTest do
  use ExUnit.Case, async: true

  alias HTTP.H3.Settings
  alias HTTP.H3.Varint

  test "encodes and decodes SETTINGS payloads" do
    settings = [
      enable_connect_protocol: 1,
      h3_datagram: 1,
      wt_enabled: 1
    ]

    assert {:ok, encoded} = Settings.encode(settings)

    assert {:ok,
            [
              {enable_connect_protocol, 1},
              {h3_datagram, 1},
              {wt_enabled, 1}
            ]} = Settings.decode(encoded)

    assert enable_connect_protocol == Settings.enable_connect_protocol()
    assert h3_datagram == Settings.h3_datagram()
    assert wt_enabled == Settings.wt_enabled()
  end

  test "normalizes map and integer identifiers" do
    max_field_section_size = Settings.max_field_section_size()

    assert {:ok, normalized} =
             Settings.normalize(%{
               0x1_0000 => 9,
               max_field_section_size: 16_384
             })

    assert {max_field_section_size, 16_384} in normalized
    assert {0x1_0000, 9} in normalized
    assert max_field_section_size == Settings.max_field_section_size()
    assert Settings.name(Settings.h3_datagram()) == :h3_datagram
    assert Settings.name(0x1_0000) == nil
  end

  test "rejects duplicate settings" do
    h3_datagram = Settings.h3_datagram()

    assert {:error, {:duplicate_setting, ^h3_datagram}} =
             Settings.validate(h3_datagram: 1, h3_datagram: 1)
  end

  test "rejects reserved HTTP/3 settings" do
    assert {:error, {:reserved_setting, 0x04}} = Settings.validate([{0x04, 0}])
  end

  test "validates boolean extension setting values" do
    h3_datagram = Settings.h3_datagram()

    assert :ok = Settings.validate(h3_datagram: 1)
    assert :ok = Settings.validate(wt_enabled: 1)

    assert {:error, {:invalid_setting_value, ^h3_datagram, 2}} =
             Settings.validate(h3_datagram: 2)

    wt_enabled = Settings.wt_enabled()

    assert {:error, {:invalid_setting_value, ^wt_enabled, 2}} =
             Settings.validate(wt_enabled: 2)
  end

  test "rejects invalid setting identifiers and values" do
    assert {:error, {:unknown_setting, :unknown}} = Settings.validate(unknown: 1)
    assert {:error, :invalid_setting_identifier} = Settings.validate([{Varint.max() + 1, 1}])
    assert {:error, :invalid_setting_value} = Settings.validate(h3_datagram: -1)
  end

  test "reports truncated settings payloads" do
    assert {:error, :truncated_setting_identifier} = Settings.decode(<<0x40>>)

    assert {:error, :truncated_setting_value} =
             Settings.decode(Varint.encode!(Settings.h3_datagram()))
  end
end
