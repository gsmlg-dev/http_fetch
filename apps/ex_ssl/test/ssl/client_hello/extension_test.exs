defmodule SSL.ClientHello.ExtensionTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.ClientHello.Extension

  test "returns tagged errors for malformed typed extension values" do
    for extension <- [
          {:alpn, nil},
          {:alpn, []},
          {:alpn, [:not_binary]},
          {:supported_groups, nil},
          {:supported_groups, []},
          {:supported_groups, [0x1_0000]},
          {:ec_point_formats, []},
          {:ec_point_formats, [256]},
          {:signature_algorithms, []},
          {:signature_algorithms, [nil]},
          {:supported_versions, []},
          {:supported_versions, [nil]},
          {:psk_key_exchange_modes, []},
          {:psk_key_exchange_modes, [nil]},
          {:key_share, [{0x001D, nil}]},
          {:key_share, [{0x1_0000, <<1>>}]}
        ] do
      assert {:error, {:invalid_materialized_extension, ^extension}} = Extension.encode(extension)
    end
  end

  test "rejects one-byte vector lengths that cannot be encoded" do
    versions = {:supported_versions, List.duplicate(0x0304, 128)}
    modes = {:psk_key_exchange_modes, List.duplicate(1, 256)}

    assert {:error, {:extension_vector_length_exceeded, :supported_versions, 256, 255}} =
             Extension.encode(versions)

    assert {:error, {:extension_vector_length_exceeded, :psk_key_exchange_modes, 256, 255}} =
             Extension.encode(modes)
  end

  test "rejects ALPN identifiers whose one-byte length cannot be encoded" do
    extension = {:alpn, [:binary.copy(<<0>>, 256)]}

    assert {:error, {:invalid_materialized_extension, ^extension}} = Extension.encode(extension)
  end

  property "bounded arbitrary inputs always return the documented result shape" do
    check all(extension <- term(), max_runs: 100) do
      case Extension.encode(extension) do
        {:ok, {id, payload}}
        when is_integer(id) and id in 0..0xFFFF and is_binary(payload) ->
          assert byte_size(payload) <= 0xFFFF

        {:error, _reason} ->
          assert true

        other ->
          flunk("unexpected encode result: #{inspect(other)}")
      end
    end
  end
end
