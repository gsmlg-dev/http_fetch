defmodule SSL.Protocol.InnerPlaintextTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.InnerPlaintext

  test "encodes content, inner type, and zero padding exactly" do
    assert {:ok, <<"hello", 22, 0, 0, 0>>} =
             InnerPlaintext.encode("hello", :handshake, 3)
  end

  test "decodes the final nonzero type and preserves content ending in zeros" do
    assert {:ok, :application_data, <<1, 0, 0>>, 4} =
             InnerPlaintext.decode(<<1, 0, 0, 23, 0, 0, 0, 0>>)
  end

  test "supports handshake, alert, and application data types" do
    for type <- [:handshake, :alert, :application_data] do
      assert {:ok, encoded} = InnerPlaintext.encode("content", type, 2)
      assert {:ok, ^type, "content", 2} = InnerPlaintext.decode(encoded)
    end
  end

  test "enforces the 16,385-byte TLSInnerPlaintext boundary" do
    maximum_content = :binary.copy(<<1>>, 16_384)

    assert {:ok, maximum} = InnerPlaintext.encode(maximum_content, :handshake, 0)
    assert byte_size(maximum) == 16_385

    assert {:error, {:padding_length_exceeded, 1, 0}} =
             InnerPlaintext.encode(maximum_content, :handshake, 1)

    assert {:error, {:inner_plaintext_length_exceeded, 16_386, 16_385}} =
             InnerPlaintext.decode(maximum <> <<0>>)
  end

  test "rejects empty handshake and alert content but permits empty application data" do
    for type <- [:handshake, :alert] do
      assert {:error, {:empty_content, ^type}} = InnerPlaintext.encode(<<>>, type, 0)
      assert {:error, {:empty_content, ^type}} = InnerPlaintext.encode(<<>>, type, 1)
      assert {:error, {:empty_content, ^type}} = InnerPlaintext.decode(<<type_code(type)>>)
      assert {:error, {:empty_content, ^type}} = InnerPlaintext.decode(<<type_code(type), 0>>)
    end

    assert {:ok, <<23>>} = InnerPlaintext.encode(<<>>, :application_data, 0)
    assert {:ok, :application_data, <<>>, 0} = InnerPlaintext.decode(<<23>>)
    assert {:ok, :application_data, <<>>, 1} = InnerPlaintext.decode(<<23, 0>>)
  end

  test "permits boundary-sized padding only when total encoded length fits" do
    assert {:ok, encoded} = InnerPlaintext.encode(<<1>>, :handshake, 16_383)
    assert byte_size(encoded) == 16_385

    assert {:error, {:padding_length_exceeded, 16_384, 16_383}} =
             InnerPlaintext.encode(<<1>>, :handshake, 16_384)
  end

  test "rejects empty, all-zero, and unsupported inner plaintext" do
    assert {:error, :empty_inner_plaintext} = InnerPlaintext.decode(<<>>)
    assert {:error, :missing_inner_content_type} = InnerPlaintext.decode(<<0, 0, 0>>)

    assert {:error, {:unsupported_inner_content_type, 24}} =
             InnerPlaintext.decode(<<1, 24, 0>>)

    assert {:error, {:unsupported_inner_content_type, :change_cipher_spec}} =
             InnerPlaintext.encode(<<>>, :change_cipher_spec, 0)
  end

  test "enforces content, padding, and total inner plaintext bounds" do
    assert {:error, {:invalid_content, :not_binary}} =
             InnerPlaintext.encode(nil, :handshake, 0)

    assert {:error, {:content_length_exceeded, 16_385, 16_384}} =
             InnerPlaintext.encode(:binary.copy(<<0>>, 16_385), :handshake, 0)

    assert {:error, {:invalid_padding_length, -1}} =
             InnerPlaintext.encode("content", :handshake, -1)

    assert {:error, {:padding_length_exceeded, 16_385, 16_384}} =
             InnerPlaintext.encode(<<>>, :application_data, 16_385)

    assert {:ok, maximum} = InnerPlaintext.encode(<<>>, :application_data, 16_384)
    assert byte_size(maximum) == 16_385

    maximum_content = :binary.copy(<<1>>, 16_384)

    assert {:error, {:padding_length_exceeded, 1, 0}} =
             InnerPlaintext.encode(maximum_content, :handshake, 1)

    oversized_content = <<0::size(16_385 * 8), 22>>

    assert {:error, {:inner_plaintext_length_exceeded, 16_386, 16_385}} =
             InnerPlaintext.decode(oversized_content)

    assert {:error, {:inner_plaintext_length_exceeded, 16_386, 16_385}} =
             InnerPlaintext.decode(:binary.copy(<<0>>, 16_386))

    assert {:error, {:invalid_inner_plaintext, :not_binary}} = InnerPlaintext.decode(nil)
  end

  property "bounded content and padding round trip" do
    check all(
            content <- binary(min_length: 1, max_length: 128),
            type <- member_of([:handshake, :alert, :application_data]),
            padding_length <- integer(0..64),
            max_runs: 100
          ) do
      assert {:ok, encoded} = InnerPlaintext.encode(content, type, padding_length)
      assert {:ok, ^type, ^content, ^padding_length} = InnerPlaintext.decode(encoded)
    end
  end

  property "bounded arbitrary plaintext always returns a tagged result" do
    check all(plaintext <- binary(max_length: 17_000), max_runs: 100) do
      assert match?({:ok, _type, _content, _padding}, InnerPlaintext.decode(plaintext)) or
               match?({:error, _reason}, InnerPlaintext.decode(plaintext))
    end
  end

  test "rejects improper term inputs without raising" do
    assert {:error, {:invalid_inner_plaintext, :not_binary}} =
             InnerPlaintext.decode([<<22>> | :not_a_list])

    assert {:error, {:invalid_content, :not_binary}} =
             InnerPlaintext.encode([<<1>> | :not_a_list], :handshake)
  end

  defp type_code(:alert), do: 21
  defp type_code(:handshake), do: 22
end
