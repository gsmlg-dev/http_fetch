defmodule SSL.ClientHello.SerializerTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.{AST, Serializer}

  test "rejects protocol-invalid legacy version without raising" do
    client_hello = ast(legacy_version: 0x0304)

    assert {:error, {:invalid_client_hello, :legacy_version}} =
             Serializer.validate(client_hello)

    assert {:error, {:invalid_client_hello, :legacy_version}} =
             Serializer.encode(client_hello)
  end

  test "rejects protocol-invalid compression methods without raising" do
    for methods <- [[], [1], [0, 1]] do
      client_hello = ast(compression_methods: methods)

      assert {:error, {:invalid_client_hello, :compression_methods}} =
               Serializer.validate(client_hello)

      assert {:error, {:invalid_client_hello, :compression_methods}} =
               Serializer.encode(client_hello)
    end
  end

  test "rejects duplicate cipher suites without raising" do
    client_hello = ast(cipher_suites: [0x1301, 0x1301])

    assert {:error, {:duplicate_cipher_suite, 0x1301}} = Serializer.validate(client_hello)
    assert {:error, {:duplicate_cipher_suite, 0x1301}} = Serializer.encode(client_hello)
  end

  test "rejects duplicate extensions without raising" do
    client_hello = ast(extensions: [{16, <<>>}, {16, <<>>}])

    assert {:error, {:duplicate_extension, 16}} = Serializer.validate(client_hello)
    assert {:error, {:duplicate_extension, 16}} = Serializer.encode(client_hello)
  end

  test "requires pre_shared_key to be the final extension without raising" do
    client_hello = ast(extensions: [{41, <<0>>}, {43, <<2, 3, 4>>}])

    assert {:error, :pre_shared_key_must_be_last} = Serializer.validate(client_hello)
    assert {:error, :pre_shared_key_must_be_last} = Serializer.encode(client_hello)
  end

  defp ast(overrides) do
    struct!(
      AST,
      Keyword.merge(
        [
          legacy_version: 0x0303,
          random: :binary.copy(<<0>>, 32),
          session_id: <<>>,
          cipher_suites: [0x1301],
          compression_methods: [0],
          extensions: []
        ],
        overrides
      )
    )
  end
end
