defmodule HTTP.ManagedTransportCipherMapTest do
  use ExUnit.Case, async: true

  alias HTTP.ManagedTransport.Policy

  for backend <- [:ssl, :ex_ssl], protocol <- [:http1, :http2], tls <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{backend} #{protocol} #{tls} freezes the supported OTP cipher map" do
      tls = unquote(tls)

      cipher = %{
        key_exchange: unquote(if(tls == :"tlsv1.2", do: :ecdhe_rsa, else: :any)),
        cipher: :aes_128_gcm,
        mac: :aead,
        prf: :sha256
      }

      assert {:ok, policy} =
               freeze([versions: [tls], ciphers: [cipher]], unquote(backend), unquote(protocol))

      assert policy.transport[:ssl][:ciphers] == [cipher]
      assert policy.transport[:ssl][:versions] == [tls]
      assert policy.transport[:tls_backend] == unquote(backend)
      assert policy.transport[:http_version] == unquote(protocol)
    end
  end

  test "nested map keys and values own compact backing without changing policy identity" do
    key = String.duplicate("key", 40)
    value = String.duplicate("value", 40)
    borrowed_key = borrowed(key)
    borrowed_value = borrowed(value)
    nested = %{borrowed_key => [%{borrowed_value => {borrowed_key, borrowed_value}}]}
    compact = %{key => [%{value => {key, value}}]}

    assert {:ok, policy} = freeze(ciphers: [nested])
    assert {:ok, compact_policy} = freeze(ciphers: [compact])
    assert policy == compact_policy
    assert policy.transport[:ssl][:ciphers] == [nested]

    for binary <- binaries(policy.transport[:ssl][:ciphers]) do
      assert :binary.referenced_byte_size(binary) == byte_size(binary)
    end
  end

  test "map entry count is bounded before policy retention" do
    at_limit = Map.new(1..4_096, &{&1, :value})
    assert {:ok, _} = freeze(ciphers: [at_limit])

    assert {:error, :invalid_transport_scope_tls_policy} =
             freeze(ciphers: [Map.put(at_limit, 4_097, :value)])
  end

  test "nested maps consume the existing depth budget in keys and values" do
    assert {:ok, _} = freeze(ciphers: [nest(8, :value)])

    for map <- [nest(20, :value), %{nest(20, :key) => :value}] do
      assert {:error, :invalid_transport_scope_tls_policy} = freeze(ciphers: [map])
    end
  end

  test "map keys and values preserve binary and aggregate serialized byte bounds" do
    oversized = :binary.copy("x", 1_048_577)

    for map <- [%{key: oversized}, %{oversized => :value}] do
      assert {:error, :invalid_transport_scope_tls_policy} = freeze(ciphers: [map])
    end

    binary = :binary.copy("x", 600_000)
    assert {:ok, _} = freeze(ciphers: [%{key: binary}])

    assert {:error, :invalid_transport_scope_policy} =
             freeze(ciphers: [%{first: binary, second: binary}])
  end

  test "callable and process identity terms remain rejected as map keys and values" do
    for unsupported <- [fn -> :ok end, self(), make_ref()],
        map <- [%{unsupported => :value}, %{key: [nested: {unsupported}]}] do
      assert {:error, :invalid_transport_scope_tls_policy} = freeze(ciphers: [map])
    end
  end

  defp freeze(ssl, backend \\ :ex_ssl, protocol \\ :http1) do
    Policy.freeze(
      origin: "https://localhost",
      connect_address: {127, 0, 0, 1},
      http_version: protocol,
      tls_backend: backend,
      ssl: Keyword.put_new(ssl, :cacerts, [])
    )
  end

  defp nest(0, value), do: value
  defp nest(depth, value), do: %{nested: nest(depth - 1, value)}

  defp borrowed(value) do
    slice = binary_part(value <> :binary.copy(<<0>>, 1_048_576), 0, byte_size(value))
    assert :binary.referenced_byte_size(slice) > byte_size(slice)
    slice
  end

  defp binaries(value) when is_binary(value), do: [value]
  defp binaries(value) when is_map(value), do: value |> Map.to_list() |> binaries()
  defp binaries(value) when is_list(value), do: Enum.flat_map(value, &binaries/1)
  defp binaries(value) when is_tuple(value), do: value |> Tuple.to_list() |> binaries()
  defp binaries(_), do: []
end
