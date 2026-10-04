defmodule SSL.ClientHello.Serializer do
  @moduledoc """
  Encodes a fully materialized ClientHello AST as an exact handshake message.
  """

  alias SSL.ClientHello.AST

  @client_hello_type 1
  @maximum_handshake_length 0xFFFFFF

  @spec encode(AST.t()) :: {:ok, binary()} | {:error, term()}
  def encode(%AST{} = client_hello) do
    with :ok <- validate(client_hello),
         {:ok, cipher_suites} <- encode_uint16_vector(client_hello.cipher_suites),
         {:ok, compression_methods} <- encode_uint8_vector(client_hello.compression_methods),
         {:ok, extensions} <- encode_extensions(client_hello.extensions) do
      body =
        IO.iodata_to_binary([
          <<client_hello.legacy_version::16>>,
          client_hello.random,
          <<byte_size(client_hello.session_id)>>,
          client_hello.session_id,
          cipher_suites,
          compression_methods,
          extensions
        ])

      if byte_size(body) <= @maximum_handshake_length do
        {:ok, <<@client_hello_type, byte_size(body)::24, body::binary>>}
      else
        {:error, {:client_hello_length_exceeded, byte_size(body), @maximum_handshake_length}}
      end
    end
  end

  def encode(_client_hello), do: {:error, {:invalid_client_hello, :structure}}

  @spec validate(AST.t()) :: :ok | {:error, term()}
  def validate(%AST{} = client_hello) do
    with :ok <- ensure(client_hello.legacy_version == 0x0303, :legacy_version),
         :ok <-
           ensure(
             is_binary(client_hello.random) and byte_size(client_hello.random) == 32,
             :random
           ),
         :ok <-
           ensure(
             is_binary(client_hello.session_id) and byte_size(client_hello.session_id) <= 32,
             :session_id
           ),
         :ok <- ensure(valid_uint16_list?(client_hello.cipher_suites, false), :cipher_suites),
         :ok <-
           ensure(
             client_hello.compression_methods == [0],
             :compression_methods
           ),
         :ok <- ensure(valid_extensions?(client_hello.extensions), :extensions),
         :ok <- reject_duplicates(client_hello.cipher_suites, :cipher_suite),
         :ok <- reject_duplicates(Enum.map(client_hello.extensions, &elem(&1, 0)), :extension),
         :ok <- validate_pre_shared_key_position(client_hello.extensions) do
      validate_field_lengths(client_hello)
    end
  end

  def validate(_client_hello), do: {:error, {:invalid_client_hello, :structure}}

  defp ensure(true, _field), do: :ok
  defp ensure(false, field), do: {:error, {:invalid_client_hello, field}}

  defp encode_uint16_vector(values) do
    payload = IO.iodata_to_binary(Enum.map(values, &<<&1::16>>))

    if byte_size(payload) <= 0xFFFF do
      {:ok, <<byte_size(payload)::16, payload::binary>>}
    else
      {:error, {:client_hello_field_length_exceeded, :cipher_suites}}
    end
  end

  defp encode_uint8_vector(values) do
    payload = :erlang.list_to_binary(values)

    if byte_size(payload) <= 0xFF do
      {:ok, <<byte_size(payload), payload::binary>>}
    else
      {:error, {:client_hello_field_length_exceeded, :compression_methods}}
    end
  end

  defp encode_extensions(extensions) do
    payload =
      IO.iodata_to_binary(
        Enum.map(extensions, fn {extension_id, extension_payload} ->
          <<extension_id::16, byte_size(extension_payload)::16, extension_payload::binary>>
        end)
      )

    if byte_size(payload) <= 0xFFFF do
      {:ok, <<byte_size(payload)::16, payload::binary>>}
    else
      {:error, {:extensions_length_exceeded, byte_size(payload), 0xFFFF}}
    end
  end

  defp valid_uint16_list?(values, allow_empty) when is_list(values) do
    (allow_empty or values != []) and Enum.all?(values, &valid_uint16?/1)
  end

  defp valid_uint16_list?(_values, _allow_empty), do: false

  defp valid_extensions?(extensions) when is_list(extensions) do
    Enum.all?(extensions, fn
      {extension_id, payload} ->
        valid_uint16?(extension_id) and is_binary(payload) and byte_size(payload) <= 0xFFFF

      _extension ->
        false
    end)
  end

  defp valid_extensions?(_extensions), do: false

  defp validate_field_lengths(client_hello) do
    cipher_suites_length = 2 * length(client_hello.cipher_suites)
    compression_methods_length = length(client_hello.compression_methods)

    extensions_length =
      Enum.reduce(client_hello.extensions, 0, fn {_id, payload}, total ->
        total + 4 + byte_size(payload)
      end)

    cond do
      cipher_suites_length > 0xFFFF ->
        {:error, {:client_hello_field_length_exceeded, :cipher_suites}}

      compression_methods_length > 0xFF ->
        {:error, {:client_hello_field_length_exceeded, :compression_methods}}

      extensions_length > 0xFFFF ->
        {:error, {:extensions_length_exceeded, extensions_length, 0xFFFF}}

      true ->
        :ok
    end
  end

  defp reject_duplicates(values, kind) do
    case Enum.reduce_while(values, MapSet.new(), fn value, seen ->
           if MapSet.member?(seen, value) do
             {:halt, {:duplicate, value}}
           else
             {:cont, MapSet.put(seen, value)}
           end
         end) do
      %MapSet{} -> :ok
      {:duplicate, value} -> duplicate_error(kind, value)
    end
  end

  defp duplicate_error(:cipher_suite, value), do: {:error, {:duplicate_cipher_suite, value}}
  defp duplicate_error(:extension, value), do: {:error, {:duplicate_extension, value}}

  defp validate_pre_shared_key_position(extensions) do
    case Enum.find_index(extensions, &(elem(&1, 0) == 41)) do
      nil -> :ok
      index when index == length(extensions) - 1 -> :ok
      _index -> {:error, :pre_shared_key_must_be_last}
    end
  end

  defp valid_uint16?(value), do: is_integer(value) and value in 0..0xFFFF
end
