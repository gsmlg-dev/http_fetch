defmodule SSL.Fingerprint do
  @moduledoc """
  JA3 and JA4 observation of exact, naked ClientHello handshake bytes.

  Transport is explicitly `:tcp` or `:quic`; it is never inferred from ALPN.
  Unknown IDs and original ordering are retained in `observation`. Only the
  analytical projections omit GREASE and sort JA4 fields. Observation does not
  validate a profile's negotiability or authenticate a peer. ECH bytes, if
  present, describe the visible outer hello only, never an encrypted inner hello.

  `new/1` and `feed/2` observe one fragmented ClientHello, bounded to 65,535
  body bytes. Completion emits one result; trailing input is rejected. Empty
  input and terminal empty feeds emit nothing. Errors discard the observer;
  start a new observer for another ClientHello.
  """
  alias SSL.Protocol.{ClientOffer, HandshakeFramer}
  @opaque t :: %__MODULE__{transport: :tcp | :quic, buffer: HandshakeFramer.t(), done: boolean()}
  defstruct [:transport, :buffer, done: false]

  @type result :: %{
          transport: :tcp | :quic,
          source: :visible_client_hello,
          observation: map(),
          ja3: %{raw: binary(), hash: binary()},
          ja4: %{
            prefix: binary(),
            cipher_raw: binary(),
            extension_raw: binary(),
            raw: binary(),
            hash: binary()
          }
        }

  @spec new(:tcp | :quic) :: {:ok, t()} | {:error, :invalid_transport}
  def new(transport) when transport in [:tcp, :quic],
    do: {:ok, %__MODULE__{transport: transport, buffer: HandshakeFramer.new()}}

  def new(_), do: {:error, :invalid_transport}

  @spec feed(t(), binary()) :: {:ok, t(), [result()]} | {:error, term()}
  def feed(%__MODULE__{} = state, <<>>), do: {:ok, state, []}
  def feed(%__MODULE__{done: true}, _), do: {:error, :observer_complete}

  def feed(%__MODULE__{} = state, bytes) when is_binary(bytes) do
    if HandshakeFramer.buffered_size(state.buffer) + byte_size(bytes) > 65_539 do
      {:error, :client_hello_too_large}
    else
      case HandshakeFramer.feed(state.buffer, bytes, max_handshake_length: 65_535) do
        {:ok, [], buffer} ->
          {:ok, %{state | buffer: buffer}, []}

        {:ok, [message], buffer} ->
          with true <- HandshakeFramer.buffered_size(buffer) == 0,
               {:ok, result} <- client_hello(message, state.transport) do
            {:ok, %{state | buffer: HandshakeFramer.new(), done: true}, [result]}
          else
            false -> {:error, :trailing_data}
            error -> error
          end

        {:ok, _, _} ->
          {:error, :trailing_data}

        {:error, {:handshake_length_exceeded, _, _}} ->
          {:error, :client_hello_too_large}

        error ->
          error
      end
    end
  end

  def feed(_, _), do: {:error, :invalid_input}

  @spec client_hello(binary(), :tcp | :quic) :: {:ok, result()} | {:error, term()}
  def client_hello(bytes, transport) when transport in [:tcp, :quic] do
    with {:ok, observed} <- ClientOffer.observe(bytes),
         {:ok, fields} <- fields(observed.extensions) do
      ciphers = clean(observed.cipher_suites)
      extensions = clean(observed.extension_ids)
      groups = clean(fields.groups)
      sigs = clean(fields.signatures)

      ja3 =
        Enum.join(
          [
            observed.legacy_version,
            decimal(ciphers),
            decimal(extensions),
            decimal(groups),
            decimal(fields.points)
          ],
          ","
        )

      versions = clean(fields.versions)
      version = if versions == [], do: observed.legacy_version, else: Enum.max(versions)

      prefix =
        if(transport == :quic, do: "q", else: "t") <>
          version_tag(version) <>
          if(0 in extensions, do: "d", else: "i") <>
          count(ciphers) <> count(extensions) <> alpn_tag(fields.alpn)

      cipher_raw = hex_list(Enum.sort(ciphers))
      extension_ids = extensions |> Enum.reject(&(&1 in [0, 16])) |> Enum.sort()

      extension_raw =
        hex_list(extension_ids) <> if sigs == [], do: "", else: "_" <> hex_list(sigs)

      raw = prefix <> "_" <> cipher_raw <> "_" <> extension_raw

      hash =
        prefix <>
          "_" <>
          short_hash(cipher_raw, ciphers) <> "_" <> short_hash(extension_raw, extension_ids)

      {:ok,
       %{
         transport: transport,
         source: :visible_client_hello,
         observation: observed,
         ja3: %{raw: ja3, hash: digest(:md5, ja3)},
         ja4: %{
           prefix: prefix,
           cipher_raw: cipher_raw,
           extension_raw: extension_raw,
           raw: raw,
           hash: hash
         }
       }}
    end
  end

  def client_hello(_, _), do: {:error, :invalid_transport}

  defp fields(extensions) do
    Enum.reduce_while(
      extensions,
      {:ok, %{groups: [], points: [], signatures: [], versions: [], alpn: <<>>}},
      fn ext, {:ok, acc} ->
        case field(ext, acc) do
          {:ok, acc} -> {:cont, {:ok, acc}}
          error -> {:halt, error}
        end
      end
    )
  end

  defp field({id, <<length::16, bytes::binary-size(length)>>}, acc)
       when id in [10, 13] and rem(length, 2) == 0 do
    key = if id == 10, do: :groups, else: :signatures
    {:ok, Map.put(acc, key, for(<<id::16 <- bytes>>, do: id))}
  end

  defp field({43, <<length, bytes::binary-size(length)>>}, acc) when rem(length, 2) == 0,
    do: {:ok, %{acc | versions: for(<<id::16 <- bytes>>, do: id)}}

  defp field({11, <<length, bytes::binary-size(length)>>}, acc),
    do: {:ok, %{acc | points: :binary.bin_to_list(bytes)}}

  defp field({16, <<length::16, bytes::binary-size(length)>>}, acc) do
    with {:ok, protocols} <- alpn(bytes, []) do
      {:ok, %{acc | alpn: List.first(protocols) || <<>>}}
    end
  end

  defp field({id, _}, _) when id in [10, 11, 13, 16, 43], do: {:error, {:malformed_extension, id}}
  defp field(_, acc), do: {:ok, acc}
  defp alpn(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp alpn(<<length, value::binary-size(length), rest::binary>>, acc),
    do: alpn(rest, [value | acc])

  defp alpn(_, _), do: {:error, {:malformed_extension, 16}}

  defp clean(ids),
    do: Enum.reject(ids, &(Bitwise.band(&1, 0x0F0F) == 0x0A0A and div(&1, 256) == rem(&1, 256)))

  defp decimal(ids), do: Enum.join(ids, "-")

  defp hex_list(ids),
    do:
      Enum.map_join(
        ids,
        ",",
        &(&1 |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0"))
      )

  defp count(ids),
    do: ids |> length() |> min(99) |> Integer.to_string() |> String.pad_leading(2, "0")

  defp digest(algorithm, bytes), do: :crypto.hash(algorithm, bytes) |> Base.encode16(case: :lower)
  defp short_hash(_, []), do: "000000000000"
  defp short_hash(bytes, _), do: binary_part(digest(:sha256, bytes), 0, 12)

  defp version_tag(version),
    do:
      Map.get(
        %{
          0x0304 => "13",
          0x0303 => "12",
          0x0302 => "11",
          0x0301 => "10",
          0x0300 => "s3",
          0x0002 => "s2"
        },
        version,
        "00"
      )

  defp alpn_tag(<<>>), do: "00"

  defp alpn_tag(bytes) do
    first = :binary.first(bytes)
    last = :binary.last(bytes)

    if alphanumeric?(first) and alphanumeric?(last),
      do: <<first, last>>,
      else: alpn_hex(bytes)
  end

  defp alpn_hex(bytes) do
    hex = Base.encode16(bytes, case: :lower)
    <<:binary.first(hex), :binary.last(hex)>>
  end

  defp alphanumeric?(byte), do: byte in ?0..?9 or byte in ?a..?z or byte in ?A..?Z
end
