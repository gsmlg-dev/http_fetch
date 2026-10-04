fixture = Path.expand("../../apps/elixir_quic/test/fixtures/tls", __DIR__)

der = fn name ->
  [{:Certificate, bytes, :not_encrypted}] =
    :public_key.pem_decode(File.read!(Path.join(fixture, name)))

  bytes
end

[{key_type, key, :not_encrypted}] =
  :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

tls = [cert: [der.("leaf.pem")], key: {key_type, key}, alpn: ["ex-quic-test"]]
{:ok, endpoint} = Quic.Endpoint.start_link(role: :server, tls: tls)
{{127, 0, 0, 1}, port} = Quic.Endpoint.local(endpoint)
{:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])

dcid = :binary.copy(<<1>>, 8)
scid = :binary.copy(<<2>>, 8)

initial = fn first ->
  payload = :binary.copy(<<0>>, 1_025)
  {:ok, length} = Quic.Codec.encode_varint(byte_size(payload) + 1)
  <<first, 0, 0, 0, 1, 8, dcid::binary, 8, scid::binary, 0, length::binary, 0, payload::binary>>
end

truncated = <<0xC0, 0, 0, 0, 1, 8, dcid::binary, 8, scid::binary>>
packets = [{:reserved_bits, initial.(0xD0)}, {:fixed_bit, initial.(0x80)}, {:truncated, truncated}]

Enum.each(packets, fn {_name, bytes} ->
  :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, bytes)
end)

responses =
  Enum.reduce(packets, [], fn {name, _bytes}, acc ->
    case :gen_udp.recv(socket, 65_535, 250) do
      {:ok, {_ip, _port, response}} -> [{name, byte_size(response)} | acc]
      {:error, :timeout} -> acc
    end
  end)

result = %{responses: Enum.reverse(responses), stats: Quic.Endpoint.stats(endpoint)}
IO.inspect(result, label: "RAW_NEGATIVE_RESULT")
:gen_udp.close(socket)
GenServer.stop(endpoint)

if result.responses == [] and result.stats.routes == 0, do: :ok, else: System.halt(1)
