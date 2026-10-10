defmodule Quic.DatagramTest do
  use ExUnit.Case, async: true

  alias Quic.{Codec, Endpoint, Profile, TransportParameters}

  defp credentials do
    fixture = Path.expand("../fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]],
     [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}, alpn: ["h3"]]}
  end

  defp pair(server_opts, client_opts) do
    {server_tls, client_tls} = credentials()

    # Let ExUnit own endpoint shutdown instead of racing the test owner's exit.
    # Keep its acceptor identity when the public start function runs in the supervisor.
    server =
      start_supervised!(%{
        id: :server,
        start: {Quic, :listen, [[acceptor: self(), tls: server_tls] ++ server_opts]},
        restart: :temporary
      })

    client =
      start_supervised!(%{
        id: :client,
        start: {Quic, :client, [[acceptor: self(), tls: client_tls] ++ client_opts]},
        restart: :temporary
      })

    {:ok, outgoing} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(outgoing, self())
    assert_receive {:quic_ready, ^outgoing, _}, 2_000
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, incoming} = Quic.accept(server)
    :ok = Quic.attach(incoming, self())
    assert_receive {:quic_ready, ^incoming, _}, 2_000
    {outgoing, incoming}
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(_fun, 0), do: flunk("condition did not become true")

  defp eventually(fun, attempts) do
    if fun.(),
      do: :ok,
      else:
        (
          Process.sleep(10)
          eventually(fun, attempts - 1)
        )
  end

  test "profile ALPN policy is configurable without changing the default" do
    assert {:ok, default} = Profile.compile(:ordered)
    assert {:alpn, ["ex-quic"]} in default.tls.extensions
    assert {:ok, profile} = Profile.compile(:ordered, alpn: ["h3"])
    assert {:alpn, ["h3"]} in profile.tls.extensions
    assert {:error, {:invalid_profile, :alpn}} = Profile.compile(:ordered, alpn: [""])
  end

  test "RFC 9221 parameter and both DATAGRAM wire forms are bounded" do
    assert {:ok, parameter} = Codec.encode_varint(1200)
    assert {:ok, wire} = TransportParameters.encode([%{id: 0x20, value: parameter}])
    assert {:ok, %{values: %{max_datagram_frame_size: 1200}}} = TransportParameters.decode(wire)
    assert {:error, :invalid_parameter_value} = TransportParameters.decode(<<0x20, 2, 1, 2>>)

    assert {:ok, <<0x31, 3, "abc">>} = Codec.encode_frames([%{type: :datagram, data: "abc"}])

    assert {:ok, [%{type: :datagram, data: "abc", wire_size: 5}], <<>>} =
             Codec.decode_frames(<<0x31, 3, "abc">>)

    assert {:ok, [%{type: :datagram, data: "abc", wire_size: 4}], <<>>} =
             Codec.decode_frames(<<0x30, "abc">>)

    # Nonminimal type and length varints are legal; their actual wire bytes count.
    assert {:ok, [%{type: :datagram, data: "abc", wire_size: 7}], <<>>} =
             Codec.decode_frames(<<0x40, 0x31, 0x40, 3, "abc">>)

    assert {:error, :malformed_datagram_frame} = Codec.decode_frames(<<0x31, 4, "abc">>)

    assert {:wrong_encryption_level, :datagram, :handshake} =
             Codec.validate_frame_levels([%{type: :datagram, data: "x"}], :handshake)
  end

  test "negotiated DATAGRAMs preserve duplicate payloads and bounded pull delivery" do
    opts = [datagram: [max_frame_size: 1200, max_items: 2, max_buffer_bytes: 8]]
    {outgoing, incoming} = pair(opts, opts)
    assert Quic.capabilities().datagram
    refute Quic.capabilities().http3
    assert {:ok, %{alpn: "h3", datagram: %{send_max_bytes: 1197}}} = Quic.info(outgoing)
    ref = make_ref()
    assert {:ok, ^ref} = Quic.send_datagram(outgoing, "same", ref: ref)
    assert {:ok, ^ref} = Quic.send_datagram(outgoing, "same", ref: ref)
    assert {:error, :operation_ref_conflict} = Quic.send_datagram(outgoing, "other", ref: ref)
    assert {:ok, _} = Quic.send_datagram(outgoing, "same")

    eventually(fn ->
      {:ok, info} = Quic.info(incoming)
      info.resources.datagram_ready_items == 2
    end)

    assert {:ok, events} = Quic.events(incoming)
    assert :datagram_readable in events

    assert {:error, :not_consumer} =
             Task.async(fn -> Quic.read_datagrams(incoming) end) |> Task.await()

    assert {:ok, ["same"]} = Quic.read_datagrams(incoming, 1)
    assert {:ok, events} = Quic.events(incoming)
    assert :datagram_readable in events
    assert {:ok, ["same"]} = Quic.read_datagrams(incoming, 1)
    assert {:ok, []} = Quic.read_datagrams(incoming)
    assert {:error, :stale_handle} = Quic.read_datagrams(%{incoming | generation: make_ref()})
    assert {:error, :datagram_too_large} = Quic.send_datagram(outgoing, :binary.copy("a", 1198))
  end

  test "DATAGRAM send reports unsupported when the peer does not advertise it" do
    {outgoing, incoming} = pair([], datagram: [max_frame_size: 1200])
    assert {:ok, %{datagram: %{send_max_bytes: 0, receive_max_bytes: 1197}}} = Quic.info(outgoing)
    assert {:error, :datagram_unsupported} = Quic.send_datagram(outgoing, "x")
    assert {:error, :datagram_unsupported} = Quic.read_datagrams(incoming)
    assert {:ok, _} = Quic.send_datagram(incoming, "one-way")

    eventually(fn ->
      {:ok, info} = Quic.info(outgoing)
      info.resources.datagram_ready_items == 1
    end)

    assert {:ok, ["one-way"]} = Quic.read_datagrams(outgoing)
  end

  test "receive overflow drops whole DATAGRAMs and retains exact admitted bytes" do
    opts = [datagram: [max_frame_size: 1200, max_items: 1, max_buffer_bytes: 4]]
    {outgoing, incoming} = pair(opts, opts)
    assert {:ok, _} = Quic.send_datagram(outgoing, "abcd")
    assert {:ok, _} = Quic.send_datagram(outgoing, "efgh")

    eventually(fn ->
      {:ok, info} = Quic.info(incoming)
      info.resources.datagram_drops == 1
    end)

    assert {:ok, ["abcd"]} = Quic.read_datagrams(incoming)

    assert {:ok, %{resources: %{datagram_ready_bytes: 0, datagram_drops: 1}}} =
             Quic.info(incoming)
  end
end
