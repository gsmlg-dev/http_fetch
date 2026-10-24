defmodule Quic.IdleTimeoutPublicTest do
  use ExUnit.Case, async: true
  alias Quic.{Codec, TransportParameters}

  defp credentials do
    fixture = Path.expand("../fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["idle-test"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["idle-test"]
     ]}
  end

  defp stop(endpoint) do
    if Process.alive?(endpoint), do: GenServer.stop(endpoint)
  catch
    :exit, {:noproc, _} -> :ok
  end

  defp connect(server_opts, client_opts) do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen([tls: server_tls] ++ server_opts)
    {:ok, client} = Quic.client([tls: client_tls] ++ client_opts)
    on_exit(fn -> Enum.each([client, server], &stop/1) end)
    {:ok, connection} = Quic.connect(client, Quic.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, client_info}, 2_000
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    {:ok, server_info} = Quic.info(accepted)
    {connection, accepted, client_info, server_info}
  end

  test "actual TLS transport parameters negotiate finite and disabled endpoint policies" do
    for {server_timeout, client_timeout, negotiated} <- [
          {:infinity, :infinity, :infinity},
          {:infinity, 20_000, 20_000},
          {15_000, :infinity, 15_000},
          {20_000, 15_000, 15_000}
        ] do
      {_, _, client, server} =
        connect([idle_timeout: server_timeout], idle_timeout: client_timeout)

      assert client.idle_timeout.local_ms == client_timeout
      assert client.idle_timeout.peer_ms == server_timeout
      assert server.idle_timeout.local_ms == server_timeout
      assert server.idle_timeout.peer_ms == client_timeout
      assert client.idle_timeout.negotiated_ms == negotiated
      assert server.idle_timeout.negotiated_ms == negotiated
      assert client.idle_timeout.effective_ms == negotiated
    end
  end

  test "default finite idle policy and profile-generated parameters remain aligned" do
    {:ok, profile} = Quic.Profile.compile(:ordered, alpn: ["idle-test"])
    {connection, accepted, client, server} = connect([], profile: profile)
    assert client.idle_timeout.local_ms == 30_000
    assert client.idle_timeout.peer_ms == 30_000
    assert server.idle_timeout.local_ms == 30_000
    assert server.idle_timeout.peer_ms == 30_000
    ref = make_ref()
    assert {:ok, ^ref} = Quic.ping(connection, ref: ref)
    assert {:ok, ^ref} = Quic.ping(connection, ref: ref)
    assert %{status: :admitted, result: {:ok, ^ref}} = Quic.operation_status(connection, ref)
    assert {:ok, _} = Quic.ping(accepted)
    assert {:error, :stale_handle} = Quic.ping(%{connection | generation: make_ref()})
    assert :ok = Quic.close(connection)
    assert {:error, :not_established} = Quic.ping(connection)
  end

  test "explicit raw transport policy conflicts are rejected, missing CIDs remain invalid" do
    {:ok, wire} = Codec.encode_varint(10_000)
    {:ok, raw} = TransportParameters.encode([%{id: 1, value: wire}])
    {:ok, profile} = Quic.Profile.compile(:ordered)

    {:ok, mismatch} =
      Quic.client(tls: [transport_parameters: raw], profile: profile, idle_timeout: :infinity)

    {:ok, missing_cid} = Quic.client(tls: [transport_parameters: raw])
    on_exit(fn -> Enum.each([mismatch, missing_cid], &stop/1) end)
    remote = {{127, 0, 0, 1}, 443}

    assert {:error, :idle_timeout_transport_parameter_mismatch} = Quic.connect(mismatch, remote)
    assert {:error, :missing_initial_source_connection_id} = Quic.connect(missing_cid, remote)
  end
end
