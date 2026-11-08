defmodule Quic.UncleanedMigrationIntegrationTest do
  # A standalone client endpoint created without a `cleanup:` scope must be
  # able to bind its migration socket the same way it bound its first socket.
  use ExUnit.Case, async: true
  @moduletag :integration
  alias Quic.Endpoint

  defp credentials do
    fixture = Path.expand("../fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-migrate"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-migrate"]
     ]}
  end

  test "client without a cleanup scope migrates to a new local port" do
    {server_tls, client_tls} = credentials()
    {:ok, server} = Quic.listen(tls: server_tls)
    {:ok, client} = Quic.client(tls: client_tls)

    on_exit(fn ->
      for endpoint <- [server, client], Process.alive?(endpoint) do
        try do
          GenServer.stop(endpoint)
        catch
          :exit, _ -> :ok
        end
      end
    end)

    {:ok, connection} = Quic.connect(client, Endpoint.local(server))
    :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2_000
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())

    ref = admit_migration(connection)

    assert {:ok, {{127, 0, 0, 1}, port}} = await_migration(connection, ref)
    assert is_integer(port) and port > 0

    {:ok, stream} = Quic.open_stream(connection, :bidi)
    {:ok, _} = Quic.send_stream(stream, "after-migration", true)
    assert await_data(accepted) == "after-migration"
  end

  # The peer issues spare connection IDs shortly after the handshake.
  defp admit_migration(connection, deadline \\ now() + 5_000) do
    assert now() < deadline
    ref = make_ref()
    bound = {:abs_ms, now() + 5_000}

    case Quic.migrate(connection, local: {{127, 0, 0, 1}, 0}, ref: ref, deadline: bound) do
      {:ok, ^ref} ->
        ref

      {:error, :no_unused_connection_id} ->
        Process.sleep(10)
        admit_migration(connection, deadline)
    end
  end

  defp await_migration(connection, ref, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, events} = Quic.events(connection, 32)

    case Enum.find(events, &match?({:migration, ^ref, _}, &1)) do
      {:migration, ^ref, outcome} ->
        outcome

      nil ->
        Process.sleep(5)
        await_migration(connection, ref, deadline)
    end
  end

  defp await_data(accepted, acc \\ <<>>, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, events} = Quic.events(accepted, 32)

    acc =
      Enum.reduce(events, acc, fn
        {:stream_open, stream, :bidi}, acc -> acc <> read_all(stream)
        _, acc -> acc
      end)

    if String.ends_with?(acc, "after-migration"),
      do: acc,
      else:
        (
          Process.sleep(5)
          await_data(accepted, acc, deadline)
        )
  end

  defp read_all(stream, acc \\ <<>>, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc <> for({:data, _, bytes} <- items, into: <<>>, do: bytes)

    if Enum.any?(items, &match?({:fin, _}, &1)),
      do: acc,
      else:
        (
          Process.sleep(5)
          read_all(stream, acc, deadline)
        )
  end

  defp now, do: System.monotonic_time(:millisecond)
end
