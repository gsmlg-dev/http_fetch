defmodule Quic.ResumptionRuntimeTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  defp now, do: System.monotonic_time(:millisecond)

  defp await(fun, deadline) do
    case fun.() do
      value when value in [false, nil] ->
        assert now() < deadline, "runtime resumption deadline"

        receive do
          {:quic_closed, _, reason}
          when reason not in [:peer_closed, :closed] and not is_tuple(reason) ->
            flunk("closed #{inspect(reason)}")
        after
          5 -> await(fun, deadline)
        end

      value ->
        value
    end
  end

  defp cert_options do
    dir = Path.expand("../fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(dir, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(dir, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["r1-runtime"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["r1-runtime"]
     ]}
  end

  test "endpoint-local tickets resume a fresh connection without early application data" do
    {server_tls, client_tls} = cert_options()
    policy = [enabled: true, application_profile: "raw-r1-v1"]

    {:ok, server} =
      Quic.listen(tls: server_tls, resumption: policy, closing_timeout: 10, draining_timeout: 10)

    {:ok, _, lease} = Quic.Cleanup.new()

    {:ok, client} =
      Quic.client(
        cleanup: lease,
        tls: client_tls,
        resumption: policy,
        closing_timeout: 10,
        draining_timeout: 10
      )

    on_exit(fn ->
      Quic.Cleanup.retire(lease, {:abs_ms, now() + 5000})
      Quic.TestStop.quietly(server)
    end)

    for index <- 0..1 do
      {:ok, connection} = Quic.connect(client, Quic.local(server))
      :ok = Quic.attach(connection, self())
      await(fn -> Quic.ready(connection) == :ready end, now() + 5000)

      peer =
        await(
          fn ->
            case Quic.accept(server) do
              {:ok, connection} -> connection
              {:error, :would_block} -> false
            end
          end,
          now() + 5000
        )

      :ok = Quic.attach(peer, self())

      for handle <- [connection, peer] do
        assert {:ok, %{resumption: %{resumed: resumed, early_data: :disabled}}} =
                 Quic.info(handle)

        assert resumed == (index == 1)
      end

      {:ok, stream} = Quic.open_stream(connection, :bidi)
      {:ok, _} = Quic.send_stream(stream, "message/#{index}", true)

      peer_stream =
        await(
          fn ->
            {:ok, events} = Quic.events(peer)

            Enum.find_value(events, fn
              {:stream_open, handle, :bidi} -> handle
              _ -> false
            end)
          end,
          now() + 5000
        )

      items =
        await(
          fn ->
            {:ok, items} = Quic.read(peer_stream, 16_384)
            if items == [], do: false, else: items
          end,
          now() + 5000
        )

      assert items == [{:data, stream.id, "message/#{index}"}, {:fin, stream.id}]
      await(fn -> Quic.Endpoint.stats(client).resumption.tickets > 0 end, now() + 2000)
      assert :ok = Quic.close(connection)
      await(fn -> Quic.Endpoint.connections(client) == [] end, now() + 2000)
    end
  end

  test "early packets precede readiness and rejection keeps refs but invalidates stream epochs" do
    {server_tls, client_tls} = cert_options()
    policy = [enabled: true, application_profile: "raw-r2-v1"]
    early = [enabled: true, application_profile: "early-raw-v1"]

    {:ok, server} =
      Quic.listen(
        tls: server_tls,
        resumption: policy,
        early_data: early,
        datagram: [max_frame_size: 1200],
        closing_timeout: 10,
        draining_timeout: 10
      )

    {:ok, _, lease} = Quic.Cleanup.new()

    {:ok, client} =
      Quic.client(
        cleanup: lease,
        tls: client_tls,
        resumption: policy,
        early_data: early,
        datagram: [max_frame_size: 1200],
        closing_timeout: 10,
        draining_timeout: 10
      )

    on_exit(fn ->
      if Process.alive?(server) do
        :sys.resume(server)
        GenServer.stop(server)
      end

      Quic.Cleanup.retire(lease, {:abs_ms, now() + 5000})
    end)

    {:ok, initial} = Quic.connect(client, Quic.local(server))
    await(fn -> Quic.ready(initial) == :ready end, now() + 5000)
    await(fn -> Quic.Endpoint.stats(client).resumption.tickets > 0 end, now() + 2000)
    :ok = Quic.close(initial)
    await(fn -> Quic.Endpoint.connections(client) == [] end, now() + 2000)

    for rejection <- [false, true] do
      # Suspend the protocol owner as a deterministic traffic barrier: the client
      # emits early ciphertext before the server can process ClientHello.
      if rejection do
        :sys.replace_state(server, &%{&1 | early_policy: nil})
      end

      remote = Quic.local(server)
      :ok = :sys.suspend(server)
      {:ok, connection} = Quic.connect(client, remote)
      :ok = Quic.attach(connection, self())
      assert Quic.ready(connection) == :pending
      assert {:error, :not_established} = Quic.open_stream(connection, :bidi)
      {:ok, stream} = Quic.open_stream(connection, :bidi, early_data: :replayable)
      ref = make_ref()

      {:ok, ^ref} =
        Quic.send_stream(stream, "early-payload", true, early_data: :replayable, ref: ref)

      {:ok, _} = Quic.send_datagram(connection, "early-message", early_data: :replayable)
      {_, state} = :sys.get_state(connection.id)

      assert Enum.count(state.scheduler.recovery.spaces.application.sent, fn {_, packet} ->
               packet.metadata.level == :early_data
             end) == 2

      assert Quic.ready(connection) == :pending
      :ok = :sys.resume(server)
      await(fn -> Quic.ready(connection) == :ready end, now() + 5000)
      status = if rejection, do: :rejected, else: :accepted
      assert %{outcome: {:early_data, ^status}} = Quic.operation_status(connection, ref)

      assert {:ok, ^ref} =
               Quic.send_stream(stream, "early-payload", true, early_data: :replayable, ref: ref)

      peer =
        await(
          fn ->
            Enum.find_value(Quic.Endpoint.connections(server), fn %{
                                                                    pid: pid,
                                                                    generation: generation
                                                                  } ->
              handle = %Quic.Runtime.ConnectionHandle{id: pid, generation: generation}

              case Quic.info(handle) do
                {:ok, %{resumption: %{resumed: true}}} -> handle
                {:ok, _} when rejection -> handle
                _ -> false
              end
            end)
          end,
          now() + 5000
        )

      :ok = Quic.attach(peer, self())
      {:ok, events} = Quic.events(peer)

      if rejection do
        refute Enum.any?(events, &match?({:stream_open, _, _}, &1))
        assert {:ok, []} = Quic.read_datagrams(peer)
        assert {:error, :stale_stream_epoch} = Quic.send_stream(stream, "stale")
        {:ok, replacement} = Quic.open_stream(connection, :bidi)
        assert replacement.id == stream.id
        assert replacement.epoch > stream.epoch
        {:ok, _} = Quic.send_stream(replacement, "explicit-new", true)
      else
        assert [{:stream_open, peer_stream, :bidi}] =
                 Enum.filter(events, &match?({:stream_open, _, _}, &1))

        assert {:ok, [{:data, 0, "early-payload"}, {:fin, 0}]} = Quic.read(peer_stream, 16_384)
        assert {:ok, ["early-message"]} = Quic.read_datagrams(peer)
      end

      await(fn -> Quic.Endpoint.stats(client).resumption.tickets > 0 end, now() + 2000)
      :ok = Quic.close(connection)
      await(fn -> Quic.Endpoint.connections(client) == [] end, now() + 2000)
      await(fn -> Quic.Endpoint.connections(server) == [] end, now() + 2000)
    end
  end
end
