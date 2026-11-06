defmodule Abyss.NativeTruncationDropTestHandler do
  @behaviour Abyss.DatagramHandler
  def init(options, _context), do: {:ok, options[:owner]}

  def handle_datagram(datagram, owner) do
    send(owner, {:native_truncation_callback, datagram})
    {:ok, owner, []}
  end
end

defmodule Abyss.NativeTruncationDropTestTransport do
  @moduledoc false
  alias Abyss.Transport.UDP.Native
  defdelegate capabilities(socket), to: Native
  defdelegate cancel(socket, operation), to: Native
  defdelegate close(socket), to: Native

  # Only the test's replacement adapter uses this buffer. Production arm/2
  # remains unchanged at 65,535 bytes; recvmsg creates the actual kernel flags.
  def arm(socket, reference), do: :socket.recvmsg(socket, 2, 4096, [], reference)

  def datagram(message, context) do
    owner = :persistent_term.get({__MODULE__, :owner})
    send(owner, {:native_truncation_message, message, context})
    Native.datagram(message, context)
  end
end

defmodule Abyss.DatagramNativeDropAccountingTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.{Endpoint, Telemetry}
  alias Abyss.Transport.UDP.Native

  if :os.type() != {:unix, :linux}, do: @moduletag(:skip)

  setup do
    :persistent_term.put({Abyss.NativeTruncationDropTestTransport, :owner}, self())
    id = make_ref()

    :ok =
      :telemetry.attach(
        id,
        [:abyss, :datagram, :dropped],
        &__MODULE__.event/4,
        self()
      )

    on_exit(fn ->
      :telemetry.detach(id)
      :persistent_term.erase({Abyss.NativeTruncationDropTestTransport, :owner})
    end)

    :ok
  end

  def event(_event, measurements, metadata, owner),
    do: send(owner, {:native_truncation_drop, measurements, metadata})

  for rate <- [0.0, 1.0] do
    test "actual native payload truncation records observed bytes and one ingress drop at sampling #{rate}" do
      {:ok, endpoint} =
        Endpoint.start_link(
          datagram_handler: Abyss.NativeTruncationDropTestHandler,
          handler_options: [owner: self()],
          io_backend: :socket_native,
          connection_telemetry_sample_rate: unquote(rate),
          port: 0,
          transport_options: [ip: {127, 0, 0, 1}]
        )

      Process.unlink(endpoint)
      on_exit(fn -> if Process.alive?(endpoint), do: Endpoint.stop(endpoint, 100) end)
      {:ok, {_, port}} = Endpoint.local_endpoint(endpoint)
      {:ok, client} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_udp.close(client) end)

      [listener] =
        endpoint |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

      assert {:ok, %{received: 0, generation: generation}} = Endpoint.info(endpoint)
      assert :ok = Endpoint.pause(endpoint)
      before = :sys.get_state(listener)

      # Execute cancellation in the actual socket owner before swapping this
      # test-only receive adapter. No receive result or datagram is fabricated.
      :sys.replace_state(listener, fn state ->
        {_, selection} = state.native_select
        :ok = Native.cancel(state.listener_socket, selection)

        %{
          state
          | transport: Abyss.NativeTruncationDropTestTransport,
            native_select: nil,
            armed: false
        }
      end)

      after_setup = :sys.get_state(listener)
      assert after_setup.listener_socket == before.listener_socket
      assert after_setup.generation == generation
      assert :ok = Endpoint.resume(endpoint)

      assert {:ok, %{mode: :running, capabilities: %{adapter: :socket_native}}} =
               Endpoint.status(endpoint)

      :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "truncated")
      assert_receive {:native_truncation_message, message, %{generation: ^generation}}, 1000
      assert :trunc in message.flags
      assert IO.iodata_to_binary(message.iov) == "tr"
      assert IO.iodata_length(message.iov) == 2

      # The telemetry event occurs inside this listener's rejection decision;
      # the subsequent public call observes its completed state transition.
      assert_receive {:native_truncation_drop, %{bytes: 2},
                      %{server_id: ^endpoint, reason: :payload_truncated}},
                     1000

      assert {:ok, info} = Endpoint.info(endpoint)
      assert info.received == 1
      assert info.dropped == 1
      assert info.drop_counts == %{ingress: 1, runtime: 0}
      assert info.input_count == 0
      assert info.retained_bytes == 0
      assert {:ok, status} = Endpoint.status(endpoint)
      fields = [:generation, :received, :dropped, :drop_counts]
      assert Map.take(status, fields) == Map.take(info, fields)
      metrics = Telemetry.get_metrics(endpoint)
      assert metrics.datagrams_received == 1
      assert metrics.datagrams_dropped == 1
      assert metrics.bytes_received == 2
      assert metrics.bytes_dropped == 2
      refute_receive {:native_truncation_drop, _, _}, 0
      refute_receive {:native_truncation_callback, _}, 0
    end
  end
end
