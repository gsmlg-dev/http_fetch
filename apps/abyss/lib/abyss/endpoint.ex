defmodule Abyss.Endpoint do
  @moduledoc """
  Facade over the existing Abyss UDP owner and supervision tree.

  Select `datagram_handler: Module` for the new application-state API. An endpoint
  has one logical identity and a replaceable socket generation. Capabilities and
  receipts belong to that generation. Sends return admission references; await
  reports local completion, definite failure or an unknown outcome. Timeouts do
  not cancel accepted sends or authorize retries.
  """

  alias Abyss.Datagram
  alias Abyss.Dispatcher
  alias Abyss.Dispatcher.SendCapability
  alias Abyss.Transport.UDP.Multicast

  defdelegate start_link(options), to: Abyss
  @doc "Return a supervisor child specification for an endpoint."
  defdelegate child_spec(options), to: Abyss
  defdelegate pause(server), to: Abyss, as: :suspend
  defdelegate resume(server), to: Abyss
  defdelegate join(server, membership), to: Abyss
  defdelegate leave(server, membership), to: Abyss
  defdelegate memberships(server), to: Abyss

  @doc "Stop with one overall drain deadline; accepted outcomes can remain unknown."
  def stop(server, timeout \\ 15_000), do: Abyss.stop(server, timeout)

  @doc """
  Inspect the single existing socket owner without creating a second owner.

  For the datagram API, `received` and `dropped` count current-generation
  network inputs. `dropped` sums `drop_counts.ingress` and `drop_counts.runtime`;
  internal timer/send-outcome rejection is separate in `internal_events_rejected`.
  Counts persist while the same generation remains inspectable after drain.
  Generation replacement resets these counts; logical-server telemetry retains
  its existing lifetime. Callback/send failure, teardown discard and unknown
  kernel loss are outside the network admission-drop total.
  """
  def info(server) do
    case Abyss.Server.listener_pool_pid(server) do
      nil -> {:error, :not_running}
      pool -> listener_info(Abyss.ListenerPool.listener_pids(pool))
    end
  end

  def local_endpoint(server), do: field(server, :local_endpoint)
  def capabilities(server), do: field(server, :capabilities)
  def capability(server), do: field(server, :send)
  def status(server), do: info(server)

  @doc "Admit a bounded send from the original endpoint socket."
  def send(capability, destination, payload, timeout \\ 100)

  def send(%SendCapability{} = capability, destination, payload, timeout)
      when is_binary(payload) and is_integer(timeout) and timeout >= 0 do
    with {:ok, remote} <- send_destination(capability, destination),
         do: Dispatcher.send(capability, remote, payload, timeout)
  end

  def send(_, _, _, _), do: {:error, :invalid_send}

  @doc "Reply to the observed peer, optionally requiring source/interface correctness."
  def reply(capability, datagram, payload, policy \\ :route, timeout \\ 100)

  def reply(
        %SendCapability{generation: generation} = capability,
        %Datagram{generation: generation} = datagram,
        payload,
        :route,
        timeout
      ),
      do: send(capability, datagram.peer, payload, timeout)

  def reply(
        %SendCapability{generation: generation} = capability,
        %Datagram{generation: generation} = datagram,
        payload,
        :strict,
        timeout
      )
      when is_binary(payload) and is_integer(timeout) and timeout >= 0 do
    if Map.get(capability, :io_backend, :gen_udp) == :socket_native do
      if datagram.local_address && datagram.interface_index,
        do:
          Dispatcher.send(capability, {:native_reply, compact_reply(datagram)}, payload, timeout),
        else: {:error, :missing_reply_metadata}
    else
      {:error, :strict_reply_unsupported}
    end
  end

  def reply(%SendCapability{generation: generation}, %Datagram{generation: generation}, _, _, _),
    do: {:error, :invalid_reply}

  def reply(%SendCapability{}, %Datagram{}, _, _, _), do: {:error, :stale_generation}
  def reply(_, _, _, _, _), do: {:error, :invalid_reply}

  @doc "Await local completion of an admitted send without cancelling it on timeout."
  def await(capability, ref, timeout \\ 100)

  def await(%SendCapability{} = capability, ref, timeout)
      when is_reference(ref) and is_integer(timeout) and timeout >= 0,
      do: Dispatcher.Writer.await(capability.writer, capability, ref, timeout)

  def await(_, _, _), do: {:error, :invalid_send_reference}

  defp compact_reply(datagram) do
    %{
      datagram
      | payload: <<>>,
        ancillary: [],
        destination: nil,
        hop_limit: nil,
        traffic_class: nil,
        endpoint_id: nil,
        local_endpoint: nil
    }
  end

  defp listener_info([listener]) do
    GenServer.call(listener, :endpoint_info)
  catch
    :exit, _ -> {:error, :not_running}
  end

  defp listener_info([]), do: {:error, :not_running}
  defp listener_info(_), do: {:error, :multiple_receive_endpoints}

  defp field(server, key) do
    with {:ok, info} <- info(server), do: {:ok, Map.fetch!(info, key)}
  end

  defp send_destination(capability, %{family: family, addr: address, port: port} = destination)
       when family in [:inet, :inet6] and is_tuple(address) and is_integer(port) and
              port in 0..65_535 do
    cond do
      not valid_sockaddr?(destination) ->
        {:error, :invalid_destination}

      Map.get(capability, :io_backend, :gen_udp) == :socket_native ->
        {:ok, {:native, destination}}

      family == :inet6 and Map.get(destination, :scope_id, 0) != 0 ->
        {:ok, {:scoped, destination}}

      true ->
        {:ok, {address, port}}
    end
  end

  defp send_destination(_, _), do: {:error, :invalid_destination}

  defp valid_sockaddr?(%{family: family, addr: address} = destination) do
    scope = Map.get(destination, :scope_id, 0)
    flowinfo = Map.get(destination, :flowinfo, 0)

    Multicast.family(address) == family and
      nonnegative_integer?(scope) and scope <= 4_294_967_295 and
      nonnegative_integer?(flowinfo) and flowinfo <= 4_294_967_295 and
      Enum.all?(Map.keys(destination), &(&1 in [:family, :addr, :port, :scope_id, :flowinfo]))
  end

  defp nonnegative_integer?(value), do: is_integer(value) and value >= 0
end
