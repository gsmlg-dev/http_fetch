defmodule Abyss.Datagram do
  @moduledoc """
  A complete received UDP datagram and its observed network context.

  Unavailable metadata is `nil`. `local_endpoint` is the bound socket address,
  including wildcard binds; it is not the packet destination. `received_at` is
  BEAM monotonic time in microseconds when receive processing occurs, rather
  than a kernel arrival timestamp. Original ancillary data and flags are kept
  independently of telemetry sampling.
  """

  @type sockaddr :: %{
          required(:family) => :inet | :inet6,
          required(:addr) => :inet.ip_address(),
          required(:port) => :inet.port_number(),
          optional(:scope_id) => non_neg_integer(),
          optional(:flowinfo) => non_neg_integer()
        }
  @type t :: %__MODULE__{
          payload: binary(),
          peer: sockaddr(),
          local_endpoint: term(),
          destination: :inet.ip_address() | nil,
          interface_index: non_neg_integer() | nil,
          local_address: :inet.ip_address() | nil,
          hop_limit: integer() | nil,
          traffic_class: integer() | nil,
          ancillary: list(),
          flags: list(),
          endpoint_id: term(),
          generation: reference(),
          received_at: integer()
        }

  @enforce_keys [:payload, :peer, :endpoint_id, :generation, :received_at]
  defstruct [
    :payload,
    :peer,
    :local_endpoint,
    :destination,
    :interface_index,
    :local_address,
    :hop_limit,
    :traffic_class,
    :endpoint_id,
    :generation,
    :received_at,
    ancillary: [],
    flags: []
  ]

  @doc "Normalize a GenUDP receive tuple without inferring packet addressing."
  def from_gen_udp({address, port, payload}, context) when is_binary(payload),
    do: from_gen_udp({address, port, [], payload}, context)

  def from_gen_udp({address, port, ancillary, payload}, context)
      when is_list(ancillary) and is_binary(payload) do
    base(payload, sockaddr(address, port), context)
    |> Map.put(:ancillary, ancillary)
    |> gen_udp_metadata(ancillary)
  end

  @doc "Normalize an OTP recvmsg map. The adapter must reject payload truncation."
  def from_native(%{addr: peer, iov: iov} = message, context) do
    flags = Map.get(message, :flags, [])

    controls =
      Enum.map(Map.get(message, :ctrl, []), fn
        %{data: data} = control when is_binary(data) -> %{control | data: owned_binary(data)}
        control -> control
      end)

    datagram =
      base(owned_binary(IO.iodata_to_binary(iov)), peer, context)
      |> Map.put(:ancillary, controls)
      |> Map.put(:flags, flags)

    if :ctrunc in flags,
      do: datagram,
      else: Enum.reduce(controls, datagram, &native_metadata/2)
  end

  @doc "Build a sockaddr from an observed address and port, preserving IPv6 scope."
  def sockaddr(%{family: family, addr: _} = address, port) when family in [:inet, :inet6],
    do: Map.put(address, :port, port)

  def sockaddr(address, port) when is_tuple(address) and tuple_size(address) == 4,
    do: %{family: :inet, addr: address, port: port}

  def sockaddr(address, port) when is_tuple(address) and tuple_size(address) == 8,
    do: %{family: :inet6, addr: address, port: port}

  defp base(payload, peer, context) do
    %__MODULE__{
      payload: payload,
      peer: peer,
      endpoint_id: Map.fetch!(context, :endpoint_id),
      generation: Map.fetch!(context, :generation),
      local_endpoint: Map.get(context, :local_endpoint),
      received_at:
        Map.get_lazy(context, :received_at, fn -> System.monotonic_time(:microsecond) end)
    }
  end

  defp owned_binary(binary) do
    if :binary.referenced_byte_size(binary) > byte_size(binary),
      do: :binary.copy(binary),
      else: binary
  end

  defp gen_udp_metadata(datagram, ancillary) do
    Enum.reduce(ancillary, datagram, fn
      {:ttl, value}, acc -> %{acc | hop_limit: value}
      {:hoplimit, value}, acc -> %{acc | hop_limit: value}
      {:tos, value}, acc -> %{acc | traffic_class: value}
      {:tclass, value}, acc -> %{acc | traffic_class: value}
      _, acc -> acc
    end)
  end

  defp native_metadata(%{level: level, type: :pktinfo, value: value}, datagram)
       when level in [:ip, :hopopt, 0] do
    %{
      datagram
      | destination: Map.get(value, :addr),
        local_address: usable_source(Map.get(value, :spec_dst)),
        interface_index: Map.get(value, :ifindex)
    }
  end

  defp native_metadata(%{level: level, type: :pktinfo, value: value}, datagram)
       when level in [:ipv6, 41] do
    address = Map.get(value, :addr)

    %{
      datagram
      | destination: address,
        local_address: usable_source(address),
        interface_index: Map.get(value, :ifindex)
    }
  end

  defp native_metadata(%{type: type, value: value}, datagram) when type in [:ttl, :hoplimit],
    do: %{datagram | hop_limit: value}

  defp native_metadata(%{type: type, value: value}, datagram) when type in [:tos, :tclass],
    do: %{datagram | traffic_class: value}

  defp native_metadata(_, datagram), do: datagram

  defp usable_source({0, 0, 0, 0}), do: nil
  defp usable_source({255, 255, 255, 255}), do: nil
  defp usable_source({first, _, _, _}) when first in 224..239, do: nil
  defp usable_source({0, 0, 0, 0, 0, 0, 0, 0}), do: nil
  defp usable_source({first, _, _, _, _, _, _, _}) when first in 0xFF00..0xFFFF, do: nil
  defp usable_source(address), do: address
end
