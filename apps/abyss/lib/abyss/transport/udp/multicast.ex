defmodule Abyss.Transport.UDP.Multicast do
  @moduledoc """
  IPv4 and IPv6 multicast transport. Membership and outgoing interface are
  separate options: `add_membership: {group, interface}` joins for reception,
  while `multicast_if: interface` selects transmission. Sending needs no join.

  IPv4 interfaces are local IPv4 addresses, `:any`, or interface names; IPv6
  interfaces are existing positive indices or names. Link-local IPv6 senders
  must select a scope index (see `Abyss.Client`). Defaults are passive binary
  reception, loopback enabled, and TTL/hop limit 1. IPv6 broadcast is rejected.

  `join/2` and `leave/2` operate on an owned socket. Services should call their
  listener membership API, which maintains desired state and idempotency across
  socket restarts. This facade does not fabricate packet destination metadata.
  `strict_group_filter: true` disables Linux IPv4 IP_MULTICAST_ALL on the inet
  backend. Other families/backends/platforms explicitly reject this capability.
  The default is false: OS-wide membership filtering can affect wildcard sockets.
  """
  @behaviour Abyss.Transport
  alias Abyss.Transport.UDP.Core

  @defaults [
    mode: :binary,
    active: false,
    reuseaddr: true,
    multicast_ttl: 1,
    multicast_loop: true
  ]

  @impl true
  def listen(port, options), do: open(port, options)

  def open(port, options) do
    with {:ok, backend} <- Core.effective_backend(options),
         options = [
           {:inet_backend, backend} | Enum.reject(options, &match?({:inet_backend, _}, &1))
         ],
         {:ok, options} <- filtering_options(options),
         {:ok, normalized} <- Core.normalize_options(@defaults, options),
         do: Core.open_socket(port, normalized)
  end

  defp filtering_options(options) when is_list(options) do
    enabled =
      Enum.find_value(options, false, fn
        {:strict_group_filter, value} -> {:value, value}
        _ -> nil
      end)

    options = Enum.reject(options, &match?({:strict_group_filter, _}, &1))
    family = Core.selected_family(options)

    backend =
      Enum.find_value(options, :inet, fn
        {:inet_backend, value} -> value
        _ -> nil
      end)

    case enabled do
      false ->
        {:ok, options}

      {:value, false} ->
        {:ok, options}

      {:value, true} when family == :inet and backend == :inet ->
        if :os.type() == {:unix, :linux},
          do: {:ok, options ++ [{:raw, 0, 49, <<0::native-32>>}]},
          else: {:error, {:unsupported_capability, :strict_group_filter, family, backend}}

      {:value, true} ->
        {:error, {:unsupported_capability, :strict_group_filter, family, backend}}

      {:value, value} ->
        {:error, {:invalid_option, :strict_group_filter, value}}
    end
  end

  @doc "Canonicalize a group and its receiving interface; invalid selectors fail explicitly."
  def normalize_membership({group, selector}) do
    if multicast_address?(group) do
      with {:ok, interface} <- resolve_interface(selector, family(group)),
           do: {:ok, {group, interface}}
    else
      {:error, {:invalid_multicast_group, group}}
    end
  end

  def normalize_membership(value), do: {:error, {:invalid_membership, value}}

  @doc "Return the validated IP address family."
  def family(address) when is_tuple(address) and tuple_size(address) in [4, 8] do
    maximum = if tuple_size(address) == 4, do: 255, else: 65_535

    if Enum.all?(Tuple.to_list(address), &(is_integer(&1) and &1 >= 0 and &1 <= maximum)),
      do: if(tuple_size(address) == 4, do: :inet, else: :inet6),
      else: :invalid
  end

  def family(_), do: :invalid

  def multicast_address?({first, _, _, _} = address),
    do: family(address) == :inet and first in 224..239

  def multicast_address?({first, _, _, _, _, _, _, _} = address),
    do: family(address) == :inet6 and Bitwise.band(first, 0xFF00) == 0xFF00

  def multicast_address?(_), do: false

  @doc "Resolve interface selectors without opening trial sockets or falling back."
  def resolve_interface(:any, :inet), do: {:ok, {0, 0, 0, 0}}
  def resolve_interface({0, 0, 0, 0}, :inet), do: {:ok, {0, 0, 0, 0}}

  def resolve_interface(address, :inet) when is_tuple(address) and tuple_size(address) == 4 do
    with {:ok, interfaces} <- :inet.getifaddrs() do
      if family(address) == :inet and local_address?(interfaces, address),
        do: {:ok, address},
        else: {:error, {:invalid_membership_interface, :inet, address}}
    end
  end

  def resolve_interface(index, :inet6) when is_integer(index) and index > 0 do
    with {:ok, interfaces} <- interface_names() do
      if List.keymember?(interfaces, index, 0), do: {:ok, index}, else: {:error, :enodev}
    end
  end

  def resolve_interface(name, family) when is_binary(name) or is_list(name) do
    name = if is_binary(name), do: String.to_charlist(name), else: name

    with {:ok, interfaces} <- :inet.getifaddrs(),
         {^name, options} <- List.keyfind(interfaces, name, 0) || {:error, :enodev},
         :ok <- interface_up(options) do
      resolve_named(name, options, family)
    end
  end

  def resolve_interface(selector, family),
    do: {:error, {:invalid_membership_interface, family, selector}}

  defp local_address?(interfaces, address) do
    Enum.any?(interfaces, fn {_, options} -> address in Keyword.get_values(options, :addr) end)
  end

  defp interface_up(options) do
    if :up in Keyword.get(options, :flags, []), do: :ok, else: {:error, :enetdown}
  end

  defp resolve_named(_, options, :inet) do
    case Enum.find(Keyword.get_values(options, :addr), &(family(&1) == :inet)) do
      nil -> {:error, :eaddrnotavail}
      address -> {:ok, address}
    end
  end

  defp resolve_named(name, _options, :inet6) do
    with {:ok, names} <- interface_names() do
      named_index(names, name)
    end
  end

  defp named_index(names, name) do
    case List.keyfind(names, name, 1) do
      {index, _} -> {:ok, index}
      nil -> {:error, :enodev}
    end
  end

  defp interface_names do
    if Code.ensure_loaded?(:net) and function_exported?(:net, :if_names, 0),
      do: :net.if_names(),
      else: {:error, :interface_indices_not_supported}
  end

  @doc "Join one validated membership; host owners provide duplicate idempotency."
  def join(socket, membership), do: membership_operation(socket, :add_membership, membership)
  @doc "Leave one membership, preserving operating-system errors."
  def leave(socket, membership), do: membership_operation(socket, :drop_membership, membership)

  defp membership_operation(socket, operation, membership) do
    with {:ok, {group, _} = normalized} <- normalize_membership(membership),
         {:ok, {local, _}} <- Core.sockname(socket),
         true <- family(local) == family(group) do
      Core.setopts(socket, [{operation, normalized}])
    else
      false -> {:error, {:invalid_option, operation, :family_mismatch}}
      error -> error
    end
  end

  @impl true
  defdelegate controlling_process(socket, pid), to: Core
  @impl true
  defdelegate recv(socket, length, timeout), to: Core
  @impl true
  defdelegate send(socket, data), to: Core
  defdelegate send(socket, destination, data), to: Core
  defdelegate send(socket, ip, port, data), to: Core
  defdelegate send(socket, ip, port, ancillary, data), to: Core
  @impl true
  defdelegate getopts(socket, options), to: Core
  @impl true
  defdelegate setopts(socket, options), to: Core
  @impl true
  defdelegate close(socket), to: Core
  @impl true
  defdelegate sockname(socket), to: Core
  @impl true
  defdelegate peername(socket), to: Core
  @impl true
  defdelegate getstat(socket), to: Core
end
