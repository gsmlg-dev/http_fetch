defmodule Abyss.Transport.UDP.Core do
  @moduledoc """
  Core UDP transport functionality shared between Unicast and Broadcast transports.

  This module contains common UDP socket operations that are used by both
  `Abyss.Transport.UDP.Unicast` and `Abyss.Transport.UDP.Broadcast` to avoid
  code duplication.

  ## Shared Operations

  - Socket control and ownership transfer
  - Data receiving and sending
  - Socket option management
  - Socket information retrieval
  - Connection statistics

  This module is not meant to be used directly. Use the specific transport
  modules instead:
  - `Abyss.Transport.UDP.Unicast` for unicast traffic
  - `Abyss.Transport.UDP.Broadcast` for broadcast/multicast traffic
  """

  alias Abyss.Transport.UDP.Multicast

  @doc false
  def effective_backend(options) when is_list(options) do
    case List.keyfind(options, :inet_backend, 0) do
      {:inet_backend, backend} when backend in [:inet, :socket] -> {:ok, backend}
      {:inet_backend, value} -> {:error, {:invalid_option, :inet_backend, value}}
      nil -> boot_backend()
    end
  end

  def effective_backend(options), do: {:error, {:invalid_options, options}}

  # OTP caches its startup choice. Probe the public API once instead of reading
  # mutable application settings or depending on private OTP implementation.
  defp boot_backend do
    case :persistent_term.get({__MODULE__, :boot_backend}, :unknown) do
      :unknown ->
        probe_boot_backend()

      backend ->
        {:ok, backend}
    end
  end

  defp probe_boot_backend do
    with {:ok, socket} <- :gen_udp.open(0, [:binary, {:active, false}]) do
      backend = if is_port(socket), do: :inet, else: :socket
      :gen_udp.close(socket)
      :persistent_term.put({__MODULE__, :boot_backend}, backend)
      {:ok, backend}
    end
  end

  @doc false
  def resolve_destination(host) when is_tuple(host), do: {:ok, host}

  def resolve_destination(host) when is_binary(host),
    do: :inet.getaddr(String.to_charlist(host), :inet)

  def resolve_destination(host) when is_list(host), do: :inet.getaddr(host, :inet)
  def resolve_destination(host), do: {:error, {:invalid_address, host}}

  @doc false
  def response_policy({address, _}) do
    if Multicast.multicast_address?(address) or address == {255, 255, 255, 255},
      do: :any,
      else: :exact
  end

  def response_policy(%{addr: address, port: port}), do: response_policy({address, port})

  @doc false
  def exchange(socket, destination, data, timeout, policy) do
    deadline =
      if timeout == :infinity,
        do: :infinity,
        else: System.monotonic_time(:millisecond) + timeout

    with :ok <- send(socket, destination, data),
         do: receive_response(socket, destination, deadline, policy, true)
  end

  defp receive_response(socket, destination, deadline, policy, first) do
    remaining =
      if deadline == :infinity,
        do: :infinity,
        else: max(0, deadline - System.monotonic_time(:millisecond))

    # Preserve one nonblocking receive for timeout zero. Subsequent rejected
    # packets must not keep a full kernel queue alive past the deadline.
    if remaining == 0 and not first do
      {:error, :timeout}
    else
      accept_response(socket, destination, deadline, policy, recv(socket, 0, remaining))
    end
  end

  defp accept_response(socket, destination, deadline, policy, {:ok, response} = result) do
    if policy == :any or peer_matches?(response, destination),
      do: result,
      else: receive_response(socket, destination, deadline, policy, false)
  end

  defp accept_response(_socket, _destination, _deadline, _policy, error), do: error

  @doc false
  def peer_matches?(response, {address, port}) when tuple_size(response) in [3, 4],
    do: elem(response, 0) == address and elem(response, 1) == port

  def peer_matches?(response, %{addr: address, port: port} = destination)
      when tuple_size(response) in [3, 4] do
    case elem(response, 0) do
      %{addr: ^address, port: ^port} = peer ->
        Map.get(peer, :scope_id) == Map.get(destination, :scope_id)

      ^address ->
        elem(response, 1) == port and Map.get(destination, :scope_id, 0) == 0

      _ ->
        false
    end
  end

  def peer_matches?(_, _), do: false

  @doc """
  Transfers ownership of the given socket to the given process.
  """
  @spec controlling_process(Abyss.Transport.socket(), pid()) ::
          Abyss.Transport.on_controlling_process()
  defdelegate controlling_process(socket, pid), to: :gen_udp

  @doc """
  Receives data from a UDP socket.
  """
  @spec recv(Abyss.Transport.socket(), non_neg_integer(), timeout()) ::
          Abyss.Transport.on_recv()
  defdelegate recv(socket, length, timeout), to: :gen_udp

  @spec recv(Abyss.Transport.socket(), non_neg_integer()) :: Abyss.Transport.on_recv()
  defdelegate recv(socket, length), to: :gen_udp

  @doc """
  Sends data on a UDP socket.
  """
  @spec send(Abyss.Transport.socket(), iodata()) :: Abyss.Transport.on_send()
  def send(socket, data), do: record_send(socket, data, :gen_udp.send(socket, data))

  def send(socket, %{family: :inet6, scope_id: _}, _data) when not is_port(socket),
    do: {:error, {:unsupported_capability, :scoped_sockaddr_send, :socket}}

  def send(socket, dest, data), do: record_send(socket, data, :gen_udp.send(socket, dest, data))

  def send(socket, ip, port, data),
    do: record_send(socket, data, :gen_udp.send(socket, ip, port, data))

  def send(socket, ip, port, anc_data, data),
    do: record_send(socket, data, :gen_udp.send(socket, ip, port, anc_data, data))

  defp record_send(socket, data, result) do
    Abyss.Telemetry.track_send_result(
      Abyss.Telemetry.socket_scope(socket),
      result,
      IO.iodata_length(data),
      %{socket: socket}
    )

    result
  end

  @doc """
  Gets socket options.
  """
  @spec getopts(Abyss.Transport.socket(), Abyss.Transport.socket_get_options()) ::
          Abyss.Transport.on_getopts()
  def getopts(socket, options) do
    with {:ok, {local, _}} <- sockname(socket),
         {:ok, requested} <- normalize_get_options(options, Multicast.family(local), socket),
         {:ok, values} <- :inet.getopts(socket, requested) do
      {:ok,
       Enum.map(Enum.zip(options, values), fn {requested, value} ->
         restore_get_option(requested, value)
       end)}
    end
  end

  @doc """
  Sets socket options.
  """
  @spec setopts(Abyss.Transport.socket(), Abyss.Transport.socket_set_options()) ::
          Abyss.Transport.on_setopts()
  def setopts(socket, options) do
    with {:ok, {local, _}} <- sockname(socket),
         {:ok, normalized} <- normalize_all(options, Multicast.family(local)),
         {:ok, runtime_options} <- runtime_options(socket, normalized),
         do: :inet.setopts(socket, runtime_options)
  end

  @doc """
  Closes a UDP socket.
  """
  @spec close(Abyss.Transport.socket() | Abyss.Transport.listener_socket()) :: :ok
  defdelegate close(socket), to: :gen_udp

  @doc """
  Returns information about the local socket endpoint.
  """
  @spec sockname(Abyss.Transport.socket() | Abyss.Transport.listener_socket()) ::
          Abyss.Transport.on_sockname()
  defdelegate sockname(socket), to: :inet

  @doc """
  Returns information about the remote socket endpoint.
  """
  @spec peername(Abyss.Transport.socket()) :: Abyss.Transport.on_peername()
  defdelegate peername(socket), to: :inet

  @doc """
  Returns statistics about the socket connection.
  """
  @spec getstat(Abyss.Transport.socket()) :: Abyss.Transport.socket_stats()
  defdelegate getstat(socket), to: :inet

  @doc """
  Merge scalar options with first-user-value precedence. Family and data-mode
  aliases share a key. Membership operations retain their order and distinct
  group/interface pairs; repeated identical operations are idempotent until an
  opposite operation appears. Raw options are ordered operations, not keywords.
  The backend selector is always first as required by OTP.
  """
  @spec merge_options(list(), list()) :: list()
  def merge_options(defaults, users) do
    {options, _, _} =
      Enum.reduce(users ++ defaults, {[], MapSet.new(), %{}}, fn
        {op, membership} = option, {acc, seen, memberships}
        when op in [:add_membership, :drop_membership] ->
          if Map.get(memberships, membership) == op do
            {acc, seen, memberships}
          else
            {[option | acc], seen, Map.put(memberships, membership, op)}
          end

        {:raw, _, _, _} = option, {acc, seen, memberships} ->
          {[option | acc], seen, memberships}

        option, {acc, seen, memberships} ->
          key = option_key(option)

          if MapSet.member?(seen, key),
            do: {acc, seen, memberships},
            else: {[option | acc], MapSet.put(seen, key), memberships}
      end)

    {backend, rest} =
      options |> Enum.reverse() |> Enum.split_with(&match?({:inet_backend, _}, &1))

    backend ++ rest
  end

  defp option_key(atom) when atom in [:inet, :inet6, :local], do: :family
  defp option_key(atom) when atom in [:binary, :list], do: :mode
  defp option_key({key, _}), do: key
  defp option_key(option), do: option

  @doc "Validate actual UDP option forms before opening a socket."
  @spec normalize_options(list(), list()) :: {:ok, list()} | {:error, term()}
  def normalize_options(defaults, users) when is_list(defaults) and is_list(users) do
    with :ok <- validate_conflicts(users),
         {:ok, backend} <- effective_backend(merge_options(defaults, users)) do
      options = merge_options(defaults, users)
      family = selected_family(options)

      options =
        if family == :inet6 and :inet6 not in options, do: [:inet6 | options], else: options

      rest = Enum.reject(options, &match?({:inet_backend, _}, &1))
      options = [{:inet_backend, backend} | rest]

      with {:ok, normalized} <- normalize_all(options, family),
           do: {:ok, merge_options([], normalized)}
    end
  end

  def normalize_options(_, users), do: {:error, {:invalid_options, users}}

  defp normalize_all(options, family) do
    result = Enum.reduce_while(options, {:ok, []}, &normalize_step(&1, &2, family))

    case result do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      error -> error
    end
  end

  defp normalize_step(option, {:ok, acc}, family) do
    case normalize_option(option, family) do
      {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
      error -> {:halt, error}
    end
  end

  defp validate_conflicts(options) do
    families = Enum.filter(options, &(&1 in [:inet, :inet6, :local])) |> Enum.uniq()

    modes =
      Enum.flat_map(options, fn
        mode when mode in [:binary, :list] -> [mode]
        {:mode, mode} -> [mode]
        _ -> []
      end)
      |> Enum.uniq()

    cond do
      length(families) > 1 -> {:error, {:invalid_option, :family, :conflicting}}
      length(modes) > 1 -> {:error, {:invalid_option, :mode, :conflicting}}
      true -> :ok
    end
  end

  @doc false
  def selected_family(options) do
    Enum.find(options, &(&1 in [:inet, :inet6, :local])) ||
      Enum.find_value(options, :inet, fn
        {:ip, ip} when is_tuple(ip) and tuple_size(ip) == 8 ->
          :inet6

        {op, {group, _}}
        when op in [:add_membership, :drop_membership] and is_tuple(group) and
               tuple_size(group) == 8 ->
          :inet6

        _ ->
          nil
      end)
  end

  defp normalize_option({op, membership}, family)
       when op in [:add_membership, :drop_membership] do
    with {:ok, {group, _} = normalized} <-
           Multicast.normalize_membership(membership),
         true <- Multicast.family(group) == family do
      {:ok, {op, normalized}}
    else
      false -> {:error, {:invalid_option, op, :family_mismatch}}
      error -> error
    end
  end

  defp normalize_option({:broadcast, true}, :inet6),
    do: {:error, {:invalid_option, :broadcast, :ipv6}}

  defp normalize_option({:ip, ip} = option, family)
       when is_tuple(ip) and tuple_size(ip) in [4, 8] do
    if Multicast.family(ip) == family,
      do: {:ok, option},
      else: {:error, {:invalid_option, :ip, :family_mismatch}}
  end

  defp normalize_option({:multicast_if, selector}, family) do
    with {:ok, interface} <- Multicast.resolve_interface(selector, family),
         do: multicast_option(:multicast_if, interface, family)
  end

  defp normalize_option({:multicast_ttl, value}, family)
       when is_integer(value) and value in 0..255,
       do: multicast_option(:multicast_ttl, value, family)

  defp normalize_option({:multicast_ttl, value}, _),
    do: {:error, {:invalid_option, :multicast_ttl, value}}

  defp normalize_option({:multicast_loop, value}, family) when is_boolean(value),
    do: multicast_option(:multicast_loop, value, family)

  defp normalize_option({key, value} = option, _)
       when key in [:broadcast, :multicast_loop, :reuseaddr, :reuseport] do
    if is_boolean(value), do: {:ok, option}, else: {:error, {:invalid_option, key, value}}
  end

  defp normalize_option({:raw, level, name, value} = option, _)
       when is_integer(level) and is_integer(name) and is_binary(value),
       do: {:ok, option}

  defp normalize_option(option, _) when is_atom(option), do: {:ok, option}
  defp normalize_option({key, _} = option, _) when is_atom(key), do: {:ok, option}
  defp normalize_option(option, _), do: {:error, {:invalid_option, option, :unsupported_form}}

  # OTP generic multicast option names target IPv4, even on IPv6 sockets.
  # Use the correct public raw socket option ABI on the verified Linux backend.
  defp multicast_option(key, value, :inet6) do
    with {:ok, number} <- ipv6_option_number(key) do
      encoded = encode_option_value(value)
      {:ok, {:raw, 41, number, <<encoded::native-unsigned-32>>}}
    end
  end

  defp multicast_option(key, value, _), do: {:ok, {key, value}}

  defp encode_option_value(true), do: 1
  defp encode_option_value(false), do: 0
  defp encode_option_value(value), do: value

  defp ipv6_option_number(key) do
    if :os.type() == {:unix, :linux},
      do: {:ok, Map.fetch!(%{multicast_if: 17, multicast_ttl: 18, multicast_loop: 19}, key)},
      else: {:error, {:unsupported_capability, :ipv6_multicast_options, :os.type()}}
  end

  defp ipv4_option_number(key) do
    if :os.type() == {:unix, :linux},
      do: {:ok, Map.fetch!(%{multicast_if: 32, multicast_ttl: 33, multicast_loop: 34}, key)},
      else: {:error, {:unsupported_capability, :socket_backend_multicast_options, :os.type()}}
  end

  defp normalize_get_options(options, family, socket) do
    Enum.reduce_while(options, {:ok, []}, &normalize_get_step(&1, &2, family, socket))
    |> reverse_normalized()
  end

  defp normalize_get_step(key, {:ok, acc}, family, socket)
       when key in [:multicast_if, :multicast_ttl, :multicast_loop] do
    case multicast_get_option(key, family, socket) do
      {:ok, option} -> {:cont, {:ok, [option | acc]}}
      error -> {:halt, error}
    end
  end

  defp normalize_get_step(option, {:ok, acc}, _, _), do: {:cont, {:ok, [option | acc]}}

  defp multicast_get_option(key, :inet6, _) do
    with {:ok, number} <- ipv6_option_number(key), do: {:ok, {:raw, 41, number, 4}}
  end

  # The inet driver's named getter can misdecode IP_MULTICAST_IF on Linux.
  # The kernel's four-byte address is unambiguous on the verified ABI.
  defp multicast_get_option(:multicast_if, :inet, socket) when is_port(socket) do
    if :os.type() == {:unix, :linux},
      do: {:ok, {:raw, 0, 32, 4}},
      else: {:ok, :multicast_if}
  end

  defp multicast_get_option(key, :inet, socket) when not is_port(socket) do
    with {:ok, number} <- ipv4_option_number(key), do: {:ok, {:raw, 0, number, 4}}
  end

  defp multicast_get_option(key, _, _), do: {:ok, key}
  defp reverse_normalized({:ok, options}), do: {:ok, Enum.reverse(options)}
  defp reverse_normalized(error), do: error

  defp restore_get_option(:multicast_if, {:raw, 0, 32, <<a, b, c, d>>}),
    do: {:multicast_if, {a, b, c, d}}

  defp restore_get_option(key, {:raw, level, _, <<value::native-unsigned-32>>})
       when level in [0, 41] and key in [:multicast_if, :multicast_ttl, :multicast_loop] do
    {key, if(key == :multicast_loop, do: value != 0, else: value)}
  end

  defp restore_get_option(key, {{:raw, level, number, 4}, value})
       when level in [0, 41] and key in [:multicast_if, :multicast_ttl, :multicast_loop],
       do: restore_get_option(key, {:raw, level, number, value})

  defp restore_get_option(_requested, value), do: value

  @doc "Open a validated socket; failed startup leaves no live socket or memberships."
  @spec open_socket(integer(), list()) :: {:ok, Abyss.Transport.socket()} | {:error, term()}
  def open_socket(port, options) when is_integer(port) and port in 0..65_535 do
    with {:ok, normalized} <- normalize_options([], options) do
      {memberships, socket_options} = Enum.split_with(normalized, &membership_option?/1)

      with {:ok, socket_options} <- open_backend_options(socket_options),
           {:ok, socket} <- :gen_udp.open(port, socket_options),
           do: initialize_memberships(socket, memberships)
    end
  catch
    :error, :badarg -> {:error, {:invalid_socket_options, options}}
    :exit, :badarg -> {:error, {:invalid_socket_options, options}}
  end

  def open_socket(port, _), do: {:error, {:invalid_port, port}}

  defp runtime_options(socket, options) when is_port(socket), do: {:ok, options}

  defp runtime_options(_socket, options), do: socket_backend_options(options)

  defp open_backend_options(options) do
    if {:inet_backend, :socket} in options,
      do: socket_backend_options(options),
      else: {:ok, options}
  end

  defp socket_backend_options(options) do
    Enum.reduce_while(options, {:ok, []}, &runtime_option_step/2)
    |> reverse_normalized()
  end

  defp runtime_option_step({operation, {group, interface}}, {:ok, acc})
       when operation in [:add_membership, :drop_membership] do
    case raw_membership(operation, group, interface) do
      {:ok, option} -> {:cont, {:ok, [option | acc]}}
      error -> {:halt, error}
    end
  end

  defp runtime_option_step({key, value}, {:ok, acc})
       when key in [:multicast_if, :multicast_ttl, :multicast_loop] do
    case ipv4_option_number(key) do
      {:ok, number} ->
        encoded = encode_ipv4_option(key, value)
        {:cont, {:ok, [{:raw, 0, number, encoded} | acc]}}

      error ->
        {:halt, error}
    end
  end

  defp runtime_option_step(option, {:ok, acc}), do: {:cont, {:ok, [option | acc]}}

  defp encode_ipv4_option(:multicast_if, {a, b, c, d}), do: <<a, b, c, d>>
  defp encode_ipv4_option(_, value), do: <<encode_option_value(value)::native-unsigned-32>>

  defp raw_membership(operation, group, interface) do
    if :os.type() == {:unix, :linux},
      do: {:ok, encode_membership(operation, group, interface)},
      else: {:error, {:unsupported_capability, :socket_backend_membership, :os.type()}}
  end

  defp encode_membership(operation, {a, b, c, d}, {e, f, g, h}) do
    number = if operation == :add_membership, do: 35, else: 36
    {:raw, 0, number, <<a, b, c, d, e, f, g, h, 0::native-32>>}
  end

  defp encode_membership(operation, group, index) do
    number = if operation == :add_membership, do: 20, else: 21
    address = for part <- Tuple.to_list(group), into: <<>>, do: <<part::16>>
    {:raw, 41, number, <<address::binary, index::native-32>>}
  end

  defp membership_option?({operation, _}) when operation in [:add_membership, :drop_membership],
    do: true

  defp membership_option?(_), do: false

  # OTP's open-option parser treats IPv6 membership as a scalar; apply each
  # operation separately through its public API, then roll back on any error.
  defp initialize_memberships(socket, memberships) do
    case Enum.reduce_while(memberships, :ok, &apply_membership(socket, &1, &2)) do
      :ok ->
        {:ok, socket}

      error ->
        close(socket)
        error
    end
  catch
    kind, reason ->
      close(socket)
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp apply_membership(socket, option, :ok) do
    case setopts(socket, [option]) do
      :ok -> {:cont, :ok}
      {:error, reason} -> {:halt, {:error, {:membership_failed, option, reason}}}
    end
  end
end
