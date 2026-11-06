defmodule Abyss.Client do
  @moduledoc """
  Stateless UDP client for outbound packet transmission and request-response operations.

  Provides client capabilities for unicast and broadcast operations, as well as
  request-response patterns for protocols like DNS. Each call opens an ephemeral
  socket, performs the operation, and closes the socket.

  ## Features

  - **Stateless** - No connection state or socket lifecycle management
  - **Explicit** - Caller provides all addressing parameters
  - **Request-Response** - `send_recv/5` for unicast query protocols (DNS)
  - **Broadcast** - `broadcast/4` for send-only multicast/broadcast
  - **Subscribe** - `subscribe_broadcast/4` for receive-only multicast/broadcast
  - **Telemetry integrated** - Consistent with Abyss server telemetry patterns

  ## Usage Examples

  ### DNS Query (Request-Response)

      # Query DNS server with timeout
      query_packet = DNS.encode(query)
      {:ok, response} = Abyss.Client.send_recv({8, 8, 8, 8}, 53, query_packet, 5000)

      # With source binding
      {:ok, response} = Abyss.Client.send_recv({8, 8, 8, 8}, 53, query_packet, 5000,
        source: {192, 168, 1, 10})

  ### DNS Forwarding (Fire-and-Forget)

      # Forward query to upstream resolver
      query_packet = DNS.encode(query)
      Abyss.Client.send({8, 8, 8, 8}, 53, query_packet)

  ### mDNS Announcements (Send-only Broadcast)

      # Multicast announcement
      announcement = MDNS.encode(response)
      Abyss.Client.broadcast({224, 0, 0, 251}, 5353, announcement,
        source: {192, 168, 1, 10},
        interface: "eth0"
      )

  ### mDNS Discovery (Receive-only Subscribe)

      # Subscribe to multicast and collect responses for 2 seconds
      {:ok, responses} = Abyss.Client.subscribe_broadcast({224, 0, 0, 251}, 5353, 2000,
        source: {192, 168, 1, 10})

  ### DHCPv4 Responses

      # DHCPOFFER via limited broadcast
      offer_packet = DHCP.encode(offer)
      Abyss.Client.broadcast({255, 255, 255, 255}, 68, offer_packet,
        source: {192, 168, 1, 1},
        interface: "eth0"
      )
  """

  @typedoc "Destination host - IP address or hostname"
  @type host :: :inet.ip_address() | :inet.hostname()

  @typedoc "Port number"
  @type port_number :: :inet.port_number()

  @typedoc "Binary packet data"
  @type packet :: binary()

  @typedoc "Broadcast address - IP address for broadcast or multicast"
  @type broadcast_addr :: :inet.ip_address()

  @typedoc """
  Client options.

  - `:source` - Source IP address to bind the socket to
  - `:interface` - Network interface name (e.g., "eth0") for interface binding
  - `:ttl` - Time-to-live for multicast packets (default: 1 for link-local)
  - `:bind_port` - Port to bind the socket to (default: 0 for ephemeral)
  """
  @type opts :: keyword()

  @typedoc "POSIX error reason"
  @type reason :: :inet.posix()

  alias Abyss.Transport.UDP.Core
  alias Abyss.Transport.UDP.Multicast

  @doc """
  Send one datagram and return its unicast response. `source`, `interface`,
  `family`, and `bind_port` settings are shared by all client helpers.

  Unicast responses must match the resolved address and port. Multicast and
  limited broadcast accept any peer. Directed broadcast requires explicit
  `response_policy: :any`; `:exact` may be selected to restrict other requests.
  Resolution and socket startup precede the response budget; sending and all
  rejected packets share one monotonic deadline. Matching is not authentication.
  """
  @spec send_recv(host(), port_number(), packet(), non_neg_integer(), opts()) ::
          {:ok, binary()} | {:error, term()}
  def send_recv(host, port, packet, timeout, opts \\ []) do
    operation(:send_recv, host, port, packet, timeout, fn ->
      request_response(host, port, packet, timeout, opts, false)
    end)
  end

  @doc "Send a datagram. A successful result means local submission, not peer delivery."
  @spec send(host(), port_number(), packet(), opts()) :: :ok | {:error, term()}
  def send(host, port, packet, opts \\ []) do
    operation(:send, host, port, packet, nil, fn ->
      with_socket(host, port, opts, false, fn socket, destination ->
        Core.send(socket, destination, packet)
      end)
    end)
  end

  @doc """
  Send IPv4 limited/directed broadcast or IPv4/IPv6 multicast. The caller
  supplies the destination; no subnet broadcast is guessed. `interface` names
  select multicast egress or Linux broadcast egress explicitly. IPv6 multicast
  uses a positive interface index/name and scope; IPv6 broadcast is rejected.
  `ttl` (or `hop_limit`) defaults to 1 and `loopback` defaults to true.
  """
  @spec broadcast(broadcast_addr(), port_number(), packet(), opts()) :: :ok | {:error, term()}
  def broadcast(address, port, packet, opts \\ []) do
    operation({:send, :broadcast}, address, port, packet, nil, fn ->
      with_socket(address, port, opts, true, fn socket, destination ->
        Core.send(socket, destination, packet)
      end)
    end)
  end

  @doc "Send a broadcast/multicast datagram and collect one unicast reply."
  @spec broadcast_send_recv(broadcast_addr(), port_number(), packet(), non_neg_integer(), opts()) ::
          {:ok, binary()} | {:error, term()}
  def broadcast_send_recv(address, port, packet, timeout, opts \\ []) do
    operation({:send_recv, :broadcast_send_recv}, address, port, packet, timeout, fn ->
      request_response(address, port, packet, timeout, opts, true)
    end)
  end

  @doc """
  Subscribe on the group/broadcast port for a finite collection window.
  Multicast membership uses `membership_interface`, falling back to explicit
  `interface` or `source` for IPv4, and an explicit index/name for IPv6.
  Reception binds wildcard by default, independently of membership egress.

  All collectors default to 256 packets and 1 MiB retained bytes. Exceeding
  `max_responses` or `max_response_bytes` returns
  `{:error, {:response_limit, :count | :bytes}, partial}`. A receive error
  returns `{:error, reason, partial}`; deadline expiry returns `{:ok, packets}`.
  Empty datagrams consume one response slot. `with_metadata: true` returns peer
  tuples including actual ancillary fields, otherwise legacy binaries remain.
  `on_ready: fn {ip, port} -> ... end` runs after bind/join and before collection.
  """
  @spec subscribe_broadcast(broadcast_addr(), port_number(), non_neg_integer(), opts()) ::
          {:ok, list()} | {:error, term()} | {:error, term(), list()}
  def subscribe_broadcast(address, port, timeout, opts \\ []) do
    operation({:subscribe, :subscribe_broadcast}, address, port, nil, timeout, fn ->
      subscribe(address, port, timeout, opts)
    end)
  end

  defp subscribe(address, port, timeout, opts) do
    with :ok <- validate_collection(timeout, opts),
         {:ok, socket_opts, _destination} <- build_socket_opts(address, port, opts, true),
         {:ok, membership} <- subscription_membership(address, opts) do
      subscription_opts =
        socket_opts
        |> Enum.reject(&match?({:ip, _}, &1))
        |> Core.merge_options([{:ip, wildcard(Multicast.family(address))}, {:reuseaddr, true}])

      subscription_opts =
        if membership,
          do: subscription_opts ++ [{:add_membership, membership}],
          else: subscription_opts

      with_open_socket(port, subscription_opts, &ready_collection(&1, timeout, opts, :binary))
    end
  end

  @doc """
  Send a multicast query and collect replies with peer metadata.
  `reply_mode: :unicast` (default) uses an ephemeral socket; responders reply
  to its source port. `reply_mode: :multicast` binds `bind_port` (default group
  port) and joins the group before sending. Joining and egress selection remain
  separate: use `membership_interface` and `interface` respectively. Collection
  bounds and partial/error outcomes match `subscribe_broadcast/4`.
  """
  @spec multicast_query(broadcast_addr(), port_number(), packet(), non_neg_integer(), opts()) ::
          {:ok, list()} | {:error, term()} | {:error, term(), list()}
  def multicast_query(address, port, packet, timeout, opts \\ []) do
    operation({:send_recv, :multicast_query}, address, port, packet, timeout, fn ->
      query(address, port, packet, timeout, opts)
    end)
  end

  defp query(address, port, packet, timeout, opts) do
    with :ok <- validate_collection(timeout, opts),
         true <- Multicast.multicast_address?(address),
         {:ok, socket_opts, destination} <- build_socket_opts(address, port, opts, false),
         {:ok, bind_port, query_opts} <- query_socket(address, port, socket_opts, opts) do
      with_open_socket(
        bind_port,
        query_opts,
        &query_exchange(&1, destination, packet, timeout, opts)
      )
    else
      false -> {:error, {:invalid_multicast_group, address}}
      error -> error
    end
  end

  defp request_response(host, port, packet, timeout, opts, broadcast) do
    with :ok <- validate_timeout(timeout) do
      with_socket(host, port, opts, broadcast, fn socket, destination ->
        single_response(socket, destination, packet, timeout, opts, broadcast)
      end)
    end
  end

  defp single_response(socket, destination, packet, timeout, opts, broadcast) do
    policy =
      Keyword.get(
        opts,
        :response_policy,
        if(broadcast, do: :any, else: Core.response_policy(destination))
      )

    if policy in [:exact, :any],
      do: single_exchange(socket, destination, packet, timeout, policy),
      else: {:error, {:invalid_option, :response_policy, policy}}
  end

  defp single_exchange(socket, destination, packet, timeout, policy) do
    with {:ok, response} <- Core.exchange(socket, destination, packet, timeout, policy),
         do: {:ok, packet_data(response)}
  end

  defp ready_collection(socket, timeout, opts, shape) do
    with :ok <- ready(socket, opts), do: collect(socket, timeout, opts, shape)
  end

  defp query_exchange(socket, destination, packet, timeout, opts) do
    with :ok <- ready(socket, opts),
         :ok <- Core.send(socket, destination, packet),
         do: collect(socket, timeout, opts, :peer)
  end

  defp query_socket(address, port, socket_opts, opts) do
    case Keyword.get(opts, :reply_mode, :unicast) do
      :unicast ->
        {:ok, Keyword.get(opts, :bind_port, 0), socket_opts}

      :multicast ->
        with {:ok, membership} <- subscription_membership(address, opts) do
          query_opts =
            Enum.reject(socket_opts, &match?({:ip, _}, &1)) ++
              [
                {:ip, wildcard(Multicast.family(address))},
                {:reuseaddr, true},
                {:add_membership, membership}
              ]

          {:ok, Keyword.get(opts, :bind_port, port), query_opts}
        end

      mode ->
        {:error, {:invalid_option, :reply_mode, mode}}
    end
  end

  defp subscription_membership(address, opts) do
    if Multicast.multicast_address?(address) do
      selector =
        Keyword.get(
          opts,
          :membership_interface,
          Keyword.get(opts, :interface, Keyword.get(opts, :source, :any))
        )

      Multicast.normalize_membership({address, selector})
    else
      {:ok, nil}
    end
  end

  defp with_socket(host, port, opts, broadcast, callback) do
    with {:ok, options, destination} <- build_socket_opts(host, port, opts, broadcast) do
      with_open_socket(Keyword.get(opts, :bind_port, 0), options, &callback.(&1, destination))
    end
  end

  defp with_open_socket(port, options, callback) do
    case Core.open_socket(port, options) do
      {:ok, socket} ->
        try do
          callback.(socket)
        after
          Core.close(socket)
        end

      error ->
        error
    end
  end

  defp build_socket_opts(host, port, opts, broadcast) do
    family = Keyword.get(opts, :family, host_family(host, opts))

    with {:ok, backend} <- Core.effective_backend(opts),
         :ok <- validate_destination_port(port),
         :ok <- validate_family(family),
         {:ok, address} <- resolve_host(host, family),
         :ok <- validate_source(Keyword.get(opts, :source), family),
         {:ok, interface} <- resolve_selected_interface(opts, family),
         :ok <- validate_source_interface(opts, interface, family),
         {:ok, network_options, destination} <-
           network_options(address, port, family, interface, opts, broadcast) do
      options =
        [family, :binary, {:active, false}, {:buffer, 65_536}, {:recbuf, 262_144}] ++
          network_options

      options = if opts[:source], do: options ++ [{:ip, opts[:source]}], else: options

      options = [{:inet_backend, backend} | options]

      with :ok <- validate_destination_backend(destination, backend),
           {:ok, normalized} <- Core.normalize_options([], options),
           do: {:ok, normalized, destination}
    end
  end

  defp validate_destination_backend(%{family: :inet6, scope_id: _}, backend) do
    if backend == :socket,
      do: {:error, {:unsupported_capability, :scoped_sockaddr_send, :socket}},
      else: :ok
  end

  defp validate_destination_backend(_, _), do: :ok

  defp host_family(host, opts) do
    case Multicast.family(host) do
      :invalid -> if Multicast.family(opts[:source]) == :inet6, do: :inet6, else: :inet
      family -> family
    end
  end

  defp validate_family(family) when family in [:inet, :inet6], do: :ok
  defp validate_family(value), do: {:error, {:invalid_option, :family, value}}
  defp validate_destination_port(port) when is_integer(port) and port in 0..65_535, do: :ok
  defp validate_destination_port(port), do: {:error, {:invalid_port, port}}

  defp resolve_host(host, family) when is_tuple(host) do
    if Multicast.family(host) == family,
      do: {:ok, host},
      else: {:error, {:address_family_mismatch, host, family}}
  end

  defp resolve_host(host, family) when is_binary(host),
    do: :inet.getaddr(String.to_charlist(host), family)

  defp resolve_host(host, family) when is_list(host), do: :inet.getaddr(host, family)
  defp resolve_host(host, _), do: {:error, {:invalid_address, host}}
  defp validate_source(nil, _), do: :ok

  defp validate_source(source, family) do
    if Multicast.family(source) == family,
      do: :ok,
      else: {:error, {:invalid_option, :source, :family_mismatch}}
  end

  defp resolve_selected_interface(opts, family) do
    case Keyword.fetch(opts, :interface) do
      {:ok, selector} -> Multicast.resolve_interface(selector, family)
      :error -> {:ok, if(family == :inet, do: opts[:source], else: nil)}
    end
  end

  defp validate_source_interface(opts, interface, :inet) do
    if opts[:source] && interface && opts[:source] != interface,
      do: {:error, {:invalid_option, :source, :interface_mismatch}},
      else: :ok
  end

  defp validate_source_interface(_opts, _interface, :inet6), do: :ok

  defp network_options(address, port, family, interface, opts, broadcast) do
    if Multicast.multicast_address?(address),
      do: multicast_options(address, port, family, interface, opts),
      else: non_multicast_options(address, port, family, opts, broadcast)
  end

  defp non_multicast_options(_address, _port, :inet6, _opts, true),
    do: {:error, {:invalid_option, :broadcast, :ipv6}}

  defp non_multicast_options(address, port, family, opts, broadcast) do
    with {:ok, device_options} <- device_binding(opts, family) do
      options = if broadcast, do: [{:broadcast, true} | device_options], else: device_options
      {:ok, options, {address, port}}
    end
  end

  defp multicast_options(address, port, family, interface, opts) do
    ttl = Keyword.get(opts, :hop_limit, Keyword.get(opts, :ttl, 1))
    loopback = Keyword.get(opts, :loopback, true)
    scope = Keyword.get(opts, :scope_id, interface)

    with :ok <- validate_ttl(ttl),
         :ok <- validate_loopback(loopback),
         :ok <- validate_scope(family, scope, interface) do
      egress = if family == :inet6, do: scope, else: interface
      options = [multicast_ttl: ttl, multicast_loop: loopback]
      options = if egress, do: options ++ [{:multicast_if, egress}], else: options
      destination = multicast_destination(address, port, family, scope)
      {:ok, options, destination}
    end
  end

  defp multicast_destination(address, port, :inet6, scope),
    do: %{family: :inet6, addr: address, port: port, scope_id: scope}

  defp multicast_destination(address, port, :inet, _scope), do: {address, port}
  defp validate_ttl(ttl) when is_integer(ttl) and ttl in 0..255, do: :ok
  defp validate_ttl(ttl), do: {:error, {:invalid_option, :ttl, ttl}}
  defp validate_loopback(value) when is_boolean(value), do: :ok
  defp validate_loopback(value), do: {:error, {:invalid_option, :loopback, value}}
  defp validate_scope(:inet, _, _), do: :ok

  defp validate_scope(:inet6, scope, _interface) when not is_integer(scope) or scope <= 0,
    do: {:error, {:invalid_option, :scope_id, :required}}

  defp validate_scope(:inet6, scope, interface) when not is_nil(interface) and scope != interface,
    do: {:error, {:invalid_option, :scope_id, :interface_mismatch}}

  defp validate_scope(:inet6, scope, _) do
    case Multicast.resolve_interface(scope, :inet6) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp device_binding(opts, _family) do
    case opts[:interface] do
      nil ->
        {:ok, []}

      name when is_binary(name) or is_list(name) ->
        if match?({:unix, :linux}, :os.type()),
          do: {:ok, [{:bind_to_device, IO.chardata_to_string(name)}]},
          else: {:error, :explicit_device_binding_not_supported}

      selector ->
        {:error, {:invalid_option, :interface, selector}}
    end
  end

  defp wildcard(:inet6), do: {0, 0, 0, 0, 0, 0, 0, 0}
  defp wildcard(_), do: {0, 0, 0, 0}

  defp ready(socket, opts) do
    case Keyword.get(opts, :on_ready) do
      nil ->
        :ok

      callback when is_function(callback, 1) ->
        with {:ok, endpoint} <- Core.sockname(socket) do
          callback.(endpoint)
          :ok
        end

      value ->
        {:error, {:invalid_option, :on_ready, value}}
    end
  end

  defp validate_timeout(timeout) when is_integer(timeout) and timeout >= 0, do: :ok
  defp validate_timeout(timeout), do: {:error, {:invalid_option, :timeout, timeout}}

  defp validate_collection(timeout, opts) do
    with :ok <- validate_timeout(timeout),
         :ok <- validate_limit(:max_responses, Keyword.get(opts, :max_responses, 256)),
         do:
           validate_limit(:max_response_bytes, Keyword.get(opts, :max_response_bytes, 1_048_576))
  end

  defp validate_limit(_key, value) when is_integer(value) and value > 0, do: :ok
  defp validate_limit(key, value), do: {:error, {:invalid_option, key, value}}

  defp collect(socket, timeout, opts, shape) do
    deadline = System.monotonic_time(:millisecond) + timeout
    shape = if Keyword.get(opts, :with_metadata, false), do: :peer, else: shape

    limits =
      {Keyword.get(opts, :max_responses, 256), Keyword.get(opts, :max_response_bytes, 1_048_576)}

    do_collect(socket, deadline, limits, shape, [], 0, 0)
  end

  defp do_collect(socket, deadline, limits, shape, acc, count, bytes) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0,
      do: {:ok, Enum.reverse(acc)},
      else: receive_collection(socket, remaining, {deadline, limits, shape, acc, count, bytes})
  end

  defp receive_collection(
         socket,
         remaining,
         {_deadline, _limits, _shape, acc, _count, _bytes} = context
       ) do
    case receive_packet(socket, remaining) do
      {:ok, response} -> retain_response(socket, response, context)
      {:error, :timeout} -> {:ok, Enum.reverse(acc)}
      {:error, reason} -> {:error, reason, Enum.reverse(acc)}
    end
  end

  defp retain_response(
         socket,
         response,
         {deadline, {max_count, max_bytes} = limits, shape, acc, count, bytes}
       ) do
    size = byte_size(packet_data(response))

    cond do
      count >= max_count ->
        {:error, {:response_limit, :count}, Enum.reverse(acc)}

      bytes + size > max_bytes ->
        {:error, {:response_limit, :bytes}, Enum.reverse(acc)}

      true ->
        value = if shape == :peer, do: response, else: packet_data(response)
        do_collect(socket, deadline, limits, shape, [value | acc], count + 1, bytes + size)
    end
  end

  defp receive_packet(socket, timeout) do
    case Core.recv(socket, 0, timeout) do
      {:ok, {_, _, data} = response} when is_binary(data) ->
        {:ok, response}

      {:ok, {_, _, ancillary, data} = response} when is_list(ancillary) and is_binary(data) ->
        {:ok, response}

      {:error, _} = error ->
        error

      other ->
        {:error, {:unexpected_datagram, other}}
    end
  end

  defp packet_data({_, _, data}), do: data
  defp packet_data({_, _, _, data}), do: data

  @doc "Resolve an explicitly selected interface to a local IPv4 address."
  @spec resolve_interface_ip(String.t()) :: {:ok, :inet.ip4_address()} | {:error, term()}
  def resolve_interface_ip(interface), do: Multicast.resolve_interface(interface, :inet)

  defp operation(event, host, port, packet, timeout, callback) do
    {kind, type} =
      case event do
        {kind, type} -> {kind, type}
        :send -> {:send, :unicast}
        :send_recv -> {:send_recv, :request_response}
      end

    metadata = %{host: host, port: port, type: type}
    metadata = if packet, do: Map.put(metadata, :size, byte_size(packet)), else: metadata
    metadata = if timeout, do: Map.put(metadata, :timeout, timeout), else: metadata
    start = System.monotonic_time()
    :telemetry.execute([:abyss, :client, kind, :start], %{}, metadata)
    result = callback.()
    measurements = %{duration: System.monotonic_time() - start}

    case result do
      {:error, reason} ->
        :telemetry.execute(
          [:abyss, :client, kind, :exception],
          measurements,
          Map.put(metadata, :reason, reason)
        )

      {:error, reason, _partial} ->
        :telemetry.execute(
          [:abyss, :client, kind, :exception],
          measurements,
          Map.put(metadata, :reason, reason)
        )

      _ ->
        :telemetry.execute(
          [:abyss, :client, kind, :stop],
          response_measurements(measurements, result),
          metadata
        )
    end

    result
  end

  defp response_measurements(measurements, {:ok, data}) when is_binary(data),
    do: Map.put(measurements, :response_size, byte_size(data))

  defp response_measurements(measurements, {:ok, responses}) when is_list(responses) do
    size =
      Enum.reduce(responses, 0, fn
        response, acc when is_binary(response) -> acc + byte_size(response)
        response, acc -> acc + byte_size(packet_data(response))
      end)

    Map.merge(measurements, %{
      packet_count: length(responses),
      response_count: length(responses),
      total_size: size
    })
  end

  defp response_measurements(measurements, _), do: measurements
end
