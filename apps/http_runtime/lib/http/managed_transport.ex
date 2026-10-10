defmodule HTTP.ManagedTransport do
  @moduledoc """
  Owns one bounded transport generation for a fixed origin and literal address.

  `open/1` freezes direct TCP/OTP TLS policy and creates private connection pools.
  Pass the opaque scope as `transport_scope` to raw, streamed Fetch requests with
  manual/error redirects. Request and connection capacity fail immediately;
  request leases last through unread response streams.

  `retire/2` closes admission and idle connections. Graceful retirement permits
  admitted requests to finish; abort retirement also cancels them. Its durable
  receipt can be awaited repeatedly from any process. `:ok` proves termination
  of this generation's independently monitored requests, connectors, raw socket
  ports, owners, private pools, supervisor and coordinator. A finite wait can
  return `:cleanup_pending`; lost evidence returns `:cleanup_unconfirmed`.
  Creator death initiates abort retirement. No request is replayed.

  ## Opening and selecting a generation

      {:ok, scope} = HTTP.ManagedTransport.open(
        origin: "https://upstream.example",
        connect_address: {192, 0, 2, 10},
        http_version: :http2,
        max_requests: 100,
        max_connections: 2,
        idle_timeout: 30_000
      )

      promise = HTTP.fetch("https://upstream.example/data",
        transport_scope: scope,
        redirect: :manual,
        decode_body: false,
        stream_response: true
      )

  `origin`, literal `connect_address` and explicit `http_version` are required.
  Supported protocols are `:http1` (HTTP/HTTPS), `:http2` (HTTPS) and `:h2c`
  (HTTP). Optional capacity is `max_requests: 1..2048` (default 100),
  `max_connections: 1..256` (default 2), `max_pending: 0`, and
  `idle_timeout: 1..60000` milliseconds (default 30000). `ssl` and `socket_opts`
  freeze supported OTP TLS/socket settings. Only `tls_backend: :ssl` and
  `http2_profile: :native_v1` are accepted. TLS files and system CAs are captured
  once at open; rotated policy requires a new scope.

  Request capacity includes preparation and unread streams. Connections include
  connecting, checked-out and idle transports. Exhaustion returns
  `{:error, {:transport_scope_capacity, :requests | :connections}}`, with no
  waiting queue. Frozen TLS/socket policy owns compact binary backing within its
  1 MiB serialized limit. Freeze/preparation copy overlap and OTP's parsed TLS
  state are outside that retained-policy payload bound. Request metadata is
  bounded to 64 KiB/256 fields,
  buffered upload bodies to 1 MiB, and upload chunks/bridges to 64 KiB. The native
  HTTP/2 writer/receive budgets are 1 MiB each per connection, header blocks are
  bounded to 64 KiB/256 fields/256 frames. The H2 owner admits at most 128
  informational heads/64 KiB regular metadata over each request lifetime, before
  enqueueing. Each request generates at most 130 header notifications including
  final headers/trailers. SETTINGS pool snapshots coalesce with one in flight;
  GOAWAY draining notices are one-shot. See the managed transport guide for
  accounted-data, representation and decode/copy overlap reservations.
  Caller-owned producer input, arbitrary
  public-operation messages, OS/TLS allocations and the whole VM are outside
  these retained transport bounds.

  Conflicting origin, route, TLS or socket overrides fail before dialing. Each
  request/connect deadline remains independent; socket writer settings stay
  frozen. Managed upload attachment and admission use the request deadline.
  An unresponsive caller source receives cooperative stop but keeps cleanup
  pending and its slot occupied until the caller terminates it.

  ## Status and retirement

      {:ok, status} = HTTP.ManagedTransport.snapshot(scope, 100)
      {:ok, receipt} = HTTP.ManagedTransport.retire(scope, mode: :graceful)
      :ok = HTTP.ManagedTransport.await_retired(receipt, 1_000)

  Snapshot and receipt waits require finite, nonnegative millisecond timeouts.
  Snapshots contain aggregate counts, finite limits, policy digest and lifecycle,
  without request history or credentials. Retirement closes admission and idle
  sockets immediately; `:graceful` drains live requests, while `:abort` requests
  cancellation. Neither a response terminal event nor an individual
  `HTTP.RequestCompletion` proves whole-generation retirement. A caller may retry
  receipt waits after `{:error, :cleanup_pending}`. Lost evidence produces
  `{:error, :cleanup_unconfirmed}`. Normal coordinator termination preserves the
  durable receipt; unexpected coordinator death cannot report success.
  """
  alias HTTP.ManagedTransport.{Policy, Scope}

  @opaque t :: %__MODULE__{coordinator: pid(), latch: reference(), identity: binary()}
  defstruct [:coordinator, :latch, :identity, :ingress, :configuration, :gate, :max_requests]

  defmodule Receipt do
    @moduledoc """
    Opaque durable retirement receipt returned by `HTTP.ManagedTransport.retire/2`.

    Pass it to `HTTP.ManagedTransport.await_retired/2` for repeated or concurrent
    finite waits, including after the generation coordinator has terminated.
    """
    @opaque t :: %__MODULE__{coordinator: pid(), latch: reference()}
    defstruct [:coordinator, :latch]
  end

  @spec open(keyword()) :: {:ok, t()} | {:error, term()}
  def open(opts) do
    with {:ok, policy} <- Policy.freeze(opts) do
      latch = :atomics.new(1, [])
      :atomics.put(latch, 1, 1)

      child = %{
        id: Scope,
        start: {Scope, :start_link, [[policy: policy, latch: latch, creator: self()]]},
        restart: :temporary
      }

      case DynamicSupervisor.start_child(:http_managed_transport_supervisor, child) do
        {:ok, pid} ->
          handle = GenServer.call(pid, :handle)

          {:ok,
           struct!(__MODULE__, Map.merge(handle, %{latch: latch, identity: policy.identity}))}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @spec snapshot(t(), non_neg_integer()) :: {:ok, map()} | {:error, term()}
  def snapshot(%__MODULE__{} = scope, timeout) when is_integer(timeout) and timeout >= 0,
    do: call(scope.coordinator, :snapshot, timeout)

  @spec retire(t(), keyword()) :: {:ok, Receipt.t()} | {:error, term()}
  def retire(%__MODULE__{} = scope, opts \\ []) do
    mode = Keyword.get(opts, :mode, :graceful)

    if mode in [:graceful, :abort] do
      receipt = %Receipt{coordinator: scope.coordinator, latch: scope.latch}

      case :atomics.get(scope.latch, 1) do
        2 ->
          {:ok, receipt}

        _ ->
          retire_call(scope, receipt, mode)
      end
    else
      {:error, :invalid_transport_scope_retirement}
    end
  end

  defp retire_call(scope, receipt, mode) do
    case call(scope.coordinator, {:retire, mode}, 5_000) do
      :ok -> {:ok, receipt}
      error -> if :atomics.get(scope.latch, 1) == 2, do: {:ok, receipt}, else: error
    end
  end

  @spec await_retired(Receipt.t(), non_neg_integer()) :: :ok | {:error, term()}
  def await_retired(%Receipt{} = receipt, timeout) when is_integer(timeout) and timeout >= 0 do
    monitor = Process.monitor(receipt.coordinator)

    try do
      wait(receipt, monitor, System.monotonic_time(:millisecond) + timeout)
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp wait(receipt, monitor, deadline) do
    case :atomics.get(receipt.latch, 1) do
      2 ->
        if Process.alive?(receipt.coordinator),
          do: wait_down(receipt, monitor, deadline),
          else: :ok

      3 ->
        {:error, :cleanup_unconfirmed}

      _ ->
        if Process.alive?(receipt.coordinator),
          do: wait_down(receipt, monitor, deadline),
          else: terminal_result(receipt)
    end
  end

  defp terminal_result(receipt) do
    if :atomics.get(receipt.latch, 1) == 2, do: :ok, else: {:error, :cleanup_unconfirmed}
  end

  defp wait_down(receipt, monitor, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    if remaining == 0 do
      {:error, :cleanup_pending}
    else
      receive do
        {:DOWN, ^monitor, :process, _, _} -> wait(receipt, monitor, deadline)
      after
        min(remaining, 10) -> wait(receipt, monitor, deadline)
      end
    end
  end

  @doc false
  def prepare(request, supplied) do
    case Keyword.get(request.transport_options, :transport_scope) do
      nil ->
        {:ok, request}

      %__MODULE__{} = scope ->
        with {:ok, lease} <- claim(scope) do
          [{:policy, policy, injection}] = :ets.lookup(scope.configuration, :policy)

          case Policy.prepare(policy, request, supplied) do
            {:ok, request} ->
              deadline =
                System.monotonic_time(:millisecond) +
                  Keyword.get(request.transport_options, :timeout, 30_000)

              injection =
                [managed_admission_lease: lease, managed_deadline_at: deadline] ++ injection

              {:ok,
               %{request | transport_options: Keyword.merge(request.transport_options, injection)}}

            error ->
              cancel_lease(scope, lease)
              error
          end
        end

      _ ->
        {:error, :invalid_transport_scope}
    end
  rescue
    ArgumentError -> {:error, :transport_scope_retired}
  end

  @doc false
  def associate(request, tracker) do
    case request.transport_options[:managed_admission_lease] do
      nil ->
        :ok

      {id, token} ->
        scope = request.transport_options[:transport_scope]

        replaced =
          :ets.select_replace(
            scope.ingress,
            [
              {{id, token, :"$1", :preparing, nil}, [],
               [{{id, token, :"$1", :reserved, tracker}}]}
            ]
          )

        if replaced == 1, do: :ok, else: {:error, :transport_scope_retired}
    end
  rescue
    ArgumentError -> {:error, :transport_scope_retired}
  end

  @doc false
  def admit(request, tracker) do
    case Keyword.get(request.transport_options, :managed_admission_lease) do
      nil ->
        :ok

      {id, token} = lease ->
        scope = request.transport_options[:transport_scope]
        deadline = request.transport_options[:managed_deadline_at]

        case HTTP.RequestLifecycle.bind_scope(tracker, scope.coordinator, deadline) do
          :ok ->
            replaced =
              :ets.select_replace(
                scope.ingress,
                [
                  {{id, token, :_, :reserved, tracker}, [],
                   [{:const, {id, token, self(), :awaiting, tracker}}]}
                ]
              )

            if replaced == 1,
              do:
                await_admission(
                  scope,
                  lease,
                  deadline,
                  tracker
                ),
              else: {:error, :transport_scope_retired}

          error ->
            cancel_lease(scope, lease)
            error
        end
    end
  rescue
    ArgumentError -> {:error, :transport_scope_retired}
  end

  defp claim(scope) do
    if :atomics.get(scope.gate, 1) == 1 do
      token = make_ref()

      id =
        Enum.find(1..scope.max_requests, fn id ->
          :ets.select_replace(
            scope.ingress,
            [{{id, nil, nil, :free, nil}, [], [{:const, {id, token, self(), :preparing, nil}}]}]
          ) == 1
        end)

      if id, do: {:ok, {id, token}}, else: {:error, {:transport_scope_capacity, :requests}}
    else
      {:error, :transport_scope_retired}
    end
  end

  defp await_admission(scope, {id, token} = lease, deadline, tracker) do
    cond do
      System.monotonic_time(:millisecond) >= deadline ->
        cancel_lease(scope, lease)
        {:error, :request_timeout}

      :ets.lookup(scope.ingress, id) == [{id, token, self(), :active, tracker}] ->
        :ok

      :atomics.get(scope.gate, 1) != 1 ->
        cancel_lease(scope, lease)
        {:error, :transport_scope_retired}

      true ->
        receive do
          :abort ->
            cancel_lease(scope, lease)
            {:error, :aborted}
        after
          min(max(deadline - System.monotonic_time(:millisecond), 0), 5) ->
            await_admission(scope, lease, deadline, tracker)
        end
    end
  end

  defp cancel_lease(scope, {id, token}) do
    :ets.select_replace(
      scope.ingress,
      [
        {{id, token, :"$1", :"$2", :"$3"}, [{:"/=", :"$2", :canceling}],
         [{{id, token, :"$1", :canceled, :"$3"}}]}
      ]
    )

    :ok
  end

  @doc false
  def connect_start(request) do
    case Keyword.get(request.transport_options, :managed_coordinator) do
      nil ->
        {:ok, nil}

      coordinator ->
        deadline = request.transport_options[:managed_deadline_at]

        with {:ok, token} <-
               deadline_call(
                 coordinator,
                 {:connect_start, HTTP.RequestLifecycle.current()},
                 deadline
               ),
             :ok <-
               HTTP.RequestLifecycle.bind_connector(
                 HTTP.RequestLifecycle.current(),
                 token,
                 deadline
               ),
             do: {:ok, token}
    end
  end

  @doc false
  def connect_done(_request, nil), do: :ok

  def connect_done(request, token),
    do: GenServer.cast(request.transport_options[:managed_coordinator], {:connect_done, token})

  defp deadline_call(pid, message, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining > 0,
      do: GenServer.call(pid, message, remaining),
      else: {:error, :request_timeout}
  catch
    :exit, {:timeout, _} -> {:error, :request_timeout}
    :exit, _ -> {:error, :transport_scope_retired}
  end

  defp call(pid, message, timeout) do
    GenServer.call(pid, message, timeout)
  catch
    :exit, {:timeout, _} -> {:error, :cleanup_pending}
    :exit, _ -> {:error, :transport_scope_retired}
  end
end
