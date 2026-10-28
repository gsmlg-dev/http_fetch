defmodule SSL.Lifecycle.ResourceLedger do
  @moduledoc false

  # Pure bookkeeping, not a public receipt. The runtime establishes real monitors,
  # gates allocation/use, seals evidence and observes the observer's exit.
  import Bitwise

  @roles %{allocator: 1, setup: 2, connection: 4, writer: 8, tcp: 16}
  @derive {Inspect, only: [:scope, :admission, :losses]}
  defstruct scope: :dial, admission: :open, resources: %{}, permits: %{}, losses: 0, rejected: 0

  @type role :: :allocator | :setup | :connection | :writer | :tcp
  @type identity ::
          {reference(), :process, pid()}
          | {reference(), :port, port()}
          | {reference(), :socket, :socket.socket()}
  @type creator :: :observer | {role(), reference()}
  @type scope :: :dial | :upgrade | :layer
  @type role_mask :: 0..31
  @type snapshot :: %{
          scope: scope(),
          admission: :open | :closed,
          roles: role_mask(),
          observed_down: role_mask(),
          allocations: role_mask(),
          losses: role_mask()
        }
  @type proof :: %{
          scope: scope(),
          roles: role_mask(),
          observed_down: role_mask(),
          losses: role_mask(),
          cleanup: :confirmed | :unconfirmed
        }
  @type enrollment :: %{identity: identity(), state: :live | :down, creator: creator()}
  @opaque t :: %__MODULE__{}

  @spec enrollment_view(t(), role()) :: {:ok, enrollment()} | :error
  def enrollment_view(%__MODULE__{} = ledger, role), do: Map.fetch(ledger.resources, role)

  @spec new(scope()) :: t()
  def new(scope \\ :dial) when scope in [:dial, :upgrade, :layer],
    do: %__MODULE__{scope: scope}

  @spec reserve(t(), role(), creator(), reference()) :: {:ok, t()} | {:error, atom()}
  def reserve(%__MODULE__{} = ledger, role, creator, token) when is_reference(token) do
    cond do
      not Map.has_key?(@roles, role) -> {:error, :invalid_role}
      ledger.scope == :layer and role in [:allocator, :tcp] -> {:error, :role_outside_scope}
      ledger.admission != :open -> {:error, :admission_closed}
      occupied?(ledger, role) -> {:error, :role_used}
      not creator_live?(ledger, creator) -> {:error, :creator_not_observed}
      true -> {:ok, %{ledger | permits: Map.put(ledger.permits, role, {token, creator})}}
    end
  end

  # Only the runtime's authenticated pre-TLS candidate transition uses this.
  # Keep the old exact DOWN until replacement enrollment, so a creator lost
  # between reserve and birth cannot erase either historical proof or its permit.
  @spec rollover_tcp(t(), identity(), creator(), reference()) ::
          {:ok, t()} | {:error, atom()}
  def rollover_tcp(ledger, identity, {:allocator, ref} = creator, token)
      when is_reference(ref) and is_reference(token) do
    with :dial <- ledger.scope,
         :open <- ledger.admission,
         0 <- ledger.losses,
         false <- Map.has_key?(ledger.permits, :tcp),
         true <- creator_live?(ledger, creator),
         %{identity: ^identity, creator: ^creator, state: :down} <- ledger.resources[:tcp] do
      {:ok, %{ledger | permits: Map.put(ledger.permits, :tcp, {token, creator})}}
    else
      _ -> {:error, :rollover_not_permitted}
    end
  end

  def rollover_tcp(_ledger, _identity, _creator, _token), do: {:error, :rollover_not_permitted}

  @spec enroll(t(), role(), reference(), identity()) ::
          {:ok, t(), :use | :stop} | {:error, atom()}
  def enroll(%__MODULE__{} = ledger, role, token, identity) do
    case Map.fetch(ledger.permits, role) do
      {:ok, {^token, creator}} -> register(ledger, role, identity, creator)
      _ -> {:error, :unknown_permit}
    end
  end

  # Trusted provider assertion: the constructor rejected before entering native
  # allocation and cannot allocate later. A connect error, timeout or creator DOWN
  # is never this event. The observer authenticates the actual caller/attempt.
  @spec reject_before_native(t(), role(), reference(), creator()) ::
          {:ok, t()} | {:error, atom()}
  def reject_before_native(%__MODULE__{} = ledger, role, token, creator) do
    case Map.fetch(ledger.permits, role) do
      {:ok, {^token, ^creator}} -> reject_reserved(ledger, role, creator)
      {:ok, {^token, _other}} -> {:error, :unauthorized_creator}
      _ -> {:error, :unknown_permit}
    end
  end

  defp reject_reserved(ledger, role, creator) do
    cond do
      not creator_live?(ledger, creator) ->
        {:error, :creator_not_observed}

      (ledger.losses &&& Map.fetch!(@roles, role)) != 0 ->
        {:error, :allocation_evidence_lost}

      true ->
        {:ok,
         %{
           ledger
           | permits: Map.delete(ledger.permits, role),
             rejected: ledger.rejected ||| Map.fetch!(@roles, role)
         }}
    end
  end

  # Adoption covers an existing owned port, not its creation. Ownership checking
  # and monitor establishment precede this event in the runtime.
  @spec adopt_tcp(t(), identity()) :: {:ok, t(), :use | :stop} | {:error, atom()}
  def adopt_tcp(%__MODULE__{scope: :upgrade, admission: :open} = ledger, identity) do
    if occupied?(ledger, :tcp),
      do: {:error, :role_used},
      else: register(ledger, :tcp, identity, :observer)
  end

  def adopt_tcp(%__MODULE__{}, _identity), do: {:error, :adoption_not_permitted}

  @spec close_admission(t()) :: t()
  def close_admission(%__MODULE__{} = ledger), do: %{ledger | admission: :closed}

  @spec down(t(), {:DOWN, reference(), :process | :port | :socket, term(), term()}) :: t()
  def down(%__MODULE__{} = ledger, {:DOWN, ref, type, object, _reason}) do
    case Enum.find(ledger.resources, fn {_role, resource} ->
           resource.identity == {ref, type, object} and resource.state == :live
         end) do
      nil -> ledger
      {role, resource} -> record_down(ledger, role, resource, ref)
    end
  end

  @spec snapshot(t()) :: snapshot()
  def snapshot(%__MODULE__{} = ledger) do
    %{
      scope: ledger.scope,
      admission: ledger.admission,
      roles: mask(Map.keys(ledger.resources)),
      observed_down: down_mask(ledger),
      allocations: mask(Map.keys(ledger.permits)),
      losses: ledger.losses
    }
  end

  # Count enrolled live identities, never the historical role masks. Outstanding
  # constructors and lost evidence make a complete numerical census unavailable.
  @spec resource_counts(t()) :: map() | nil
  def resource_counts(%__MODULE__{losses: 0, permits: permits} = ledger)
      when map_size(permits) == 0 do
    live = Enum.filter(ledger.resources, fn {_, record} -> record.state == :live end)
    processes = identities(live, fn {_, {_, kind, _}} -> kind == :process end)
    sockets = identities(live, fn {_, {_, kind, _}} -> kind in [:port, :socket] end)
    data = identities(live, fn {role, _} -> role in [:connection, :writer, :tcp] end)

    %{
      processes: MapSet.size(processes),
      tcp_sockets: MapSet.size(sockets),
      observers: 0,
      data_resources: MapSet.size(data)
    }
  end

  def resource_counts(%__MODULE__{}), do: nil

  defp identities(records, predicate) do
    for {role, %{identity: identity}} <- records,
        predicate.({role, identity}),
        into: MapSet.new(),
        do: {elem(identity, 1), elem(identity, 2)}
  end

  # This bounded proof fragment excludes setup/authority and observer termination.
  # Known resources still need matching DOWN after unknown allocation causes loss.
  @spec proof(t()) :: {:pending, snapshot()} | {:ok, proof()}
  def proof(%__MODULE__{} = ledger) do
    snapshot = snapshot(ledger)

    if ledger.admission == :closed and map_size(ledger.permits) == 0 and
         snapshot.roles == snapshot.observed_down do
      {:ok,
       %{
         scope: ledger.scope,
         roles: snapshot.roles,
         observed_down: snapshot.observed_down,
         losses: ledger.losses,
         cleanup: if(ledger.losses == 0, do: :confirmed, else: :unconfirmed)
       }}
    else
      {:pending, snapshot}
    end
  end

  defp register(ledger, role, identity, creator) do
    cond do
      not valid_identity?(ledger.scope, role, identity) ->
        {:error, :invalid_monitor_identity}

      duplicate_monitor?(ledger, identity) ->
        {:error, :monitor_used}

      true ->
        resource = %{identity: identity, state: :live, creator: creator}

        next = %{
          ledger
          | permits: Map.delete(ledger.permits, role),
            resources: Map.put(ledger.resources, role, resource)
        }

        use? = ledger.admission == :open and (ledger.losses &&& Map.fetch!(@roles, role)) == 0
        {:ok, next, if(use?, do: :use, else: :stop)}
    end
  end

  defp record_down(ledger, role, resource, ref) do
    lost =
      Enum.filter(ledger.permits, fn {_child, {_token, creator}} ->
        creator == {role, ref}
      end)

    # Keep the bounded permit tombstone: a delayed identity must still enroll,
    # stop and contribute its exact DOWN. No identity means no settled proof.
    %{
      ledger
      | resources: Map.put(ledger.resources, role, %{resource | state: :down}),
        losses: ledger.losses ||| mask(Enum.map(lost, &elem(&1, 0)))
    }
  end

  defp occupied?(ledger, role),
    do:
      Map.has_key?(ledger.resources, role) or Map.has_key?(ledger.permits, role) or
        ((ledger.losses ||| ledger.rejected) &&& Map.fetch!(@roles, role)) != 0

  defp creator_live?(_ledger, :observer), do: true

  defp creator_live?(ledger, {role, ref}) do
    case Map.get(ledger.resources, role) do
      %{identity: {^ref, :process, _pid}, state: :live} -> true
      _ -> false
    end
  end

  defp creator_live?(_ledger, _creator), do: false

  defp valid_identity?(_scope, :tcp, {ref, :port, object}),
    do: is_reference(ref) and is_port(object)

  # The runtime validates the opaque socket and establishes its real monitor.
  # Restrict this new identity kind to dial; existing-socket adoption stays Port-only.
  defp valid_identity?(:dial, :tcp, {ref, :socket, _socket}), do: is_reference(ref)

  defp valid_identity?(_scope, role, {ref, :process, object})
       when role in [:allocator, :setup, :connection, :writer],
       do: is_reference(ref) and is_pid(object)

  defp valid_identity?(_scope, _role, _identity), do: false

  defp duplicate_monitor?(ledger, {ref, _type, _object}) do
    Enum.any?(ledger.resources, fn {_role, resource} -> elem(resource.identity, 0) == ref end)
  end

  defp down_mask(ledger) do
    ledger.resources
    |> Enum.filter(fn {role, resource} ->
      resource.state == :down and not Map.has_key?(ledger.permits, role)
    end)
    |> Enum.map(&elem(&1, 0))
    |> mask()
  end

  defp mask(roles),
    do: Enum.reduce(roles, 0, fn role, bits -> bits ||| Map.fetch!(@roles, role) end)
end
