defmodule SSL.Lifecycle.AuxiliaryLedger do
  @moduledoc false

  # Pure evidence reducer. The Observer authenticates the attempt, creator,
  # permit, real monitor and every native-completion assertion before calling.
  # A reducer :use result is not itself a runtime capability.
  import Bitwise

  @roles %{http_socket: 1, file_executor: 2}
  @limits %{http_socket: 32, file_executor: 256}
  @native_loss 4
  @derive {Inspect, only: [:admission, :losses]}
  defstruct admission: :open,
            generation: 0,
            counts: %{http_socket: 0, file_executor: 0},
            current: nil,
            roles: 0,
            observed_down: 0,
            losses: 0

  @type kind :: :http_socket | :file_executor
  @type creator :: {reference(), :process, pid()}
  @type identity :: {reference(), :socket, term()} | {reference(), :process, pid()}
  @type generation :: 1..288
  @type snapshot :: %{
          admission: :open | :closed,
          roles: 0..3,
          observed_down: 0..3,
          allocations: 0..3,
          native_operation: :idle | :pending,
          handle_close: :not_required | :pending | :completed,
          resource_state: :none | :open | :closed | :unknown,
          losses: 0..7
        }
  @type proof :: %{
          roles: 0..3,
          observed_down: 0..3,
          losses: 0..7,
          cleanup: :confirmed | :unconfirmed
        }
  @opaque t :: %__MODULE__{}

  @spec new() :: t()
  def new, do: %__MODULE__{}

  @spec admitted?(t()) :: boolean()
  def admitted?(%__MODULE__{generation: generation}), do: generation != 0

  @spec reserve(t(), kind(), creator(), reference()) ::
          {:ok, t(), generation()} | {:error, atom()}
  def reserve(%__MODULE__{} = ledger, kind, creator, token) do
    cond do
      not Map.has_key?(@roles, kind) -> {:error, :invalid_kind}
      not valid_creator?(creator) or not is_reference(token) -> {:error, :invalid_reservation}
      ledger.admission != :open -> {:error, :admission_closed}
      ledger.losses != 0 -> {:error, :evidence_lost}
      not discharged?(ledger.current) -> {:error, :auxiliary_busy}
      ledger.counts[kind] == @limits[kind] -> {:error, :auxiliary_limit}
      true -> reserve_next(ledger, kind, creator, token)
    end
  end

  @spec enroll(t(), generation(), reference(), identity()) ::
          {:ok, t(), :use | :stop} | {:error, atom()}
  def enroll(%__MODULE__{} = ledger, generation, token, identity) do
    with %{generation: ^generation, token: ^token, state: :reserved} = current <- ledger.current,
         true <- valid_identity?(current.kind, identity) do
      current = %{current | identity: identity, state: :live}

      ledger = %{
        ledger
        | current: current,
          roles: ledger.roles ||| @roles[current.kind],
          observed_down: ledger.observed_down &&& bnot(@roles[current.kind])
      }

      action = if ledger.admission == :open and ledger.losses == 0, do: :use, else: :stop
      {:ok, ledger, action}
    else
      false -> {:error, :invalid_monitor_identity}
      _ -> {:error, :unknown_permit}
    end
  end

  # Only a trusted pre-native rejection discharges an unobserved birth. The
  # runtime must prove that the constructor cannot allocate after this event.
  @spec reject_before_native(t(), generation(), reference(), creator() | :observer) ::
          {:ok, t()} | {:error, atom()}
  def reject_before_native(%__MODULE__{} = ledger, generation, token, creator) do
    case ledger.current do
      %{generation: ^generation, token: ^token, creator: ^creator, state: :reserved} = current
      when ledger.losses == 0 ->
        {:ok, %{ledger | current: %{current | state: :rejected, operation: nil}}}

      _ ->
        {:error, :rejection_not_permitted}
    end
  end

  @spec close_admission(t()) :: t()
  def close_admission(%__MODULE__{} = ledger), do: %{ledger | admission: :closed}

  # Connection is requester only for files: its loss stops use, not the
  # independent executor's native witness. HTTP creator-loss rules stay exact.
  @spec creator_down(t(), {:DOWN, reference(), :process, pid(), term()}) :: t()
  def creator_down(%__MODULE__{} = ledger, {:DOWN, ref, :process, pid, _reason}) do
    case ledger.current do
      %{kind: :file_executor, requester: {^ref, :process, ^pid}} ->
        close_admission(ledger)

      %{creator: {^ref, :process, ^pid}} = current ->
        birth_loss = if current.state == :reserved, do: @roles[current.kind], else: 0
        native_loss = if current.operation != nil, do: @native_loss, else: 0
        %{ledger | admission: :closed, losses: ledger.losses ||| birth_loss ||| native_loss}

      _ ->
        ledger
    end
  end

  @spec down(t(), {:DOWN, reference(), :process | :socket, term(), term()}) :: t()
  def down(%__MODULE__{} = ledger, {:DOWN, ref, type, object, _reason}) do
    case ledger.current do
      %{identity: {^ref, ^type, ^object}, state: :live} = current ->
        lost =
          current.kind == :file_executor and
            (current.operation != nil or current.resource in [:open, :unknown])

        %{
          ledger
          | current: %{current | state: :down},
            observed_down: ledger.observed_down ||| @roles[current.kind],
            admission: if(lost, do: :closed, else: ledger.admission),
            losses: if(lost, do: ledger.losses ||| @native_loss, else: ledger.losses)
        }

      _ ->
        ledger
    end
  end

  @type operation :: :open | :read | :close
  @type result ::
          :opened | :enoent | :unknown | :read_completed | :closed | :close_unknown | :skipped
  @type completion :: {reference(), operation(), result()}
  @type close_completion :: :none | {reference(), :closed | :close_unknown}

  # Open grant is separate from inert actor enrollment. The second token
  # preauthorizes exactly one serial cleanup close, including after ACK loss.
  @spec grant_open(t(), generation(), reference(), reference()) :: {:ok, t()} | {:error, atom()}
  def grant_open(%__MODULE__{} = ledger, generation, operation, cleanup)
      when is_reference(operation) and is_reference(cleanup) and operation != cleanup do
    case ledger.current do
      %{
        kind: :file_executor,
        generation: ^generation,
        state: :live,
        resource: :none,
        operation: nil,
        last_result: nil,
        cleanup: nil
      } = current
      when ledger.admission == :open and ledger.losses == 0 ->
        {:ok,
         %{
           ledger
           | current: %{current | operation: {operation, :open}, cleanup: {cleanup, :available}}
         }}

      _ ->
        {:error, :operation_not_permitted}
    end
  end

  def grant_open(%__MODULE__{}, _generation, _operation, _cleanup),
    do: {:error, :operation_not_permitted}

  @spec begin_operation(t(), generation(), reference(), :read | :close) ::
          {:ok, t()} | {:error, atom()}
  def begin_operation(%__MODULE__{} = ledger, generation, operation, kind)
      when is_reference(operation) and kind in [:read, :close] do
    case ledger.current do
      %{
        generation: ^generation,
        kind: :file_executor,
        state: :live,
        operation: nil,
        resource: :open,
        cleanup: {cleanup, :available}
      } = current ->
        cond do
          kind == :close and operation == cleanup ->
            {:ok,
             %{
               ledger
               | current: %{
                   current
                   | operation: {operation, :close},
                     cleanup: {cleanup, :pending}
                 }
             }}

          kind == :read and ledger.admission != :open ->
            {:error, :admission_closed}

          kind == :read and ledger.losses == 0 and operation != cleanup and
              not last_token?(current, operation) ->
            {:ok, %{ledger | current: %{current | operation: {operation, :read}}}}

          true ->
            {:error, :operation_not_permitted}
        end

      _ ->
        {:error, :operation_not_permitted}
    end
  end

  def begin_operation(%__MODULE__{}, _generation, _operation, _kind),
    do: {:error, :operation_not_permitted}

  # A trusted adapter classifies actual synchronous returns. ENOENT is the
  # source-proven Unix raw-open no-handle result; generic errors are unknown.
  @spec complete_operation(t(), generation(), completion()) :: {:ok, t()} | {:error, atom()}
  def complete_operation(%__MODULE__{} = ledger, generation, {token, kind, result} = completion)
      when is_reference(token) and kind in [:open, :read, :close] and
             result in [
               :opened,
               :enoent,
               :unknown,
               :read_completed,
               :closed,
               :close_unknown,
               :skipped
             ] do
    with %{kind: :file_executor, generation: ^generation} = current <- ledger.current,
         true <-
           current.state == :live or
             (current.state == :down and ledger.losses == 0 and current.operation == nil and
                current.resource in [:none, :closed] and current.last_result == completion),
         {:ok, next} <- commit_result(current, completion) do
      {:ok,
       %{
         ledger
         | current: next,
           admission: if(elem(completion, 2) == :skipped, do: :closed, else: ledger.admission)
       }}
    else
      _ -> {:error, :unknown_operation}
    end
  end

  def complete_operation(%__MODULE__{}, _generation, _completion),
    do: {:error, :unknown_operation}

  # Fixed two-part summary. Validation is atomic; an invalid close part cannot
  # commit its preceding operation. No bare closure clears a pending operation.
  @spec drain_completed(t(), generation(), completion(), close_completion()) ::
          {:ok, t()} | {:error, atom()}
  def drain_completed(%__MODULE__{} = ledger, generation, completion, close_completion) do
    with {:ok, next} <- complete_operation(ledger, generation, completion),
         {:ok, current} <- commit_cleanup(next.current, close_completion) do
      {:ok, %{next | admission: :closed, current: current}}
    else
      _ -> {:error, :invalid_drain_summary}
    end
  end

  # Public close progress alone never proves native completion/closure.
  @spec handle_closed(t(), generation()) :: {:ok, t()} | {:error, atom()}
  def handle_closed(%__MODULE__{} = ledger, generation) do
    case ledger.current do
      %{generation: ^generation, kind: :file_executor, identity: identity} = current
      when identity != nil ->
        {:ok, %{ledger | current: %{current | handle_closed: true}}}

      _ ->
        {:error, :unknown_file_generation}
    end
  end

  defp commit_result(%{last_result: completion} = current, completion), do: {:ok, current}

  defp commit_result(%{operation: {token, kind}} = current, {token, kind, result} = completion) do
    case operation_result(current, kind, result) do
      {:ok, next} -> {:ok, %{next | operation: nil, last_result: completion}}
      :error -> {:error, :invalid_result}
    end
  end

  defp commit_result(_current, _completion), do: {:error, :unknown_operation}

  defp operation_result(current, :open, :opened), do: {:ok, %{current | resource: :open}}

  defp operation_result(current, :open, :enoent),
    do: {:ok, %{current | resource: :none, cleanup: nil}}

  defp operation_result(current, :open, :unknown),
    do: {:ok, %{current | resource: :unknown, cleanup: nil}}

  defp operation_result(current, :open, :skipped),
    do: {:ok, %{current | resource: :none, cleanup: nil}}

  defp operation_result(current, :read, result) when result in [:read_completed, :skipped],
    do: {:ok, current}

  defp operation_result(current, :close, result) when result in [:closed, :close_unknown],
    do: commit_cleanup(%{current | operation: nil}, {elem(current.operation, 0), result})

  defp operation_result(_current, _kind, _result), do: :error

  defp commit_cleanup(%{operation: nil, resource: resource, cleanup: nil} = current, :none)
       when resource == :none,
       do: {:ok, current}

  defp commit_cleanup(%{operation: nil, cleanup: {token, result}} = current, {token, result})
       when result in [:closed, :close_unknown],
       do: {:ok, current}

  defp commit_cleanup(
         %{operation: nil, resource: :open, cleanup: {token, state}} = current,
         {token, result}
       )
       when state in [:available, :pending] and result in [:closed, :close_unknown] do
    resource = if result == :closed, do: :closed, else: :unknown
    {:ok, %{current | resource: resource, cleanup: {token, result}}}
  end

  defp commit_cleanup(_current, _completion), do: {:error, :unknown_cleanup}

  defp last_token?(%{last_result: {token, _kind, _result}}, token), do: true
  defp last_token?(_current, _token), do: false

  @spec snapshot(t()) :: snapshot()
  def snapshot(%__MODULE__{} = ledger) do
    %{
      admission: ledger.admission,
      roles: ledger.roles,
      observed_down: ledger.observed_down,
      allocations: allocation_mask(ledger.current),
      native_operation: native_state(ledger.current),
      handle_close: close_state(ledger.current),
      resource_state: resource_state(ledger.current),
      losses: ledger.losses
    }
  end

  @spec proof(t()) :: {:ok, proof()} | {:pending, snapshot()}
  def proof(%__MODULE__{} = ledger) do
    if ledger.admission == :closed and discharged?(ledger.current) do
      {:ok,
       %{
         roles: ledger.roles,
         observed_down: ledger.observed_down,
         losses: ledger.losses,
         cleanup: if(ledger.losses == 0, do: :confirmed, else: :unconfirmed)
       }}
    else
      {:pending, snapshot(ledger)}
    end
  end

  defp reserve_next(ledger, kind, creator, token) do
    generation = ledger.generation + 1

    current = %{
      kind: kind,
      generation: generation,
      creator: if(kind == :file_executor, do: :observer, else: creator),
      requester: creator,
      token: token,
      identity: nil,
      state: :reserved,
      operation: nil,
      last_result: nil,
      resource: :none,
      cleanup: nil,
      handle_closed: false
    }

    {:ok,
     %{
       ledger
       | generation: generation,
         counts: Map.update!(ledger.counts, kind, &(&1 + 1)),
         current: current
     }, generation}
  end

  defp discharged?(nil), do: true
  defp discharged?(%{state: :rejected}), do: true
  defp discharged?(%{state: :down, kind: :http_socket}), do: true

  defp discharged?(%{state: :down, kind: :file_executor, operation: nil, resource: resource})
       when resource in [:none, :closed],
       do: true

  defp discharged?(_current), do: false

  defp valid_creator?({ref, :process, pid}), do: is_reference(ref) and is_pid(pid)
  defp valid_creator?(_creator), do: false
  defp valid_identity?(:http_socket, {ref, :socket, _socket}), do: is_reference(ref)

  defp valid_identity?(:file_executor, {ref, :process, pid}),
    do: is_reference(ref) and is_pid(pid)

  defp valid_identity?(_kind, _identity), do: false

  defp allocation_mask(%{state: :reserved, kind: kind}), do: @roles[kind]
  defp allocation_mask(_current), do: 0
  defp native_state(%{operation: operation}) when operation != nil, do: :pending
  defp native_state(_current), do: :idle
  defp resource_state(%{kind: :file_executor, resource: resource}), do: resource
  defp resource_state(_current), do: :none
  defp close_state(%{kind: :file_executor, resource: :closed}), do: :completed

  defp close_state(%{kind: :file_executor, resource: resource})
       when resource in [:open, :unknown],
       do: :pending

  defp close_state(_current), do: :not_required
end
