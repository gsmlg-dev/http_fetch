defmodule Quic.Paths do
  @moduledoc "Bounded authenticated path selection and explicit-time validation."

  defstruct [
    :role,
    :local,
    :candidate,
    :previous,
    :retiring,
    active: :default,
    next_id: 1,
    paths: %{},
    largest_non_probing: -1
  ]

  @type t :: %__MODULE__{}
  @type id :: :default | pos_integer()

  @spec new(:client | :server, term(), term(), boolean()) :: t()
  def new(role, local, remote, validated) do
    %__MODULE__{role: role, local: local, paths: %{default: record(local, remote, validated)}}
  end

  @spec lookup(t(), term()) :: {:ok, id()} | :error
  def lookup(state, remote) do
    case Enum.find(state.paths, fn {_, path} -> path.remote == remote end) do
      {id, _} -> {:ok, id}
      nil -> :error
    end
  end

  @doc "Find a locally selected path without confusing equal remote addresses."
  def lookup_local(state, local, remote) do
    case Enum.find(state.paths, fn {_, path} -> path.local == local and path.remote == remote end) do
      {id, _} -> {:ok, id}
      nil -> :error
    end
  end

  @doc "Reserve a client candidate with unchanged server-address validation."
  def start_local(state, local, at, pto, deadline) do
    cond do
      state.role != :client ->
        {:blocked, :client_only}

      map_size(state.paths) >= 2 ->
        {:blocked, :migration_busy}

      true ->
        id = state.next_id
        old = %{state.paths[state.active] | validated_in_attempt: true}

        path = %{
          record(local, old.remote, old.validated)
          | deadline: min(deadline, at + 3 * pto),
            retry_at: at
        }

        {:ok,
         %{
           state
           | paths: state.paths |> Map.put(state.active, old) |> Map.put(id, path),
             candidate: id,
             previous: state.active,
             next_id: id + 1
         }, id}
    end
  end

  @doc "Select a reachable, MTU-validated local candidate and begin old-path settlement."
  def commit_local(%{role: :client, candidate: id} = state, id) do
    case state.paths[id] do
      %{validated_in_attempt: true, mtu_validated: true} ->
        {:ok, settled, _} = settle(state, id)
        {:ok, settled}

      _ ->
        {:error, :unvalidated_path}
    end
  end

  @spec observe(t(), term(), non_neg_integer(), boolean(), integer(), pos_integer()) ::
          {:ok, t(), id(), boolean()} | {:blocked, atom()}
  def observe(state, remote, number, probing, at, pto) do
    case lookup(state, remote) do
      {:ok, id} ->
        {:ok, select(state, id, number, probing), id, false}

      :error when state.role == :client ->
        {:blocked, :remote_migration_unsupported}

      :error when map_size(state.paths) >= 2 ->
        {:blocked, :path_limit}

      :error ->
        id = state.next_id
        deadline = at + 3 * pto

        old = %{
          state.paths[state.active]
          | deadline: deadline,
            retry_at: at,
            validated_in_attempt: false,
            challenges: [],
            attempts: 0
        }

        new = %{record(state.local, remote, false) | deadline: deadline, retry_at: at}

        next = %{
          state
          | paths: state.paths |> Map.put(state.active, old) |> Map.put(id, new),
            next_id: id + 1,
            candidate: id,
            previous: state.active
        }

        {:ok, select(next, id, number, probing), id, true}
    end
  end

  defp select(%{retiring: id} = state, id, number, false),
    do: %{state | largest_non_probing: max(state.largest_non_probing, number)}

  defp select(state, id, number, false) when number > state.largest_non_probing,
    do: %{state | active: id, largest_non_probing: number}

  defp select(state, _, _, _), do: state

  @spec validate(t(), id()) :: t()
  def validate(state, id), do: update_in(state.paths[id], &%{&1 | validated: true})

  @doc "Remember the latest authenticated incoming CID without accepting reordered changes."
  @spec note_cid(t(), id(), binary(), non_neg_integer()) :: t()
  def note_cid(state, id, dcid, number) do
    if number > state.paths[id].largest_authenticated do
      update_in(state.paths[id], &%{&1 | dcid: dcid, largest_authenticated: number})
    else
      state
    end
  end

  @spec probe(t(), id(), binary(), boolean(), integer(), pos_integer()) ::
          {:ok, t()} | {:error, atom()}
  def probe(state, id, value, padded, at, pto) when byte_size(value) == 8 do
    path = state.paths[id]

    cond do
      is_nil(path) ->
        {:error, :unknown_path}

      path.attempts >= 3 ->
        {:error, :challenge_limit}

      is_integer(path.deadline) and at >= path.deadline ->
        {:error, :validation_expired}

      true ->
        path = %{
          path
          | challenges: path.challenges ++ [%{value: value, padded: padded}],
            attempts: path.attempts + 1,
            retry_at: at + pto
        }

        {:ok, put_in(state.paths[id], path)}
    end
  end

  @spec response(t(), binary(), integer()) :: {:ok, t(), id()} | :ignore
  def response(state, value, at) do
    found =
      Enum.find_value(state.paths, fn {id, path} ->
        if is_integer(path.deadline) and at < path.deadline do
          case Enum.find(path.challenges, &(&1.value == value)) do
            nil -> nil
            challenge -> {id, challenge}
          end
        end
      end)

    case found do
      nil ->
        :ignore

      {id, challenge} ->
        path = state.paths[id]
        mtu = path.mtu_validated or challenge.padded

        path = %{
          path
          | validated: true,
            validated_in_attempt: true,
            mtu_validated: mtu,
            challenges: [],
            attempts: if(mtu, do: path.attempts, else: 0),
            retry_at: if(mtu, do: nil, else: at)
        }

        {:ok, put_in(state.paths[id], path), id}
    end
  end

  @spec due(t(), integer()) :: [id()]
  def due(state, at) do
    for {id, path} <- state.paths,
        state.retiring == nil and is_integer(path.retry_at) and
          path.retry_at <= at and path.attempts < 3 and at < path.deadline,
        do: id
  end

  @spec next_deadline(t()) :: integer() | nil
  def next_deadline(state) do
    deadlines =
      for {_, path} <- state.paths,
          value <- [path.deadline, if(path.attempts < 3, do: path.retry_at)],
          is_integer(value),
          state.retiring == nil,
          do: value

    Enum.min(deadlines, fn -> nil end)
  end

  @spec on_time(t(), integer(), :all | [id()]) ::
          {:ok, t(), id() | nil} | {:error, :no_validated_path}
  def on_time(state, at, available \\ :all)
  def on_time(%{candidate: nil} = state, _, _), do: {:ok, state, nil}
  def on_time(%{retiring: id} = state, _, _) when not is_nil(id), do: {:ok, state, id}

  def on_time(state, at, available) do
    if at < state.paths[state.candidate].deadline do
      {:ok, state, nil}
    else
      validated =
        for {id, path} <- state.paths,
            path.validated_in_attempt,
            available == :all or id in available,
            do: id

      cond do
        validated == [] -> {:error, :no_validated_path}
        state.active in validated -> settle(state, state.active)
        state.previous in validated -> settle(state, state.previous)
        true -> settle(state, hd(validated))
      end
    end
  end

  defp settle(state, selected) do
    retiring = Enum.find(Map.keys(state.paths), &(&1 != selected))

    paths =
      Map.new(state.paths, fn {id, path} ->
        {id, %{path | deadline: nil, retry_at: nil, challenges: []}}
      end)

    {:ok, %{state | paths: paths, active: selected, retiring: retiring}, retiring}
  end

  @spec drop(t(), id()) :: {:ok, t()} | {:error, :active_path}
  def drop(%{active: id}, id), do: {:error, :active_path}
  def drop(state, id) when not is_map_key(state.paths, id), do: {:ok, state}

  def drop(state, id) do
    {:ok,
     %{state | paths: Map.delete(state.paths, id), candidate: nil, previous: nil, retiring: nil}}
  end

  defp record(local, remote, validated) do
    %{
      local: local,
      remote: remote,
      dcid: nil,
      largest_authenticated: -1,
      validated: validated,
      mtu_validated: false,
      validated_in_attempt: false,
      challenges: [],
      attempts: 0,
      deadline: nil,
      retry_at: nil
    }
  end
end
