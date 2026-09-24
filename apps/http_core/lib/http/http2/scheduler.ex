defmodule HTTP.HTTP2.Scheduler do
  @moduledoc "Bounded round-robin ordering for ready HTTP/2 stream work."

  defstruct order: [], cursor: 0

  @type t :: %__MODULE__{order: [pos_integer()], cursor: non_neg_integer()}

  @spec new([pos_integer()]) :: t()
  def new(ids \\ []) when is_list(ids),
    do: Enum.reduce(ids, %__MODULE__{}, &add(&2, &1))

  @spec add(t(), pos_integer()) :: t()
  def add(%__MODULE__{} = scheduler, id) when is_integer(id) and id > 0 do
    if id in scheduler.order,
      do: scheduler,
      else: %{scheduler | order: scheduler.order ++ [id]}
  end

  @spec remove(t(), pos_integer()) :: t()
  def remove(%__MODULE__{} = scheduler, id) when is_integer(id) and id > 0 do
    {removed, order} = pop_id(scheduler.order, id, [])
    cursor = if removed and order != [], do: rem(scheduler.cursor, length(order)), else: 0
    %{scheduler | order: order, cursor: cursor}
  end

  @spec ready(t(), [pos_integer()]) :: {[pos_integer()], t()}
  def ready(%__MODULE__{order: order} = scheduler, ids) when is_list(ids) do
    ready = MapSet.new(ids)
    ordered = rotate(order, scheduler.cursor) |> Enum.filter(&MapSet.member?(ready, &1))

    next_cursor =
      case ordered do
        [first | _] -> rem(Enum.find_index(order, &(&1 == first)) + 1, max(length(order), 1))
        [] -> scheduler.cursor
      end

    {ordered, %{scheduler | cursor: next_cursor}}
  end

  defp pop_id([], _id, _acc), do: {false, []}

  defp pop_id([id | rest], id, acc), do: {true, Enum.reverse(acc, rest)}
  defp pop_id([head | rest], id, acc), do: pop_id(rest, id, [head | acc])

  defp rotate([], _cursor), do: []

  defp rotate(order, cursor) do
    cursor = rem(cursor, length(order))
    Enum.drop(order, cursor) ++ Enum.take(order, cursor)
  end
end
