defmodule Abyss.DatagramActions do
  @moduledoc false

  def validate(actions, limits, persistent?),
    do: validate_list(actions, limits, persistent?, 0, 0)

  defp validate_list([], _limits, _persistent, _count, _bytes), do: :ok

  defp validate_list([action | tail], limits, persistent, count, bytes) do
    case action_size(action, persistent) do
      {:ok, size} when count < limits.max_actions and bytes + size <= limits.max_action_bytes ->
        validate_list(tail, limits, persistent, count + 1, bytes + size)

      {:ok, _} ->
        {:error, :action_limit}

      error ->
        error
    end
  end

  defp validate_list(_, _, _, _, _), do: {:error, :invalid_actions}

  defp action_size({:reply, data}, _) when is_binary(data), do: {:ok, byte_size(data)}
  defp action_size({:reply, data, :strict}, _) when is_binary(data), do: {:ok, byte_size(data)}

  defp action_size({:send, %{family: family, addr: addr, port: port} = destination, data}, _)
       when family in [:inet, :inet6] and is_tuple(addr) and is_integer(port) and
              port in 0..65_535 and is_binary(data) do
    if Enum.all?(Map.keys(destination), &(&1 in [:family, :addr, :port, :scope_id, :flowinfo])) and
         valid_control?(Map.get(destination, :scope_id, 0)) and
         valid_control?(Map.get(destination, :flowinfo, 0)) and
         valid_address?(addr, family),
       do: {:ok, byte_size(data)},
       else: {:error, :invalid_destination}
  end

  defp action_size({:timer, token, delay, value}, true)
       when is_integer(delay) and delay in 0..0xFFFFFFFF do
    if :erlang.external_size({token, value}) <= 4096,
      do: {:ok, 0},
      else: {:error, :timer_value_limit}
  end

  defp action_size({:cancel_timer, token}, true) do
    if :erlang.external_size(token) <= 4096, do: {:ok, 0}, else: {:error, :timer_value_limit}
  end

  defp action_size(_, _), do: {:error, :invalid_action}

  defp valid_address?(addr, family) do
    size = if family == :inet, do: 4, else: 8
    tuple_size(addr) == size and Enum.all?(Tuple.to_list(addr), &valid_address_part?(&1, family))
  end

  defp valid_control?(value), do: is_integer(value) and value in 0..0xFFFFFFFF
  defp valid_address_part?(part, :inet), do: is_integer(part) and part in 0..255
  defp valid_address_part?(part, :inet6), do: is_integer(part) and part in 0..65_535
end
