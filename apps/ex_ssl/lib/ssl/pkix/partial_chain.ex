defmodule SSL.PKIX.PartialChain do
  @moduledoc false

  def candidates([leaf | _] = chain, anchors) do
    pool = Enum.uniq_by(Enum.reverse(chain) ++ anchors, & &1.der)
    trusted = MapSet.new(anchors, & &1.der)

    case expand([leaf], pool, trusted, [], 0) do
      {:ok, paths, _} -> {:ok, Enum.reverse(paths)}
      error -> error
    end
  end

  # The pool supplies untrusted path candidates. Only the already selected
  # anchor DER can terminate this independent CRL signer path.
  def signer_paths(signer, pool, anchor, fuel, deadline) do
    signer_expand([signer], pool, anchor, fuel, deadline, [], 0)
  end

  defp signer_expand(_path, _pool, _anchor, fuel, _deadline, _acc, _visits)
       when fuel <= 0,
       do: {:error, :policy_capacity}

  defp signer_expand(path, pool, anchor, fuel, deadline, acc, visits) do
    if deadline != :infinity and System.monotonic_time(:millisecond) >= deadline do
      {:error, :deadline_exceeded}
    else
      # Consume the attempt's remaining fuel before retaining a new path node.
      fuel = fuel - 1
      visits = visits + 1
      top = List.last(path)

      if top.der == anchor.der do
        {:ok, [{anchor, Enum.drop(path, -1)} | acc], fuel, visits}
      else
        signer_parents(path, pool, anchor, fuel, deadline, acc, visits, top)
      end
    end
  end

  defp signer_parents(path, pool, anchor, fuel, deadline, acc, visits, top) do
    Enum.reduce_while(pool, {:ok, acc, fuel, visits}, fn parent, {:ok, paths, left, used} ->
      cond do
        deadline != :infinity and System.monotonic_time(:millisecond) >= deadline ->
          {:halt, {:error, :deadline_exceeded}}

        Enum.any?(path, &(&1.der == parent.der)) or not issuer?(top, parent) ->
          {:cont, {:ok, paths, left, used}}

        left <= 0 ->
          {:halt, {:error, :policy_capacity}}

        true ->
          case signer_expand(path ++ [parent], pool, anchor, left, deadline, paths, used) do
            {:ok, _, _, _} = result -> {:cont, result}
            error -> {:halt, error}
          end
      end
    end)
  end

  def select({:selfsigned_peer, path}, _selection), do: {:selfsigned_peer, path}

  def select({anchor, path} = candidate, {:trusted_ca, der}) when is_binary(der) do
    full = full_path(candidate)

    case Enum.find_index(full, &(&1.der == der)) do
      nil -> {anchor, path}
      index -> {Enum.at(full, index), Enum.take(full, index)}
    end
  end

  def select(candidate, _), do: candidate

  def full_path({anchor, path}) when is_atom(anchor), do: path
  def full_path({anchor, path}), do: path ++ [anchor]

  def issuer?(certificate, issuer) do
    :public_key.pkix_is_issuer(certificate.decoded, issuer.decoded)
  catch
    _, _ -> false
  end

  defp expand(_, _, _, _, count) when count >= 4_096, do: {:error, :policy_capacity}

  defp expand(path, pool, trusted, acc, count) do
    top = List.last(path)

    cond do
      length(path) == 1 and :public_key.pkix_is_self_signed(top.decoded) ->
        {:ok, [{:selfsigned_peer, path} | acc], count + 1}

      MapSet.member?(trusted, top.der) ->
        {:ok, [{top, Enum.drop(path, -1)} | acc], count + 1}

      true ->
        parents =
          Enum.filter(pool, fn candidate ->
            not Enum.any?(path, &(&1.der == candidate.der)) and issuer?(top, candidate)
          end)

        case parents do
          [] ->
            {:ok, [{:unknown_ca, path} | acc], count + 1}

          _ ->
            expand_parents(parents, path, pool, trusted, acc, count)
        end
    end
  end

  defp expand_parents(parents, path, pool, trusted, acc, count) do
    Enum.reduce_while(parents, {:ok, acc, count + 1}, fn parent, {:ok, paths, visited} ->
      case expand(path ++ [parent], pool, trusted, paths, visited) do
        {:ok, _, _} = result -> {:cont, result}
        error -> {:halt, error}
      end
    end)
  end
end
