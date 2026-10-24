defmodule SSL.PKIX.VerifyFun do
  @moduledoc false

  @type policy :: :undefined | {function(), term()} | (list() -> boolean())
  @server_auth {1, 3, 6, 1, 5, 5, 7, 3, 1}
  @extended_key_usage {2, 5, 29, 37}

  @spec valid?(term()) :: boolean()
  def valid?(:undefined), do: true
  def valid?({fun, _state}) when is_function(fun, 3) or is_function(fun, 4), do: true
  def valid?(fun) when is_function(fun, 1), do: true
  def valid?(_), do: false

  @spec enabled?(term()) :: boolean()
  def enabled?(:undefined), do: false
  def enabled?(policy), do: valid?(policy)

  @spec wrap(policy(), (term() -> boolean())) :: {function(), term()}
  def wrap(:undefined, hostname_match) do
    callback = fn certificate, _der, event, state ->
      case policy_event(event, certificate, hostname_match) do
        :handled -> {:valid, state}
        {:bad_cert, reason} -> {:fail, {:bad_cert, reason}}
        {:extension, _} -> {:unknown, state}
        _ -> {:valid, state}
      end
    end

    {callback, :undefined}
  end

  def wrap({fun, initial}, hostname_match) do
    callback = fn certificate, der, event, state ->
      case policy_event(event, certificate, hostname_match) do
        :handled -> {:valid, state}
        actual -> invoke(fun, certificate, der, actual, state)
      end
    end

    {callback, initial}
  end

  def wrap(fun, hostname_match) when is_function(fun, 1) do
    callback = fn certificate, _der, event, state ->
      case policy_event(event, certificate, hostname_match) do
        {:bad_cert, reason} = error -> legacy(fun, error, reason, state)
        {:extension, _} -> {:unknown, state}
        _ -> {:valid, state}
      end
    end

    {callback, :undefined}
  end

  defp policy_event({:extension, {:Extension, @extended_key_usage, _, usages}}, _, _) do
    if @server_auth in usages,
      do: :handled,
      else: {:bad_cert, {:ca_invalid_ext_keyusage, usages}}
  end

  defp policy_event(:valid_peer, certificate, hostname_match) do
    if hostname_match.(certificate), do: :valid_peer, else: {:bad_cert, :hostname_check_failed}
  end

  defp policy_event(event, _, _), do: event

  defp invoke(fun, certificate, der, event, state) do
    result =
      if is_function(fun, 4),
        do: fun.(certificate, der, event, state),
        else: fun.(certificate, event, state)

    case result do
      {:valid, next} -> {:valid, next}
      {:valid_peer, next} -> {:valid_peer, next}
      {:unknown, next} when elem(event, 0) == :extension -> {:unknown, next}
      {:fail, _private_reason} -> {:fail, {:verify_fun, :rejected}}
      _private_return -> {:fail, {:verify_fun, :invalid_return}}
    end
  catch
    _kind, _private_reason -> {:fail, {:verify_fun, :exception}}
  end

  defp legacy(fun, error, reason, state) do
    case fun.([error]) do
      true -> {:valid, state}
      false -> {:fail, {:bad_cert, reason}}
      _private_return -> {:fail, {:verify_fun, :invalid_return}}
    end
  catch
    _kind, _private_reason -> {:fail, {:verify_fun, :exception}}
  end
end
