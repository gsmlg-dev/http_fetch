defmodule Quic.AbyssDispatcher do
  @moduledoc """
  Abyss callback adapter for the external `Quic.Endpoint` runtime.

  This module intentionally does not compile against or call Abyss modules.
  The host dispatcher supplies a `send_fun` in the callback context; the
  adapter passes that capability to an externally owned QUIC endpoint.
  """

  alias Quic.Endpoint

  @spec init(map(), keyword()) :: {:ok, map()} | {:error, term()}
  def init(%{local_info: local_info, send_fun: send_fun}, opts)
      when is_tuple(local_info) and is_function(send_fun, 2) and is_list(opts) do
    endpoint_opts =
      opts
      |> Keyword.delete(:io)
      |> Keyword.put(:role, :server)
      |> Keyword.put(:io, {:external, local_info, send_fun})

    with {:ok, endpoint} <- Endpoint.start_link(endpoint_opts) do
      {:ok, %{endpoint: endpoint}}
    end
  end

  def init(_context, _opts), do: {:error, :invalid_abyss_context}

  @spec handle_datagram(tuple(), binary(), integer(), map()) ::
          {:ok, map()} | {:drop, term(), map()}
  def handle_datagram(remote, bytes, at, %{state: %{endpoint: endpoint} = state}) do
    case Endpoint.receive_datagram(endpoint, remote, bytes, at) do
      :ok -> {:ok, state}
      {:error, reason} -> {:drop, reason, state}
    end
  catch
    :exit, reason -> {:drop, {:endpoint_exit, reason}, state_from_context(state)}
  end

  def handle_datagram(_remote, _bytes, _at, context),
    do: {:drop, :invalid_abyss_state, Map.get(context, :state, %{})}

  @spec terminate(term(), map()) :: :ok
  def terminate(reason, %{endpoint: endpoint}) do
    if Process.alive?(endpoint), do: GenServer.stop(endpoint, reason)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp state_from_context(state), do: state
end
