defmodule HTTP.HTTP3 do
  @moduledoc false

  alias HTTP.Request

  @spec request(Request.t(), term(), function()) :: term()
  def request(%Request{}, state, _handler),
    do: :erlang.apply(__MODULE__, :unsupported, [state])

  @spec request(Request.t()) :: {:error, atom()}
  def request(%Request{}), do: {:error, :http3_not_supported_by_elixir_quic_http3}

  def unsupported(state), do: {:error, :http3_not_supported_by_elixir_quic_http3, state}
end
