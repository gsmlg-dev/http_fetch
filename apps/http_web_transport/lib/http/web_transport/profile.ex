defmodule HTTP.WebTransport.Profile do
  @moduledoc false

  alias HTTP.H3.WebTransport.Draft17

  @doc "Validates decoded negotiation evidence; this does not assert network support."
  def validate(server_settings, local_transport, peer_transport, options \\ []) do
    with :ok <- exclusive(options),
         :ok <- validate_reset(Keyword.get(options, :reliable_reset)),
         :ok <- Draft17.validate_server_settings(server_settings),
         :ok <- transport(local_transport, :local) do
      transport(peer_transport, :peer)
    end
  end

  @doc "Validates the reliable_reset entry from Quic.info/1, not transport parameters alone."
  def validate_reset(%{draft: 11, local: true, peer: true, negotiated: true}), do: :ok
  def validate_reset(_), do: {:error, :reliable_reset_not_negotiated}

  def supported?, do: false

  defp exclusive(options) do
    if Keyword.get(options, :exclusive, false) and Keyword.get(options, :session_count, 1) == 1,
      do: :ok,
      else: {:error, :exclusive_single_session_required}
  end

  defp transport(parameters, role) when is_map(parameters) do
    cond do
      not (is_integer(parameters[:max_datagram_frame_size]) and
               parameters[:max_datagram_frame_size] > 0) ->
        {:error, {:quic_datagram_required, role}}

      Map.get(parameters, :reset_stream_at) != <<>> ->
        {:error, {:reliable_reset_required, role}}

      true ->
        :ok
    end
  end

  defp transport(_parameters, role), do: {:error, {:invalid_transport_parameters, role}}
end
