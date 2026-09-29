defmodule HTTP.WebTransport.Transport.QUIC do
  @moduledoc false
  @behaviour HTTP.WebTransport.Transport
  @reason {:error, :webtransport_not_supported_by_elixir_quic_http3}

  def connect(_, _), do: @reason
  def close(_, _), do: :ok
  def get_stats(_), do: {:ok, %HTTP.WebTransport.Stats{}}
  def open_bidirectional_stream(_session, _), do: @reason
  def open_unidirectional_stream(_session, _), do: @reason
  def send_datagram(_, _, _), do: @reason
  def recv_stream(_, _), do: @reason
  def send_stream(_, _, _), do: @reason
  def close_send_stream(_), do: @reason
  def abort_send_stream(_, _), do: @reason
  def cancel_receive_stream(_, _), do: @reason
end
