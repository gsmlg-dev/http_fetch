defmodule HTTP.WebTransport.Transport.QUIC do
  @moduledoc false

  @behaviour HTTP.WebTransport.Transport

  @impl true
  def connect(_uri, _options), do: {:error, :quic_backend_unavailable}

  @impl true
  def close(_session_ref, _close_info), do: {:error, :quic_backend_unavailable}

  @impl true
  def get_stats(_session_ref), do: {:error, :quic_backend_unavailable}

  @impl true
  def open_bidirectional_stream(_session_ref, _options), do: {:error, :quic_backend_unavailable}

  @impl true
  def open_unidirectional_stream(_session_ref, _options), do: {:error, :quic_backend_unavailable}

  @impl true
  def send_datagram(_session_ref, _bytes, _options), do: {:error, :quic_backend_unavailable}

  @impl true
  def recv_stream(_stream_ref, _timeout), do: {:error, :quic_backend_unavailable}

  @impl true
  def send_stream(_stream_ref, _data, _options), do: {:error, :quic_backend_unavailable}

  @impl true
  def close_send_stream(_stream_ref), do: {:error, :quic_backend_unavailable}

  @impl true
  def abort_send_stream(_stream_ref, _code), do: {:error, :quic_backend_unavailable}

  @impl true
  def cancel_receive_stream(_stream_ref, _code), do: {:error, :quic_backend_unavailable}
end
