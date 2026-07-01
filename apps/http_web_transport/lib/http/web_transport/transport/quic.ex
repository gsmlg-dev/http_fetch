defmodule HTTP.WebTransport.Transport.QUIC do
  @moduledoc false

  @behaviour HTTP.WebTransport.Transport

  alias HTTP.H3.WebTransport, as: H3WebTransport
  alias HTTP.WebTransport.Options

  @impl true
  def connect(uri, %Options{} = options) do
    with {:ok, pseudo_headers} <- H3WebTransport.connect_pseudo_headers(uri),
         {:ok, _validated_headers} <-
           H3WebTransport.validate_connect_pseudo_headers(pseudo_headers),
         :ok <- validate_client_settings(options) do
      {:error, :quic_backend_unavailable}
    end
  end

  def connect(_uri, _options), do: {:error, :invalid_quic_connect_options}

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

  defp validate_client_settings(%Options{} = options) do
    H3WebTransport.client_settings(
      initial_max_streams_uni:
        options.anticipated_concurrent_incoming_unidirectional_streams || 0,
      initial_max_streams_bidi: options.anticipated_concurrent_incoming_bidirectional_streams || 0
    )
    |> H3WebTransport.validate_client_settings()
  end
end
