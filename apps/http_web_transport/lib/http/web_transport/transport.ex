defmodule HTTP.WebTransport.Transport do
  @moduledoc """
  Behaviour for WebTransport protocol backends.

  The public WebTransport API is intentionally decoupled from the concrete QUIC
  implementation. A compliant backend must speak WebTransport over HTTP/3; raw
  UDP is not sufficient.
  """

  @type session_ref :: term()
  @type stream_ref :: term()
  @type transport_info :: map()

  @callback connect(URI.t(), HTTP.WebTransport.Options.t()) ::
              {:ok, session_ref(), transport_info()} | {:error, term()}

  @callback close(session_ref(), HTTP.WebTransport.CloseInfo.t()) :: :ok | {:error, term()}
  @callback get_stats(session_ref()) :: {:ok, HTTP.WebTransport.Stats.t()} | {:error, term()}

  @callback open_bidirectional_stream(session_ref(), keyword()) ::
              {:ok, stream_ref()} | {:error, term()}

  @callback open_unidirectional_stream(session_ref(), keyword()) ::
              {:ok, stream_ref()} | {:error, term()}

  @callback send_datagram(session_ref(), binary(), keyword()) :: :ok | {:error, term()}
  @callback recv_stream(stream_ref(), timeout()) :: {:ok, binary()} | :fin | {:error, term()}
  @callback send_stream(stream_ref(), iodata(), keyword()) :: :ok | {:error, term()}
  @callback close_send_stream(stream_ref()) :: :ok | {:error, term()}
  @callback abort_send_stream(stream_ref(), non_neg_integer()) :: :ok | {:error, term()}
  @callback cancel_receive_stream(stream_ref(), non_neg_integer()) :: :ok | {:error, term()}
end
