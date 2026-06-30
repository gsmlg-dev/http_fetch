defmodule HTTP.WebTransport.FakeBackend do
  @moduledoc false

  @behaviour HTTP.WebTransport.Transport

  alias HTTP.WebTransport.Stats

  @impl true
  def connect(_uri, options) do
    protocol = List.first(options.protocols) || ""

    {:ok, options.ref,
     %{
       protocol: protocol,
       reliability: "supports-unreliable",
       response_headers: [{"X-Fake-WebTransport", "ok"}],
       max_datagram_size: options.max_datagram_size
     }}
  end

  @impl true
  def close(_session_ref, _close_info), do: :ok

  @impl true
  def get_stats(_session_ref), do: {:ok, %Stats{}}

  @impl true
  def open_bidirectional_stream(_session_ref, _options) do
    {:ok, {:fake_bidi_stream, System.unique_integer([:positive])}}
  end

  @impl true
  def open_unidirectional_stream(_session_ref, _options) do
    {:ok, {:fake_uni_stream, System.unique_integer([:positive])}}
  end

  @impl true
  def send_datagram(_session_ref, _bytes, _options), do: :ok

  @impl true
  def recv_stream(_stream_ref, _timeout), do: {:error, :not_supported_by_fake_backend}

  @impl true
  def send_stream(_stream_ref, _data, _options), do: :ok

  @impl true
  def close_send_stream(_stream_ref), do: :ok

  @impl true
  def abort_send_stream(_stream_ref, _code), do: :ok

  @impl true
  def cancel_receive_stream(_stream_ref, _code), do: :ok
end
