defmodule HTTP.EventSource do
  @moduledoc """
  Browser-like EventSource client API for Elixir.

  Events are delivered as messages to the owner process:

      {HTTP.EventSource, source, %HTTP.EventSource.Event.Open{}}
      {HTTP.EventSource, source, %HTTP.EventSource.Event.Message{}}
      {HTTP.EventSource, source, %HTTP.EventSource.Event.Error{}}

  Custom server-sent event names are delivered through the message event's
  `type` field.
  """

  alias HTTP.EventSource.Connection
  alias HTTP.EventSource.Options

  defstruct pid: nil, ref: nil, url: nil, with_credentials: false

  @connecting 0
  @open 1
  @closed 2
  @call_timeout 5_000

  @type t :: %__MODULE__{
          pid: pid() | nil,
          ref: reference() | nil,
          url: String.t() | nil,
          with_credentials: boolean()
        }

  @spec connecting() :: 0
  def connecting, do: @connecting

  @spec open() :: 1
  def open, do: @open

  @spec closed() :: 2
  def closed, do: @closed

  @spec new(String.t() | URI.t(), keyword() | map()) :: t() | {:error, term()}
  def new(url, init \\ []) do
    ref = make_ref()

    with {:ok, options} <- Options.new(url, put_ref(init, ref)),
         {:ok, pid} <-
           DynamicSupervisor.start_child(
             HTTP.EventSource.ConnectionSupervisor,
             {Connection, options}
           ) do
      %__MODULE__{
        pid: pid,
        ref: ref,
        url: options.url,
        with_credentials: options.with_credentials
      }
    end
  end

  @spec url(t()) :: String.t() | nil
  def url(%__MODULE__{url: url}), do: url

  @spec with_credentials(t()) :: boolean()
  def with_credentials(%__MODULE__{with_credentials: with_credentials}), do: with_credentials

  @spec ready_state(t()) :: 0 | 1 | 2
  def ready_state(source), do: connection_call(source, :ready_state, @closed)

  @spec last_event_id(t()) :: String.t()
  def last_event_id(source), do: connection_call(source, :last_event_id, "")

  @spec reconnect_time(t()) :: non_neg_integer()
  def reconnect_time(source), do: connection_call(source, :reconnect_time, 0)

  @spec close(t()) :: :ok
  def close(source), do: connection_call(source, :close, :ok)

  defp connection_call(%__MODULE__{pid: pid}, request, default) when is_pid(pid) do
    GenServer.call(pid, request, @call_timeout)
  catch
    :exit, _reason -> default
  end

  defp connection_call(_source, _request, default), do: default

  defp put_ref(init, ref) when is_map(init), do: Map.put(init, :ref, ref)
  defp put_ref(init, ref) when is_list(init), do: Keyword.put(init, :ref, ref)
end
