defmodule Quic.IO.ExternalWriter do
  @moduledoc """
  Bounded integration writer backed by a caller-owned send function.

  The function returns `:ok`, `{:ok, monotonic_microseconds}`, or
  `{:error, reason}`. `{:ok, ref}` is deliberately rejected: queue admission
  is not local send completion. The writer owns no socket and never exposes
  its callback to the connection process.
  """
  use GenServer

  @behaviour Quic.IO

  def start_link(opts) when is_list(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def send(pid, bytes, remote), do: GenServer.call(pid, {:send, bytes, remote})

  @impl true
  def close(pid), do: GenServer.call(pid, :close)

  @impl true
  def monotonic_time, do: System.monotonic_time(:microsecond)

  @impl true
  def init(opts) do
    owner = Keyword.fetch!(opts, :owner)
    send_fun = Keyword.fetch!(opts, :send_fun)

    if is_pid(owner) and is_function(send_fun, 2) do
      {:ok, %{owner: owner, owner_monitor: Process.monitor(owner), send_fun: send_fun}}
    else
      {:stop, :invalid_external_writer}
    end
  end

  @impl true
  def handle_call({:send, bytes, remote}, _from, state)
      when is_binary(bytes) and byte_size(bytes) in 1..65_507 do
    result =
      try do
        normalize_result(state.send_fun.(remote, bytes))
      rescue
        error -> {:error, {:send_exception, error}}
      catch
        kind, reason -> {:error, {:send_exit, kind, reason}}
      end

    {:reply, result, state}
  end

  def handle_call({:send, _bytes, _remote}, _from, state),
    do: {:reply, {:error, :invalid_datagram}, state}

  def handle_call(:close, _from, state), do: {:stop, :normal, :ok, state}

  @impl true
  def handle_info({:DOWN, monitor, :process, owner, _reason}, %{
        owner_monitor: monitor,
        owner: owner
      }),
      do: {:stop, :normal, :owner_down}

  def handle_info(_, state), do: {:noreply, state}

  defp normalize_result(:ok), do: {:ok, monotonic_time()}
  defp normalize_result({:ok, at}) when is_integer(at), do: {:ok, at}
  defp normalize_result({:error, _} = error), do: error
  defp normalize_result(other), do: {:error, {:invalid_send_result, other}}
end
