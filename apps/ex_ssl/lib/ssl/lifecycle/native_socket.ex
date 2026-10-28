defmodule SSL.Lifecycle.NativeSocket do
  @moduledoc false
  alias SSL.Lifecycle.{Observer, Receipt}

  # Private TLS adapter. Keep the native read bounded independently of kernel
  # buffer settings and of the record/plaintext queues in Connection.
  @read_size 65_536

  @spec prepare(:socket.socket(), SSL.Options.t()) :: :ok | {:error, term()}
  def prepare(socket, options) do
    with :ok <- :socket.setopt(socket, :otp, :rcvbuf, @read_size),
         :ok <- :socket.setopt(socket, :otp, :select_read, false),
         :ok <- :socket.setopt(socket, :socket, :linger, %{onoff: false, linger: 0}) do
      setopts(socket, options.tcp_options)
    end
  end

  @spec setopts(:socket.socket(), list()) :: :ok | {:error, term()}
  def setopts(socket, options) do
    Enum.reduce_while(options, :ok, fn option, :ok ->
      case setopt(socket, option) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp setopt(_socket, family) when family in [:inet, :inet6], do: :ok
  defp setopt(_socket, {key, _}) when key in [:ip, :port], do: :ok
  defp setopt(socket, {:buffer, value}), do: :socket.setopt(socket, :otp, :rcvbuf, value)
  defp setopt(socket, {:tclass, value}), do: :socket.setopt(socket, :ipv6, :tclass, value)
  defp setopt(socket, {:nodelay, value}), do: :socket.setopt(socket, :tcp, :nodelay, value)
  defp setopt(socket, {:keepalive, value}), do: :socket.setopt(socket, :socket, :keepalive, value)
  defp setopt(socket, {:sndbuf, value}), do: :socket.setopt(socket, :socket, :sndbuf, value)
  defp setopt(socket, {:recbuf, value}), do: :socket.setopt(socket, :socket, :rcvbuf, value)
  defp setopt(socket, {:tos, value}), do: :socket.setopt(socket, :ip, :tos, value)
  defp setopt(socket, {:priority, value}), do: :socket.setopt(socket, :socket, :priority, value)
  defp setopt(_socket, option), do: {:error, {:options, {option, :private_socket_unsupported}}}

  @type receive_result ::
          {:ok, binary()}
          | {:select, :socket.select_info() | {:socket.select_info(), binary()}}
          | {:select_read, {:socket.select_info(), binary()}}
          | {:completion, :socket.completion_info()}
          | {:error, atom() | :socket.invalid() | {atom() | :socket.invalid(), term()}}
  @spec receive_nowait(:socket.socket()) :: receive_result()
  def receive_nowait(socket), do: :socket.recv(socket, 0, :nowait)

  @spec cancel_read(:socket.socket(), term()) :: term()
  def cancel_read(_socket, nil), do: :ok
  def cancel_read(socket, info), do: :socket.cancel(socket, info)

  @spec send_bytes(:socket.socket(), iodata(), boolean(), integer()) :: :ok | {:error, term()}
  def send_bytes(socket, bytes, shutdown?, deadline)
      when is_integer(deadline) or deadline == :infinity do
    # No retry of protected bytes after partial native acceptance. The socket
    # implementation continues one send under one absolute deadline internally.
    with {:ok, remaining} <- remaining({:abs_ms, deadline}),
         :ok <- :socket.send(socket, bytes, remaining) do
      case remaining({:abs_ms, deadline}) do
        {:ok, _} -> if shutdown?, do: :socket.shutdown(socket, :write), else: :ok
        {:error, :deadline_exceeded} -> {:error, :timeout}
      end
    else
      {:error, {reason, _rest}} -> {:error, reason}
      {:error, :deadline_exceeded} -> {:error, :timeout}
      {:error, _} = error -> error
    end
  end

  @spec peername(:socket.socket()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def peername(socket), do: endpoint(:socket.peername(socket))

  @doc false
  def sockname(socket), do: endpoint(:socket.sockname(socket))

  @spec abort_on_close(:socket.socket()) :: :ok | {:error, atom() | :socket.invalid()}
  def abort_on_close(socket),
    do: :socket.setopt(socket, :socket, :linger, %{onoff: true, linger: 0})

  defp endpoint({:ok, %{addr: ip, port: port}}), do: {:ok, {ip, port}}
  defp endpoint({:error, _} = error), do: error

  @doc false
  def connect_public(receipt, host, port, options, original) do
    family = if :inet6 in options.tcp_options, do: :inet6, else: :inet
    host = if is_binary(host), do: String.to_charlist(host), else: host
    # Shared resolver helpers are outside the provider resource set. Every raw
    # candidate still requires the original observer's allocation fence.
    with {:ok, addresses} <- :inet.getaddrs(host, family, SSL.Options.remaining(original)),
         true <- SSL.Options.remaining(original) > 0,
         {:ok, token} <- Observer.reserve_child(receipt, :tcp, public_budget(original)) do
      connect_candidates(receipt, addresses, port, options, original, family, token)
    else
      false -> {:error, :timeout}
      error -> error
    end
  end

  defp connect_candidates(receipt, [ip | rest], port, options, original, family, token) do
    allocation_budget = public_budget(original)

    with true <- SSL.Options.remaining(original) > 0,
         {:ok, socket} <- :socket.open(family, :stream, :tcp) do
      with :use <- Observer.enroll_socket(receipt, token, socket, allocation_budget),
           :ok <- prepare(socket, options),
           :ok <- bind(socket, family, options.tcp_options) do
        result =
          :socket.connect(
            socket,
            %{family: family, addr: ip, port: port},
            SSL.Options.remaining(original)
          )

        case result do
          :ok ->
            public_connected(socket, receipt, original)

          {:error, reason} when reason in [:einval, :timeout] or rest == [] ->
            _ = Observer.record_socket_connect_phase(receipt, socket, reason, allocation_budget)
            {:error, reason}

          {:error, _reason} ->
            connect_next_candidate(receipt, socket, rest, port, options, original, family)
        end
      else
        :stop -> {:error, :admission_closed}
        error -> error
      end
    else
      false -> {:error, :timeout}
      error -> error
    end
  catch
    _, _ -> {:error, :invalid_arguments}
  end

  defp connect_candidates(_receipt, [], _port, _options, _original, _family, _token),
    do: {:error, :einval}

  defp public_connected(socket, receipt, original) do
    if Process.alive?(Receipt.observer(receipt)) and SSL.Options.remaining(original) > 0,
      do: {:ok, socket},
      else: {:error, :timeout}
  end

  defp connect_next_candidate(receipt, socket, rest, port, options, original, family) do
    with {:ok, nonce} <-
           Observer.begin_candidate_close(receipt, socket, public_budget(original)),
         :ok <- close_owned(socket),
         {:ok, next} <-
           Observer.finish_candidate_close(receipt, nonce, public_budget(original)) do
      connect_candidates(receipt, rest, port, options, original, family, next)
    end
  end

  defp bind(socket, family, options) do
    if Keyword.has_key?(options, :ip) or Keyword.has_key?(options, :port) do
      address =
        Keyword.get(
          options,
          :ip,
          if(family == :inet, do: {0, 0, 0, 0}, else: {0, 0, 0, 0, 0, 0, 0, 0})
        )

      :socket.bind(socket, %{family: family, addr: address, port: Keyword.get(options, :port, 0)})
    else
      :ok
    end
  end

  defp public_budget(:infinity), do: {:abs_ms, System.monotonic_time(:millisecond) + 1_000}

  defp public_budget(deadline),
    do: {:abs_ms, min(deadline, System.monotonic_time(:millisecond) + 1_000)}

  # Private raw IPv4 Socket constructor, not a gen_tcp backend handle or TLS readiness.
  # The original observer enrolls this exact object before the native connect call.
  @spec connect(Receipt.t(), :inet.ip4_address(), 1..65_535, {:abs_ms, integer()}) ::
          {:ok, :socket.socket()} | {:error, term()}
  def connect(receipt, {_, _, _, _} = ip, port, {:abs_ms, deadline} = budget)
      when is_integer(port) and port in 1..65_535 and is_integer(deadline) do
    with true <- Enum.all?(Tuple.to_list(ip), &(is_integer(&1) and &1 in 0..255)),
         {:ok, _} <- remaining(budget),
         observer = Receipt.observer(receipt),
         true <- node(observer) == node(),
         {:ok, token} <- Observer.reserve_child(receipt, :tcp, budget),
         {:ok, _} <- remaining(budget),
         {:ok, socket} <- :socket.open(:inet, :stream, :tcp) do
      enroll(receipt, observer, token, socket, ip, port, budget)
    else
      false -> {:error, :invalid_arguments}
      {:error, _} = error -> error
    end
  end

  def connect(_, _, _, _), do: {:error, :invalid_arguments}

  @spec close_owned(:socket.socket()) :: :ok | {:error, term()}
  def close_owned(socket) do
    case :socket.getopt(socket, :otp, :controlling_process) do
      {:ok, owner} when owner == self() -> :socket.close(socket)
      {:ok, _owner} -> {:error, :not_owner}
      {:error, _} = error -> error
    end
  catch
    _, _ -> {:error, :close_unconfirmed}
  end

  defp enroll(receipt, observer, token, socket, ip, port, budget) do
    with :use <- Observer.enroll_socket(receipt, token, socket, budget),
         {:ok, milliseconds} <- remaining(budget),
         true <- Process.alive?(observer) do
      connect_enrolled(receipt, observer, socket, ip, port, milliseconds, budget)
    else
      :stop -> close_error(socket, {:error, :admission_closed})
      false -> close_error(socket, {:error, :acceptance_unconfirmed})
      {:error, _} = error -> close_error(socket, error)
    end
  catch
    kind, reason ->
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp connect_enrolled(receipt, observer, socket, ip, port, milliseconds, budget) do
    address = %{family: :inet, addr: ip, port: port}

    case :socket.connect(socket, address, milliseconds) do
      :ok ->
        connected(socket, observer, budget)

      {:error, reason} = error ->
        record_failure(receipt, socket, reason, budget)
        close_error(socket, error)
    end
  end

  defp connected(socket, observer, budget) do
    with {:ok, _} <- remaining(budget),
         true <- Process.alive?(observer) do
      {:ok, socket}
    else
      false -> close_error(socket, {:error, :acceptance_unconfirmed})
      {:error, _} = error -> close_error(socket, error)
    end
  end

  # Publish while ownership is still attributable. Closing first can retire the
  # original observer; native errno and this RPC never substitute for cleanup.
  defp record_failure(receipt, socket, reason, budget)
       when reason in [:econnrefused, :enetunreach, :ehostunreach] do
    _ = Observer.record_socket_connect_failure(receipt, socket, reason, budget)
    :ok
  catch
    _, _ -> :ok
  end

  defp record_failure(_receipt, _socket, _reason, _budget), do: :ok

  # Every error returns to the enrolled allocator's stopping path. Let native
  # ownership exit close it; explicit close here can race observer retirement.
  defp close_error(_socket, error), do: error

  defp remaining({:abs_ms, :infinity}), do: {:ok, :infinity}

  defp remaining({:abs_ms, deadline}) do
    case deadline - System.monotonic_time(:millisecond) do
      value when value > 0 -> {:ok, min(value, 0xFFFFFFFF)}
      _ -> {:error, :deadline_exceeded}
    end
  end
end
