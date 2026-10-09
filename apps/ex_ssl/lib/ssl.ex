defmodule SSL do
  @moduledoc """
  OTP `:ssl`-compatible client facade for the implemented `ex_ssl` feature subset.

  This experimental client supports TLS 1.3 and explicit bounded TLS 1.2, binary raw sockets, passive and
  active-once delivery, application ownership transfer, authenticated ALPN,
  bounded streaming writes, and mandatory peer verification. These restricted
  defaults differ from OTP. Unsupported options return explicit
  `{:error, {:options, reason}}` errors.

  STARTTLS callers must own a passive binary/raw TCP socket, fully consume and
  validate the application's upgrade response, and reject any buffered plaintext.
  Supply `server_name_indication` as the certificate reference DNS name, or use
  `ex_ssl: [reference_identity: {:ip, address} | {:dns_id, name}]` to verify a
  separate IP/DNS identity independently of SNI and the TCP destination. Once
  upgrade is attempted, an owned socket is closed on failure; plaintext must
  never resume. A socket belonging to another process is left untouched.
  """
  import Kernel, except: [send: 2]
  alias SSL.{Connection, IodataCursor, Options, Socket}

  @spec connect(:gen_tcp.socket(), list()) :: {:ok, Socket.t()} | {:error, term()}
  def connect(tcp_socket, options), do: connect(tcp_socket, options, :infinity)

  @spec connect(term(), term(), term()) :: {:ok, Socket.t()} | {:error, term()}
  def connect(host, port, options) when is_integer(port),
    do: connect(host, port, options, :infinity)

  def connect(tcp_socket, options, timeout) do
    with :ok <- owned_socket(tcp_socket) do
      result =
        with {:ok, deadline} <- Options.deadline(timeout),
             {:ok, options} <- Options.normalize(:upgrade, options),
             :ok <- upgrade_boundary(tcp_socket),
             do: handoff(tcp_socket, options, deadline)

      close_on_error(result, tcp_socket)
    end
  end

  @spec connect(term(), :inet.port_number(), list(), timeout()) ::
          {:ok, Socket.t()} | {:error, term()}
  def connect(host, port, options, timeout) when is_integer(port) and port in 0..65_535 do
    with {:ok, deadline} <- Options.deadline(timeout),
         {:ok, options} <- Options.normalize(host, options),
         {:ok, _} <- Application.ensure_all_started(:ex_ssl),
         {:ok, tcp_socket} <-
           :gen_tcp.connect(
             tcp_host(host),
             port,
             [
               :binary,
               active: false,
               packet: :raw,
               send_timeout: options.send_timeout,
               send_timeout_close: options.send_timeout_close,
               buffer: 16_640
             ] ++ options.tcp_options,
             Options.remaining(deadline)
           ) do
      close_on_error(handoff(tcp_socket, options, deadline), tcp_socket)
    end
  catch
    :exit, _ -> {:error, :closed}
    :error, :badarg -> {:error, :badarg}
  end

  def connect(_, _, _, _), do: {:error, :badarg}

  @doc "Writes iodata as one ordered logical write. Concurrent writes return `:busy`."
  @spec send(Socket.t(), iodata()) :: :ok | {:error, term()}
  def send(socket, data) do
    with {:ok, cursor, size} <- IodataCursor.new(data),
         {:ok, token} <- call(socket, :reserve_write),
         do: call(socket, {:send, token, cursor, size})
  end

  @doc """
  Enables bounded response reads during an application send.

  This owner-only, idempotent operation applies to an established open socket.
  It requires a finite send timeout and rejects later infinite-timeout sends.
  Reads may progress while one already-protected application output job is
  pending. Handshake, control and shutdown output barriers remain in place;
  inbound protocol traffic requiring output on a busy writer fails closed.
  Normal sender death still fails the connection closed.
  """
  @spec enable_duplex_reads(Socket.t()) :: :ok | {:error, term()}
  def enable_duplex_reads(socket), do: call(socket, :enable_duplex_reads)

  @doc """
  Permanently abandons application writes while retaining response reads.

  Only the controlling owner may call this on an established connection. An
  admitted send settles as `{:error, :write_abandoned}`; unsent plaintext is discarded and
  future sends are rejected. A bounded already-protected application output job may
  still finish its original transport write under its original finite deadline.
  The job may include an automatic KeyUpdate followed by one application record. It is
  never re-encrypted or replayed. Reads keep their existing byte bounds; inbound
  protocol traffic that requires output while this record is pending fails closed.

  Call `close/1` after consuming the response, or to abort the pending record.
  Ordinary sender death continues to fail the connection closed unless the owner
  explicitly abandons writes before the sender dies.
  """
  @spec abandon_send(Socket.t()) :: :ok | {:error, term()}
  def abandon_send(socket), do: call(socket, :abandon_send)

  @doc "Changes supported delivery, send, and mutable TCP options after validation."
  @spec setopts(Socket.t(), list()) :: :ok | {:error, term()}
  def setopts(socket, options) do
    with {:ok, normalized} <- Options.normalize_setopts(options),
         do: call(socket, {:setopts, normalized})
  end

  @doc "Transfers application ownership while the TLS process retains the TCP socket."
  @spec controlling_process(Socket.t(), pid()) :: :ok | {:error, term()}
  def controlling_process(socket, owner) when is_pid(owner),
    do: call(socket, {:controlling_process, owner})

  def controlling_process(_, _), do: {:error, :badarg}

  @doc "Returns the authenticated ALPN selection, if the server negotiated one."
  @spec negotiated_protocol(Socket.t()) :: {:ok, binary()} | {:error, term()}
  def negotiated_protocol(socket), do: call(socket, :negotiated_protocol)

  @doc "Returns the supported non-secret connection metadata."
  @spec connection_information(Socket.t()) :: {:ok, keyword()} | {:error, term()}
  def connection_information(socket), do: connection_information(socket, SSL.Diagnostics.keys())

  @spec connection_information(Socket.t(), term()) :: {:ok, keyword()} | {:error, term()}
  def connection_information(socket, keys) do
    with :ok <- SSL.Diagnostics.validate_keys(keys),
         do: call(socket, {:connection_information, keys})
  end

  @doc "Returns the authenticated server leaf certificate as DER."
  @spec peercert(Socket.t()) :: {:ok, binary()} | {:error, term()}
  def peercert(socket), do: call(socket, :peercert)

  @doc "Returns the live TCP peer address and port."
  @spec peername(Socket.t()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def peername(socket), do: call(socket, :peername)

  @doc "Returns the live local TCP address and port."
  @spec sockname(Socket.t()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def sockname(socket), do: call(socket, :sockname)

  @doc "Receives available bytes for length 0, or exactly length bytes. Timeout retains buffered data."
  @spec recv(Socket.t(), non_neg_integer(), timeout()) :: {:ok, binary()} | {:error, term()}
  def recv(socket, length, timeout \\ :infinity)

  def recv(socket, length, timeout) when is_integer(length) and length >= 0 do
    with {:ok, deadline} <- Options.deadline(timeout), do: call(socket, {:recv, length, deadline})
  end

  def recv(_, _, _), do: {:error, :badarg}

  @doc "Closes the connection. Closing an already closed handle succeeds."
  @spec close(Socket.t()) :: :ok | {:error, term()}
  def close(%Socket{} = socket) do
    case call(socket, :close) do
      {:error, :closed} -> :ok
      {:error, :econnreset} -> :ok
      result -> result
    end
  end

  def close(_), do: {:error, :badarg}

  defp call(%Socket{pid: pid, ref: ref} = socket, request) do
    :gen_statem.call(pid, {ref, request}, :infinity)
  catch
    :exit, _ -> {:error, Socket.terminal_error(socket)}
  end

  defp call(_, _), do: {:error, :badarg}

  defp handoff(tcp, options, deadline) do
    with true <- Options.remaining(deadline) != 0,
         {:ok, _} <- Application.ensure_all_started(:ex_ssl) do
      ref = make_ref()
      status = :atomics.new(1, signed: false)

      case DynamicSupervisor.start_child(
             SSL.ConnectionSupervisor,
             {Connection, {self(), ref, status, options, deadline}}
           ) do
        {:ok, pid} ->
          socket = %Socket{pid: pid, ref: ref, status: status}

          case :gen_tcp.controlling_process(tcp, pid) do
            :ok ->
              call(socket, {:attach, tcp})

            {:error, reason} ->
              _ = DynamicSupervisor.terminate_child(SSL.ConnectionSupervisor, pid)
              {:error, reason}
          end

        {:error, _} ->
          {:error, :closed}
      end
    else
      false -> {:error, :timeout}
      {:error, _} = error -> error
    end
  end

  defp owned_socket(socket) when is_port(socket) do
    case :erlang.port_info(socket, :connected) do
      {:connected, owner} when owner == self() -> :ok
      {:connected, _} -> {:error, :not_owner}
      :undefined -> {:error, :closed}
    end
  end

  defp owned_socket(_), do: {:error, :badarg}

  defp upgrade_boundary(tcp) do
    with {:ok, options} <- :inet.getopts(tcp, [:active, :packet, :mode]),
         true <-
           options[:active] == false and options[:packet] in [0, :raw] and
             options[:mode] == :binary,
         false <- delivered_tcp_message?(tcp) do
      case :gen_tcp.recv(tcp, 0, 0) do
        {:error, :timeout} -> :ok
        {:ok, _} -> {:error, :pending_plaintext}
        {:error, reason} -> {:error, reason}
      end
    else
      true -> {:error, :pending_plaintext}
      false -> {:error, {:options, :unsupported_tcp_state}}
      {:error, _} = error -> error
    end
  end

  defp delivered_tcp_message?(tcp) do
    {:messages, messages} = Process.info(self(), :messages)

    Enum.any?(messages, fn
      {:tcp, ^tcp, _} -> true
      {:tcp_closed, ^tcp} -> true
      {:tcp_error, ^tcp, _} -> true
      _ -> false
    end)
  end

  defp close_on_error({:error, _} = error, tcp) do
    :gen_tcp.close(tcp)
    error
  end

  defp close_on_error(result, _tcp), do: result
  defp tcp_host(host) when is_binary(host), do: String.to_charlist(host)
  defp tcp_host(host), do: host
end
