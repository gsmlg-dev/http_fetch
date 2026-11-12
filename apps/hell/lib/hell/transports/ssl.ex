defmodule Hell.Transports.SSL do
  @moduledoc """
  Defines a `Hell.Transport` implementation based on TLS 1.3 over TCP as
  provided by the `ex_ssl` package's `SSL` module. For the most part, users of
  Hell will only ever need to deal with this module via `transport_options`
  passed to `Hell` at startup time.

  Only TLS 1.3 is supported. The accepted TLS options are:

  * `certfile` / `keyfile`, `cert` / `key`, `certs_keys` and `password`: the
    server certificate identity. One identity, `sni_hosts` or `sni_fun` is
    required
  * `sni_hosts` and `sni_fun`: per-server-name identities
  * `alpn_preferred_protocols`: the ALPN protocols the server selects from
  * `ciphers`: a subset of the TLS 1.3 cipher suites
  * `versions`: only `[:"tlsv1.3"]`
  * `verify: :verify_peer` with `cacerts` or `cacertfile`, `fail_if_no_peer_cert`
    and `depth`: client certificate authentication (mTLS). The validated client
    leaf is available through `Hell.Socket.peercert/1`. The default is
    `verify: :verify_none`
  * `active_chunk_size`: a positive integer bounding the plaintext bytes in
    each active-once delivery (and so each `c:Hell.Handler.handle_data/3`
    call); remaining bytes follow in order on later deliveries. The default
    `:infinity` delivers everything buffered. It can also be changed with
    `Hell.Socket.setopts/2`

  Other OTP `:ssl` options (such as `verify_fun`, `honor_cipher_order` or TLS 1.2
  `versions`) are rejected with `{:error, {:unsupported_option, key}}`. Every
  remaining option is a `:gen_tcp` listen option, such as `ip`:

  * `{1, 2, 3, 4}` for IPv4 addresses
  * `{1, 2, 3, 4, 5, 6, 7, 8}` for IPv6 addresses
  * `:loopback` for local loopback
  * `:any` for all interfaces (ie: `0.0.0.0`)
  * `{:local, "/path/to/socket"}` for a Unix domain socket. If this option is used, the `port`
    option *must* be set to `0`.

  Unless overridden, this module uses the following default options:

  ```elixir
  backlog: 1024,
  nodelay: true,
  send_timeout: 30_000,
  send_timeout_close: true,
  reuseaddr: true
  ```

  The `nodelay` default is omitted for Unix domain sockets, since it is a
  TCP-specific option.

  The following options are required for the proper operation of Hell
  and cannot be overridden:

  ```elixir
  mode: :binary,
  active: false
  ```

  `upgrade/2,3` accepts the TLS options above plus `:inet.setopts/2` carrier
  options; listen-only options such as `ip` or `backlog` are not valid there.
  """

  @type options() :: keyword()
  @type listener_socket() :: SSL.ListenSocket.t()
  @type socket() :: SSL.Socket.t()

  @behaviour Hell.Transport

  # Default chunk size: 1MB - balances memory usage vs send overhead
  @sendfile_chunk_size 1024 * 1024

  @impl Hell.Transport
  @spec listen(:inet.port_number(), options()) :: Hell.Transport.on_listen()
  def listen(port, user_options) do
    SSL.listen(port, Hell.Transport.resolve_options(user_options))
  end

  @impl Hell.Transport
  @spec accept(listener_socket()) :: Hell.Transport.on_accept()
  def accept(listener_socket), do: SSL.transport_accept(listener_socket)

  @impl Hell.Transport
  @spec handshake(socket()) :: Hell.Transport.on_handshake()
  def handshake(socket), do: handshake(socket, :infinity)

  @impl Hell.Transport
  @spec handshake(socket(), timeout()) :: Hell.Transport.on_handshake()
  def handshake(socket, timeout) do
    SSL.handshake(socket, timeout)
  end

  @impl Hell.Transport
  @spec upgrade(:gen_tcp.socket(), options()) :: Hell.Transport.on_upgrade()
  def upgrade(socket, opts), do: upgrade(socket, opts, :infinity)

  @impl Hell.Transport
  @spec upgrade(:gen_tcp.socket(), options(), timeout()) :: Hell.Transport.on_upgrade()
  def upgrade(socket, opts, timeout) do
    case SSL.handshake(socket, opts, timeout) do
      {:ok, socket, _protocol_extensions} -> {:ok, socket}
      other -> other
    end
  end

  @impl Hell.Transport
  @spec controlling_process(socket(), pid()) :: Hell.Transport.on_controlling_process()
  defdelegate controlling_process(socket, pid), to: SSL

  @impl Hell.Transport
  @spec recv(socket(), non_neg_integer(), timeout()) :: Hell.Transport.on_recv()
  defdelegate recv(socket, length, timeout), to: SSL

  @impl Hell.Transport
  @spec send(socket(), iodata()) :: Hell.Transport.on_send()
  defdelegate send(socket, data), to: SSL

  @impl Hell.Transport
  @spec sendfile(
          socket(),
          filename :: String.t(),
          offset :: non_neg_integer(),
          length :: non_neg_integer()
        ) :: Hell.Transport.on_sendfile()
  def sendfile(socket, filename, offset, length) do
    # We can't use :file.sendfile here since it works on clear sockets, not TLS sockets.
    # Build our own version with chunking for large files.
    case :file.open(filename, [:read, :raw, :binary]) do
      {:ok, fd} ->
        try do
          sendfile_loop(socket, fd, offset, length, 0)
        after
          :file.close(fd)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp sendfile_loop(_socket, _fd, _offset, sent, sent) when 0 != sent do
    {:ok, sent}
  end

  defp sendfile_loop(socket, fd, offset, length, sent) do
    with read_size <- chunk_size(length, sent, @sendfile_chunk_size),
         {:ok, data} <- :file.pread(fd, offset, read_size),
         :ok <- SSL.send(socket, data) do
      now_sent = byte_size(data)
      sendfile_loop(socket, fd, offset + now_sent, length, sent + now_sent)
    else
      :eof ->
        {:ok, sent}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp chunk_size(0, _sent, chunk_size), do: chunk_size
  defp chunk_size(length, sent, chunk), do: min(length - sent, chunk)

  @impl Hell.Transport
  @spec getopts(socket() | listener_socket(), Hell.Transport.socket_get_options()) ::
          Hell.Transport.on_getopts()
  defdelegate getopts(socket, options), to: SSL

  @impl Hell.Transport
  @spec setopts(socket(), Hell.Transport.socket_set_options()) ::
          Hell.Transport.on_setopts()
  defdelegate setopts(socket, options), to: SSL

  @impl Hell.Transport
  @spec shutdown(socket(), Hell.Transport.way()) ::
          Hell.Transport.on_shutdown()
  defdelegate shutdown(socket, way), to: SSL

  @impl Hell.Transport
  @spec close(socket() | listener_socket()) :: Hell.Transport.on_close()
  defdelegate close(socket), to: SSL

  @impl Hell.Transport
  @spec sockname(socket() | listener_socket()) :: Hell.Transport.on_sockname()
  defdelegate sockname(socket), to: SSL

  @impl Hell.Transport
  @spec peername(socket()) :: Hell.Transport.on_peername()
  defdelegate peername(socket), to: SSL

  @impl Hell.Transport
  @spec peercert(socket()) :: Hell.Transport.on_peercert()
  defdelegate peercert(socket), to: SSL

  @impl Hell.Transport
  @spec secure?() :: true
  def secure?, do: true

  @impl Hell.Transport
  @spec getstat(socket()) :: Hell.Transport.socket_stats()
  defdelegate getstat(socket), to: SSL

  @impl Hell.Transport
  @spec negotiated_protocol(socket()) :: Hell.Transport.on_negotiated_protocol()
  defdelegate negotiated_protocol(socket), to: SSL

  @impl Hell.Transport
  @spec connection_information(socket()) :: Hell.Transport.on_connection_information()
  defdelegate connection_information(socket), to: SSL
end
