defmodule Hell.Transports.TCP do
  @moduledoc """
  Defines a `Hell.Transport` implementation based on clear TCP sockets
  as provided by Erlang's `:gen_tcp` module. For the most part, users of Hell
  will only ever need to deal with this module via `transport_options`
  passed to `Hell` at startup time. A complete list of such options
  is defined via the `t::gen_tcp.listen_option/0` type. This list can be somewhat
  difficult to decipher; by far the most common value to pass to this transport
  is the following:

  * `ip`:  The IP to listen on. Can be specified as:
    * `{1, 2, 3, 4}` for IPv4 addresses
    * `{1, 2, 3, 4, 5, 6, 7, 8}` for IPv6 addresses
    * `:loopback` for local loopback
    * `:any` for all interfaces (i.e.: `0.0.0.0`)
    * `{:local, "/path/to/socket"}` for a Unix domain socket. If this option is used,
      the `port` option *must* be set to `0`

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
  """

  @type options() :: [:gen_tcp.listen_option()]
  @type listener_socket() :: :inet.socket()
  @type socket() :: :inet.socket()

  @behaviour Hell.Transport

  @impl Hell.Transport
  @spec listen(:inet.port_number(), [:inet.inet_backend() | :gen_tcp.listen_option()]) ::
          Hell.Transport.on_listen()
  def listen(port, user_options) do
    resolved_options = Hell.Transport.resolve_options(user_options)

    # `inet_backend`, if present, needs to be the first option
    sorted_options =
      Enum.sort(resolved_options, fn
        _, {:inet_backend, _} -> false
        _, _ -> true
      end)

    :gen_tcp.listen(port, sorted_options)
  end

  @impl Hell.Transport
  @spec accept(listener_socket()) :: Hell.Transport.on_accept()
  defdelegate accept(listener_socket), to: :gen_tcp

  @impl Hell.Transport
  @spec handshake(socket()) :: Hell.Transport.on_handshake()
  def handshake(socket), do: {:ok, socket}

  @impl Hell.Transport
  @spec handshake(socket(), timeout()) :: Hell.Transport.on_handshake()
  def handshake(socket, _timeout), do: {:ok, socket}

  @impl Hell.Transport
  @spec upgrade(socket(), options()) :: Hell.Transport.on_upgrade()
  def upgrade(_, _), do: {:error, :unsupported_upgrade}

  @impl Hell.Transport
  @spec controlling_process(socket(), pid()) :: Hell.Transport.on_controlling_process()
  defdelegate controlling_process(socket, pid), to: :gen_tcp

  @impl Hell.Transport
  @spec recv(socket(), non_neg_integer(), timeout()) :: Hell.Transport.on_recv()
  defdelegate recv(socket, length, timeout), to: :gen_tcp

  @impl Hell.Transport
  @spec send(socket(), iodata()) :: Hell.Transport.on_send()
  defdelegate send(socket, data), to: :gen_tcp

  @impl Hell.Transport
  @spec sendfile(
          socket(),
          filename :: String.t(),
          offset :: non_neg_integer(),
          length :: non_neg_integer()
        ) :: Hell.Transport.on_sendfile()
  def sendfile(socket, filename, offset, length) do
    case :file.open(filename, [:read, :raw, :binary]) do
      {:ok, fd} ->
        try do
          :file.sendfile(fd, socket, offset, length, [])
        after
          :file.close(fd)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl Hell.Transport
  @spec getopts(socket(), Hell.Transport.socket_get_options()) ::
          Hell.Transport.on_getopts()
  defdelegate getopts(socket, options), to: :inet

  @impl Hell.Transport
  @spec setopts(socket(), Hell.Transport.socket_set_options()) ::
          Hell.Transport.on_setopts()
  defdelegate setopts(socket, options), to: :inet

  @impl Hell.Transport
  @spec shutdown(socket(), Hell.Transport.way()) ::
          Hell.Transport.on_shutdown()
  defdelegate shutdown(socket, way), to: :gen_tcp

  @impl Hell.Transport
  @spec close(socket() | listener_socket()) :: :ok
  defdelegate close(socket), to: :gen_tcp

  @impl Hell.Transport
  @spec sockname(socket() | listener_socket()) :: Hell.Transport.on_sockname()
  defdelegate sockname(socket), to: :inet

  @impl Hell.Transport
  @spec peername(socket()) :: Hell.Transport.on_peername()
  defdelegate peername(socket), to: :inet

  @impl Hell.Transport
  @spec peercert(socket()) :: Hell.Transport.on_peercert()
  def peercert(_socket), do: {:error, :not_secure}

  @impl Hell.Transport
  @spec secure?() :: false
  def secure?, do: false

  @impl Hell.Transport
  @spec getstat(socket()) :: Hell.Transport.socket_stats()
  defdelegate getstat(socket), to: :inet

  @impl Hell.Transport
  @spec negotiated_protocol(socket()) :: Hell.Transport.on_negotiated_protocol()
  def negotiated_protocol(_socket), do: {:error, :protocol_not_negotiated}

  @impl Hell.Transport
  @spec connection_information(socket()) :: Hell.Transport.on_connection_information()
  def connection_information(_socket), do: {:error, :not_secure}
end
