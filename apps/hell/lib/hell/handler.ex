defmodule Hell.Handler do
  @moduledoc """
  `Hell.Handler` defines the behaviour required of the application layer of a Hell server. When starting a
  Hell server, you must pass the name of a module implementing this behaviour as the `handler_module` parameter.
  Hell will then use the specified module to handle each connection that is made to the server.

  The lifecycle of a Handler instance is as follows:

  1. After a client connection to a Hell server is made, Hell will complete the initial setup of the
  connection (performing a TLS handshake, for example), and then call `c:handle_connection/2`.

  2. A handler implementation may choose to process a client connection within the `c:handle_connection/2` callback by
  calling functions against the passed `Hell.Socket`. In many cases, this may be all that may be required of
  an implementation & the value `{:close, state}` can be returned which will cause Hell to close the connection
  to the client.

  3. In cases where the server wishes to keep the connection open and wait for subsequent requests from the client on the
  same socket, it may elect to return `{:continue, state}`. This will cause Hell to wait for client data
  asynchronously; `c:handle_data/3` will be invoked when the client sends more data.

  4. In the meantime, the process which is hosting the connection is idle & able to receive messages sent from elsewhere in your
  application as needed. The implementation included in the `use Hell.Handler` macro uses a `GenServer` structure,
  so you may implement such behaviour via standard `GenServer` patterns. Note that in these cases that state is provided (and
  must be returned) in a `{socket, state}` format, where the second tuple is the same state value that is passed to the various `handle_*` callbacks
  defined on this behaviour. This is illustrated in the following example:

      ```elixir
      defmodule ExampleHandler do
        use Hell.Handler

        # ...handle_data and other Handler callbacks

        @impl GenServer
        def handle_call(msg, from, {socket, state}) do
          # Do whatever you'd like with msg & from
          {:reply, :ok, {socket, state}}
        end

        @impl GenServer
        def handle_cast(msg, {socket, state}) do
          # Do whatever you'd like with msg
          {:noreply, {socket, state}}
        end

        @impl GenServer
        def handle_info(msg, {socket, state}) do
          # Do whatever you'd like with msg
          {:noreply, {socket, state}}
        end
      end
      ```

  Note that previous versions of upstream Thousand Island required you to return the value of
  socket.read_timeout as the third element in the callback tuple. As of upstream Thousand Island 1.5.0,
  network-related timeouts are handled entirely internally and as such this option retains its
  OTP-native semantic of representing an option timeout between *any* message received by this
  Handler, either network or local. In short, unless you specifically care about timeouts between
  local mailbox messages, you can safely omit a timeout from your return tuples and the network
  facing aspects of Hell will continue to have correct timeout behaviour.

  To change the persistent read-idle timeout from an owner-side GenServer callback such as
  `c:GenServer.handle_call/3` or `c:GenServer.handle_info/2`, use `set_read_timeout/2` and retain
  its returned socket in the `{socket, state}` tuple.

  # Pausing Input

  A handler can stop reading from its connection, for example while downstream capacity is
  exhausted, and resume later without losing or reordering client bytes:

  * From `c:handle_connection/2` or `c:handle_data/3`, return `{:pause, state}` (or
    `{:pause, state, {:continue, continue}}`) instead of a `:continue` result. Hell does not
    re-arm `active: :once` and does not call `c:handle_data/3` again until input is resumed.
  * From an owner-side GenServer callback such as `c:GenServer.handle_info/2`, call
    `pause_input/1` and retain its returned socket in the `{socket, state}` tuple. A chunk the
    transport had already delivered to the mailbox before the call is retained instead of being
    passed to `c:handle_data/3`.
  * To resume, call `resume_input/1` from an owner-side GenServer callback and retain its
    returned socket. Retained data is delivered to `c:handle_data/3` first, in its original
    order, before Hell reads anything new from the transport.

  A paused connection is not closed by the read-idle timeout: pausing cancels the read-idle
  timer and `resume_input/1` starts a fresh interval of the connection's persistent
  `read_timeout`. One-shot timeouts returned before the pause are discarded.
  `set_read_timeout/2` while paused only records the new persistent value, which applies on
  resume. A peer close or transport error that the transport reports while input is paused and
  no data is retained stops the connection as usual; one that follows retained data is
  processed after that data on resume. Do not call `Hell.Socket.recv/3` or change the socket's
  `:active` option while input is paused, since that would bypass the retained data.

  For example, a credit-based handler can pause when it runs out of credit and resume when
  credit is granted:

      def handle_data(data, _socket, state) do
        state = enqueue(state, data)
        if state.credit > 0, do: {:continue, state}, else: {:pause, state}
      end

      def handle_info({:credit, credit}, {socket, state}) do
        {:noreply, {Hell.Handler.resume_input(socket), %{state | credit: credit}}}
      end

  It is fully supported to intermix synchronous `Hell.Socket.recv` calls with async return values from `c:handle_connection/2`
  and `c:handle_data/3` callbacks, however it is critical to note that the timeouts between the two
  are completely separate. The `read_timeout` parameter only applies to reads
  as observed by `handle_data/3` callbacks, and only applies to the duration *between*
  Hell.Handler callbacks.

  # Example

  A simple example of a Hello World server is as follows:

  ```elixir
  defmodule HelloWorld do
    use Hell.Handler

    @impl Hell.Handler
    def handle_connection(socket, state) do
      Hell.Socket.send(socket, "Hello, World")
      {:close, state}
    end
  end
  ```

  Another example of a server that echoes back all data sent to it is as follows:

  ```elixir
  defmodule Echo do
    use Hell.Handler

    @impl Hell.Handler
    def handle_data(data, socket, state) do
      Hell.Socket.send(socket, data)
      {:continue, state}
    end
  end
  ```

  Note that in this example there is no `c:handle_connection/2` callback defined. The default implementation of this
  callback will simply return `{:continue, state}`, which is appropriate for cases where the client is the first
  party to communicate.

  Another example of a server which can send and receive messages asynchronously is as follows:

  ```elixir
  defmodule Messenger do
    use Hell.Handler

    @impl Hell.Handler
    def handle_data(msg, _socket, state) do
      IO.puts(msg)
      {:continue, state}
    end

    def handle_info({:send, msg}, {socket, state}) do
      Hell.Socket.send(socket, msg)
      {:noreply, {socket, state}}
    end
  end
  ```

  Note that in this example we make use of the fact that the handler process is really just a GenServer to send it messages
  which are able to make use of the underlying socket. This allows for bidirectional sending and receiving of messages in
  an asynchronous manner.

  You can pass options to the default handler underlying `GenServer` by passing a `genserver_options` key to `Hell.start_link/1`
  containing `t:GenServer.options/0` to be passed to the last argument of `GenServer.start_link/3`.

  Please note that you should not pass the `name` `t:GenServer.option/0`. If you need to register handler processes for
  later lookup and use, you should perform process registration in `handle_connection/2`, ensuring the handler process is
  registered only after the underlying connection is established and you have access to the connection socket and metadata
  via `Hell.Socket.peername/1`.

  For example, using a custom process registry via `Registry`:

  ```elixir

  defmodule Messenger do
    use Hell.Handler

    @impl Hell.Handler
    def handle_connection(socket, state) do
      {:ok, {ip, port}} = Hell.Socket.peername(socket)
      {:ok, _pid} = Registry.register(MessengerRegistry, {state[:my_key], address}, nil)
      {:continue, state}
    end

    @impl Hell.Handler
    def handle_data(data, socket, state) do
      Hell.Socket.send(socket, data)
      {:continue, state}
    end
  end
  ```

  This example assumes you have started a `Registry` and registered it under the name `MessengerRegistry`.

  # When Handler Isn't Enough

  The `use Hell.Handler` implementation should be flexible enough to power just about any handler, however if
  this should not be the case for you, there is an escape hatch available. If you require more flexibility than the
  `Hell.Handler` behaviour provides, you are free to specify any module which implements `start_link/1` as the
  `handler_module` parameter. The process of getting from this new process to a ready-to-use socket is somewhat
  delicate, however. The steps required are as follows:

  1. Hell calls `start_link/1` on the configured `handler_module`, passing in a tuple
  consisting of the configured handler and genserver opts. This function is expected to return a
  conventional `GenServer.on_start()` style tuple. Note that this newly created process is not
  passed the connection socket immediately.
  2. The raw `t:Hell.Transport.socket()` socket will be passed to the new process via a
  message of the form `{:hell_ready, raw_socket, handler_config, acceptor_span,
  start_time}`.
  3. Your implementation must turn this into a `to:Hell.Socket.t()` socket by using the
  `Hell.Socket.new/3` call.
  4. Your implementation must then call `Hell.Socket.handshake/1` with the socket as the
  sole argument in order to finalize the setup of the socket.
  5. The socket is now ready to use.

  In addition to this process, there are several other considerations to be aware of:

  * The underlying socket is closed automatically when the handler process ends.

  * Handler processes should have a restart strategy of `:temporary` to ensure that Hell does not attempt to
  restart crashed handlers.

  * Handler processes should trap exit if possible so that existing connections can be given a chance to cleanly shut
  down when shutting down a Hell server instance.

  * Some of the `:connection` family of telemetry span events are emitted by the
  `Hell.Handler` implementation. If you use your own implementation in its place it is
  likely that such spans will not behave as expected.
  """

  @typedoc "The possible ways to indicate a timeout when returning values to Hell"
  @type timeout_options :: timeout() | {:persistent, timeout()}

  @typedoc "The value returned by `c:handle_connection/2` and `c:handle_data/3`"
  @type handler_result ::
          {:continue, state :: term()}
          | {:continue, state :: term(), timeout_options() | {:continue, term()}}
          | {:switch_transport, {module(), upgrade_opts :: [term()]}, state :: term()}
          | {:switch_transport, {module(), upgrade_opts :: [term()]}, state :: term(),
             timeout_options() | {:continue, term()}}
          | {:pause, state :: term()}
          | {:pause, state :: term(), {:continue, term()}}
          | {:close, state :: term()}
          | {:error, term(), state :: term()}

  @doc """
  This callback is called shortly after a client connection has been made, immediately after the socket handshake process has
  completed. It is called with the server's configured `handler_options` value as initial state. Handlers may choose to
  interact synchronously with the socket in this callback via calls to various `Hell.Socket` functions.

  The value returned by this callback causes Hell to proceed in one of several ways:

  * Returning `{:close, state}` will cause Hell to close the socket & call the `c:handle_close/2` callback to
  allow final cleanup to be done.
  * Returning `{:continue, state}` will cause Hell to switch the socket to an asynchronous mode. When the
  client subsequently sends data (or if there is already unread data waiting from the client), Hell will call
  `c:handle_data/3` to allow this data to be processed.
  * Returning `{:continue, state, timeout}` is identical to the previous case with the
  addition of a timeout. If `timeout` milliseconds passes with no data being received or messages
  being sent to the process, the socket will be closed and `c:handle_timeout/2` will be called.
  Note that this timeout is not persistent; it applies only to the interval until the next message
  is received. In order to set a persistent timeout for all future messages (essentially
  overwriting the value of `read_timeout` that was set at server startup), a value of
  `{:persistent, timeout}` may be returned.
  * Returning `{:continue, state, {:continue, continue}}` is identical to the previous case with the
  addition of a `c:GenServer.handle_continue/2` callback being made immediately after, in line with
  similar behaviour on `GenServer` callbacks.
  * Returning `{:pause, state}` keeps the connection open without reading further client data:
  Hell does not re-arm the socket and does not call `c:handle_data/3` until `resume_input/1` is
  called from an owner-side GenServer callback. The read-idle timeout does not apply while
  paused. `{:pause, state, {:continue, continue}}` additionally invokes
  `c:GenServer.handle_continue/2` immediately after. See "Pausing Input" in the module docs.
  * Returning `{:switch_transport, {module, opts}, state}` will cause Hell to try switching the transport of the
  current socket. The `module` should be an Elixir module that implements the `Hell.Transport` behaviour.
  Hell will call `c:Hell.Transport.upgrade/2` for the given module to upgrade the transport in-place.
  After a successful upgrade Hell will switch the socket to an asynchronous mode, as if `{:continue, state}`
  was returned. As with `:continue` return values, there are also timeout-specifying variants of
  this return value.
  * Returning `{:error, reason, state}` will cause Hell to close the socket & call the `c:handle_error/3` callback to
  allow final cleanup to be done.
  """
  @callback handle_connection(socket :: Hell.Socket.t(), state :: term()) ::
              handler_result()

  @doc """
  This callback is called whenever client data is received after `c:handle_connection/2` or `c:handle_data/3` have returned an
  `{:continue, state}` tuple. The data received is passed as the first argument, and handlers may choose to interact
  synchronously with the socket in this callback via calls to various `Hell.Socket` functions.

  The value returned by this callback causes Hell to proceed in one of several ways:

  * Returning `{:close, state}` will cause Hell to close the socket & call the `c:handle_close/2` callback to
  allow final cleanup to be done.
  * Returning `{:continue, state}` will cause Hell to switch the socket to an asynchronous mode. When the
  client subsequently sends data (or if there is already unread data waiting from the client), Hell will call
  `c:handle_data/3` to allow this data to be processed.
  * Returning `{:continue, state, timeout}` is identical to the previous case with the
  addition of a timeout. If `timeout` milliseconds passes with no data being received or messages
  being sent to the process, the socket will be closed and `c:handle_timeout/2` will be called.
  Note that this timeout is not persistent; it applies only to the interval until the next message
  is received. In order to set a persistent timeout for all future messages (essentially
  overwriting the value of `read_timeout` that was set at server startup), a value of
  `{:persistent, timeout}` may be returned.
  * Returning `{:continue, state, {:continue, continue}}` is identical to the previous case with the
  addition of a `c:GenServer.handle_continue/2` callback being made immediately after, in line with
  similar behaviour on `GenServer` callbacks.
  * Returning `{:pause, state}` keeps the connection open without reading further client data:
  Hell does not re-arm the socket and does not call `c:handle_data/3` until `resume_input/1` is
  called from an owner-side GenServer callback. The read-idle timeout does not apply while
  paused. `{:pause, state, {:continue, continue}}` additionally invokes
  `c:GenServer.handle_continue/2` immediately after. See "Pausing Input" in the module docs.
  * Returning `{:error, reason, state}` will cause Hell to close the socket & call the `c:handle_error/3` callback to
  allow final cleanup to be done.
  """
  @callback handle_data(data :: binary(), socket :: Hell.Socket.t(), state :: term()) ::
              handler_result()

  @doc """
  This callback is called when the underlying socket is closed by the remote end; it should perform any cleanup required
  as it is the last callback called before the process backing this connection is terminated. The underlying socket
  has already been closed by the time this callback is called. The return value is ignored.

  This callback is not called if the connection is explicitly closed via `Hell.Socket.close/1`, however it
  will be called in cases where `handle_connection/2` or `handle_data/3` return a `{:close, state}` tuple.
  """
  @callback handle_close(socket :: Hell.Socket.t(), state :: term()) :: term()

  @doc """
  This callback is called when the underlying socket encounters an error; it should perform any cleanup required
  as it is the last callback called before the process backing this connection is terminated. The underlying socket
  has already been closed by the time this callback is called. The return value is ignored.

  In addition to socket level errors, this callback is also called in cases where `handle_connection/2` or `handle_data/3`
  return a `{:error, reason, state}` tuple, or when connection handshaking (typically TLS
  negotiation) fails.
  """
  @callback handle_error(reason :: any(), socket :: Hell.Socket.t(), state :: term()) ::
              term()

  @doc """
  This callback is called when the server process itself is being shut down; it should perform any cleanup required
  as it is the last callback called before the process backing this connection is terminated. The underlying socket
  has NOT been closed by the time this callback is called. The return value is ignored.

  This callback is only called when the shutdown reason is `:normal`, and is subject to the same caveats described
  in `c:GenServer.terminate/2`.
  """
  @callback handle_shutdown(socket :: Hell.Socket.t(), state :: term()) :: term()

  @doc """
  This callback is called when a handler process has gone more than `timeout` ms without receiving
  remote data from the client. The value used for `timeout` defaults to the `read_timeout` value
  specified at server startup, and may be overridden on a one-shot or persistent basis based on
  values returned from `c:handle_connection/2` or `c:handle_data/3` calls, or persistently via
  `set_read_timeout/2` in an owner-side GenServer callback. Note that it is NOT
  called on explicit `Hell.Socket.recv/3` calls as they have their own timeout
  semantics. This callback is triggered only by absence of incoming client data; local messages
  sent to the handler process do not reset the clock, and any GenServer-native timeouts will NOT
  cause this callback to be called (if you wish to handle GenServer-native timeouts, you can do so
  using the [upstream GenServer pattern](https://elixir.hexdocs.pm/GenServer.html#module-timeouts)
  for this purpose). The underlying socket has NOT been closed by the time this callback is
  called. The return value is ignored.
  """
  @callback handle_timeout(socket :: Hell.Socket.t(), state :: term()) :: term()

  @optional_callbacks handle_connection: 2,
                      handle_data: 3,
                      handle_close: 2,
                      handle_error: 3,
                      handle_shutdown: 2,
                      handle_timeout: 2

  @doc """
  Sets the connection's persistent read-idle timeout and returns the updated socket.

  Call this function only from the process owning a handler built with `use Hell.Handler`,
  and retain the returned socket in the GenServer's `{socket, state}` tuple. It may be used
  from `c:GenServer.handle_call/3`, `c:GenServer.handle_cast/2`, `c:GenServer.handle_info/2`
  or `c:GenServer.handle_continue/2`.

  A non-negative integer starts a fresh idle interval of that many milliseconds from this
  call. `:infinity` disables the read-idle timer. Both invalidate the previous timer,
  including notifications already queued for it. The setting persists across subsequent
  client data and ordinary `{:continue, state}` returns. Local mailbox messages do not
  refresh this interval; GenServer-native timeouts retain their usual semantics.

  For example, a multiplexed connection can save `socket.read_timeout` in
  `state.default_read_timeout` during `c:handle_connection/2`, then disable its idle policy
  when its first persistent stream opens and restore it when the last stream closes:

      def handle_call(:first_stream_opened, _from, {socket, state}) do
        socket = Hell.Handler.set_read_timeout(socket, :infinity)
        {:reply, :ok, {socket, state}}
      end

      def handle_info(:last_stream_closed, {socket, state}) do
        socket = Hell.Handler.set_read_timeout(socket, state.default_read_timeout)
        {:noreply, {socket, state}}
      end

  As with a `{:persistent, timeout}` callback return, this also sets the default timeout
  used by `Hell.Socket.recv/3` when no explicit timeout is supplied. Explicit receive
  timeouts, handshake timeouts, transport send timeouts and application-owned timers
  (such as partial-frame deadlines) are independent. This operation does not change
  socket active mode or generate a transport event.

  In `c:handle_connection/2` and `c:handle_data/3`, use the existing
  `{:continue, state, {:persistent, timeout}}` return instead.
  """
  @doc since: "0.1.3"
  @spec set_read_timeout(Hell.Socket.t(), timeout()) :: Hell.Socket.t()
  def set_read_timeout(%Hell.Socket{input_paused: true} = socket, timeout)
      when timeout == :infinity or (is_integer(timeout) and timeout >= 0) do
    %{socket | read_timeout: timeout}
  end

  def set_read_timeout(%Hell.Socket{} = socket, timeout)
      when timeout == :infinity or (is_integer(timeout) and timeout >= 0) do
    socket = cancel_read_timer(socket)
    arm_read_timer(%{socket | read_timeout: timeout}, timeout)
  end

  @doc """
  Pauses delivery of client data to `c:handle_data/3` and returns the updated socket.

  Call this function only from the process owning a handler built with `use Hell.Handler`,
  from `c:GenServer.handle_call/3`, `c:GenServer.handle_cast/2`, `c:GenServer.handle_info/2`
  or `c:GenServer.handle_continue/2`, and retain the returned socket in the GenServer's
  `{socket, state}` tuple. In `c:handle_connection/2` and `c:handle_data/3`, return
  `{:pause, state}` instead.

  The socket stops reading from the transport and the read-idle timer is cancelled. Client data
  the transport already delivered to the handler's mailbox is retained, in order, and is
  delivered to `c:handle_data/3` after `resume_input/1`. No `c:handle_data/3` call occurs while
  input is paused. Pausing an already paused socket returns it unchanged.

  See "Pausing Input" in the module documentation.
  """
  @doc since: "1.0.0"
  @spec pause_input(Hell.Socket.t()) :: Hell.Socket.t()
  def pause_input(%Hell.Socket{input_paused: true} = socket), do: socket

  def pause_input(%Hell.Socket{} = socket) do
    _ = Hell.Socket.setopts(socket, active: false)
    %{cancel_read_timer(socket) | input_paused: true}
  end

  @doc """
  Resumes delivery of client data after a pause and returns the updated socket.

  Call this function only from the process owning a handler built with `use Hell.Handler`,
  from `c:GenServer.handle_call/3`, `c:GenServer.handle_cast/2`, `c:GenServer.handle_info/2`
  or `c:GenServer.handle_continue/2`, and retain the returned socket in the GenServer's
  `{socket, state}` tuple.

  Data retained while paused is delivered to `c:handle_data/3` first, in its original order,
  after the current callback returns; Hell reads from the transport again once that data has
  been handled. The read-idle timer restarts with the connection's persistent `read_timeout`.
  Resuming a socket that is not paused returns it unchanged.
  """
  @doc since: "1.0.0"
  @spec resume_input(Hell.Socket.t()) :: Hell.Socket.t()
  def resume_input(%Hell.Socket{input_paused: false} = socket), do: socket

  def resume_input(%Hell.Socket{paused_input: retained} = socket) do
    socket = %{socket | input_paused: false, paused_input: []}

    # Without retained input the socket is re-armed directly. Otherwise retained transport
    # messages are re-queued to this process in order; the socket stays passive until the
    # continuation of their `handle_data/3` call re-arms it, so nothing new can overtake them
    _ =
      case retained do
        [] -> Hell.Socket.setopts(socket, active: :once)
        _ -> Enum.each(retained, &send(self(), &1))
      end

    arm_read_timer(socket, socket.read_timeout)
  end

  @doc false
  # Data is always retained. A terminal event is retained only behind retained data, so that
  # it is processed after that data on resume; otherwise nothing is lost by stopping now
  @spec handle_paused_input(tuple(), {Hell.Socket.t(), term()}) ::
          {:noreply, {Hell.Socket.t(), term()}} | {:stop, term(), {Hell.Socket.t(), term()}}
  def handle_paused_input({msg, _raw_socket, _data} = message, {socket, state})
      when msg in [:tcp, :ssl] do
    {:noreply, {retain(socket, message), state}}
  end

  def handle_paused_input(message, {%Hell.Socket{paused_input: [_ | _]} = socket, state}) do
    {:noreply, {retain(socket, message), state}}
  end

  def handle_paused_input({_closed, _raw_socket}, {socket, state}) do
    {:stop, {:shutdown, :peer_closed}, {socket, state}}
  end

  def handle_paused_input({_error, _raw_socket, reason}, {socket, state}) do
    {:stop, reason, {socket, state}}
  end

  defp retain(socket, message), do: %{socket | paused_input: socket.paused_input ++ [message]}

  @spec __using__(any) :: Macro.t()
  defmacro __using__(_opts) do
    quote location: :keep do
      @behaviour Hell.Handler

      use GenServer, restart: :temporary

      @spec start_link({handler_options :: term(), GenServer.options()}) :: GenServer.on_start()
      def start_link({handler_options, genserver_options}) do
        GenServer.start_link(__MODULE__, handler_options, genserver_options)
      end

      unquote(genserver_impl())
      unquote(handler_impl())
    end
  end

  @doc false
  defmacro add_handle_info_fallback(_module) do
    quote do
      def handle_info({msg, _raw_socket, _data}, _state) when msg in [:tcp, :ssl] do
        raise """
          The callback's `state` doesn't match the expected `{socket, state}` form.
          Please ensure that you are returning a `{socket, state}` tuple from any
          `GenServer.handle_*` callbacks you have implemented
        """
      end
    end
  end

  @doc false
  def handle_ready(raw_socket, handler_config, acceptor_span, start_time, state) do
    {ip, port} =
      case handler_config.transport_module.peername(raw_socket) do
        {:ok, remote_info} ->
          remote_info

        {:error, reason} ->
          # the socket has been prematurely closed by the client, we can't do anything with it
          # so we just close the socket, stop the GenServer with the error reason and move on.
          _ = handler_config.transport_module.close(raw_socket)
          throw({:stop, {:shutdown, {:premature_conn_closing, reason}}, {raw_socket, state}})
      end

    Hell.ProcessLabel.set(:connection, handler_config, {ip, port})

    span_meta = %{remote_address: ip, remote_port: port}

    connection_span =
      Hell.Telemetry.start_child_span(
        acceptor_span,
        :connection,
        %{monotonic_time: start_time},
        span_meta
      )

    socket = Hell.Socket.new(raw_socket, handler_config, connection_span)

    case Hell.Socket.handshake(socket) do
      {:ok, socket} ->
        Hell.Telemetry.span_event(connection_span, :ready)
        {:noreply, {socket, state}, {:continue, :handle_connection}}

      {:error, reason} ->
        {:stop, {:shutdown, {:handshake, reason}}, {socket, state}}
    end
  catch
    {:stop, _, _} = stop -> stop
  end

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def genserver_impl do
    quote do
      @impl true
      def init(handler_options) do
        Process.flag(:trap_exit, true)
        {:ok, {nil, handler_options}}
      end

      @impl true
      def handle_info(
            {:hell_ready, raw_socket, handler_config, acceptor_span, start_time},
            {nil, state}
          ) do
        Hell.Handler.handle_ready(raw_socket, handler_config, acceptor_span, start_time, state)
      end

      # While input is paused, transport events are retained for `Hell.Handler.resume_input/1`
      def handle_info(
            {msg, raw_socket, _data_or_reason} = message,
            {%Hell.Socket{socket: raw_socket, input_paused: true} = socket, state}
          )
          when msg in [:tcp, :ssl, :tcp_error, :ssl_error] do
        Hell.Handler.handle_paused_input(message, {socket, state})
      end

      def handle_info(
            {msg, raw_socket} = message,
            {%Hell.Socket{socket: raw_socket, input_paused: true} = socket, state}
          )
          when msg in [:tcp_closed, :ssl_closed] do
        Hell.Handler.handle_paused_input(message, {socket, state})
      end

      def handle_info(
            {msg, raw_socket, data},
            {%Hell.Socket{socket: raw_socket} = socket, state}
          )
          when msg in [:tcp, :ssl] do
        Hell.Telemetry.untimed_span_event(socket.span, :async_recv, %{data: data})

        Hell.Handler.invoke_callback(socket, fn ->
          __MODULE__.handle_data(data, socket, state)
        end)
        |> Hell.Handler.handle_continuation(socket)
      end

      def handle_info(
            {msg, raw_socket},
            {%Hell.Socket{socket: raw_socket} = socket, state}
          )
          when msg in [:tcp_closed, :ssl_closed] do
        {:stop, {:shutdown, :peer_closed}, {socket, state}}
      end

      def handle_info(
            {msg, raw_socket, reason},
            {%Hell.Socket{socket: raw_socket} = socket, state}
          )
          when msg in [:tcp_error, :ssl_error] do
        {:stop, reason, {socket, state}}
      end

      def handle_info(
            {:timeout, timer, :hell_read_timeout},
            {%Hell.Socket{read_timer: timer} = socket, state}
          ) do
        case Hell.Handler.check_read_deadline(socket) do
          {:timeout, socket} -> {:stop, {:shutdown, :read_timeout}, {socket, state}}
          {:continue, socket} -> {:noreply, {socket, state}}
        end
      end

      def handle_info({:timeout, _timer, :hell_read_timeout}, {%Hell.Socket{}, _state} = state) do
        {:noreply, state}
      end

      @before_compile {Hell.Handler, :add_handle_info_fallback}

      # Use a continue pattern here so that we have committed the socket
      # to state in case the `c:handle_connection/2` callback raises an error.
      # This ensures that the `c:terminate/2` calls below are able to properly
      # close down the process
      @impl true
      def handle_continue(:handle_connection, {%Hell.Socket{} = socket, state}) do
        Hell.Handler.invoke_callback(socket, fn ->
          __MODULE__.handle_connection(socket, state)
        end)
        |> Hell.Handler.handle_continuation(socket)
      end

      # Called if the remote end closed the connection before we could initialize it
      @impl true
      def terminate({:shutdown, {:premature_conn_closing, _reason}}, {_raw_socket, _state}) do
        :ok
      end

      # Called when we hit our read_timeout. Socket is still open
      def terminate({:shutdown, :read_timeout}, {%Hell.Socket{} = socket, state}) do
        _ = __MODULE__.handle_timeout(socket, state)
        Hell.Handler.do_socket_close(socket, :timeout)
      end

      # Called if we're being shutdown in an orderly manner. Socket is still open
      def terminate(:shutdown, {%Hell.Socket{} = socket, state}) do
        _ = __MODULE__.handle_shutdown(socket, state)
        Hell.Handler.do_socket_close(socket, :shutdown)
      end

      # Called if the socket encountered an error during handshaking
      def terminate({:shutdown, {:handshake, reason}}, {%Hell.Socket{} = socket, state}) do
        _ = __MODULE__.handle_error(reason, socket, state)
        Hell.Handler.do_socket_close(socket, reason)
      end

      # Called if the socket encountered an error and we are configured to shutdown silently.
      # Socket is closed
      def terminate(
            {:shutdown, {:silent_termination, reason}},
            {%Hell.Socket{} = socket, state}
          ) do
        _ = __MODULE__.handle_error(reason, socket, state)
        Hell.Handler.do_socket_close(socket, reason)
      end

      # Called if the socket encountered an error during upgrading
      def terminate({:shutdown, {:upgrade, reason}}, {socket, state}) do
        _ = __MODULE__.handle_error(reason, socket, state)
        Hell.Handler.do_socket_close(socket, reason)
      end

      # Called if the remote end shut down the connection, or if the local end closed the
      # connection by returning a `{:close,...}` tuple (in which case the socket will be open)
      def terminate({:shutdown, reason}, {%Hell.Socket{} = socket, state}) do
        _ = __MODULE__.handle_close(socket, state)
        Hell.Handler.do_socket_close(socket, reason)
      end

      # Called if the socket encountered an error. Socket is closed
      def terminate(reason, {%Hell.Socket{} = socket, state}) do
        _ = __MODULE__.handle_error(reason, socket, state)
        Hell.Handler.do_socket_close(socket, reason)
      end

      # This clause could happen if we do not have a socket defined in state (either because the
      # process crashed before setting it up, or because the user sent an invalid state)
      def terminate(_reason, _state) do
        :ok
      end
    end
  end

  def handler_impl do
    quote do
      @impl true
      def handle_connection(_socket, state), do: {:continue, state}

      @impl true
      def handle_data(_data, _socket, state), do: {:continue, state}

      @impl true
      def handle_close(_socket, _state), do: :ok

      @impl true
      def handle_error(_error, _socket, _state), do: :ok

      @impl true
      def handle_shutdown(_socket, _state), do: :ok

      @impl true
      def handle_timeout(_socket, _state), do: :ok

      defoverridable Hell.Handler
    end
  end

  @spec do_socket_close(
          Hell.Socket.t(),
          reason :: :shutdown | :local_closed | term()
        ) :: :ok
  @doc false
  def do_socket_close(socket, reason) do
    measurements =
      case Hell.Socket.getstat(socket) do
        {:ok, stats} ->
          %{
            send_oct: stats[:send_oct],
            send_cnt: stats[:send_cnt],
            recv_oct: stats[:recv_oct],
            recv_cnt: stats[:recv_cnt]
          }

        _ ->
          %{}
      end

    metadata =
      if reason in [:shutdown, :local_closed, :peer_closed], do: %{}, else: %{error: reason}

    _ = Hell.Socket.close(socket)
    Hell.Telemetry.stop_span(socket.span, measurements, metadata)
  end

  defp cancel_read_timer(%{read_timer: nil} = socket) do
    %{socket | read_deadline: nil, timer_deadline: nil}
  end

  defp cancel_read_timer(%{read_timer: timer} = socket) do
    _ = Process.cancel_timer(timer)

    # Remove an already delivered notification. Any later delivery is ignored because
    # its reference no longer matches the socket's current read timer.
    receive do
      {:timeout, ^timer, :hell_read_timeout} -> :ok
    after
      0 -> :ok
    end

    %{socket | read_timer: nil, read_deadline: nil, timer_deadline: nil}
  end

  # The read timer is lazily evaluated: the hot path (a callback returning a `:continue` tuple
  # after every piece of data) only records the new deadline, and the already-armed timer
  # re-checks that deadline whenever it fires (see `check_read_deadline/1`). This keeps timer
  # arming and cancellation off of the per-message path; a timer is armed at most once per
  # timeout interval rather than once per message
  defp arm_read_timer(socket, :infinity), do: cancel_read_timer(socket)

  defp arm_read_timer(socket, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    cond do
      is_nil(socket.read_timer) ->
        timer = :erlang.start_timer(timeout, self(), :hell_read_timeout)
        %{socket | read_deadline: deadline, read_timer: timer, timer_deadline: deadline}

      socket.timer_deadline <= deadline ->
        # The armed timer fires at or before the new deadline; when it fires it will re-arm
        # itself for whatever time then remains
        %{socket | read_deadline: deadline}

      true ->
        # The new deadline is sooner than the armed timer would fire; re-arm eagerly
        socket = cancel_read_timer(socket)
        timer = :erlang.start_timer(timeout, self(), :hell_read_timeout)
        %{socket | read_deadline: deadline, read_timer: timer, timer_deadline: deadline}
    end
  end

  @doc false
  # Called when the current read timer fires. Because arming is lazy, a firing timer is not
  # necessarily a timeout: data may have moved the deadline forward since the timer was armed
  @spec check_read_deadline(Hell.Socket.t()) ::
          {:timeout, Hell.Socket.t()} | {:continue, Hell.Socket.t()}
  def check_read_deadline(%{read_deadline: nil} = socket) do
    # The timeout has since been set to :infinity; absorb the stale firing
    {:continue, %{socket | read_timer: nil, timer_deadline: nil}}
  end

  def check_read_deadline(socket) do
    now = System.monotonic_time(:millisecond)

    if now >= socket.read_deadline do
      {:timeout, socket}
    else
      timer = :erlang.start_timer(socket.read_deadline - now, self(), :hell_read_timeout)
      {:continue, %{socket | read_timer: timer, timer_deadline: socket.read_deadline}}
    end
  end

  @doc false
  @spec invoke_callback(Hell.Socket.t(), (-> result)) :: result when result: term()
  def invoke_callback(socket, callback) do
    callback.()
  catch
    kind, reason ->
      stacktrace = __STACKTRACE__
      Hell.Telemetry.exception_span(socket.span, kind, reason, stacktrace)
      :erlang.raise(kind, reason, stacktrace)
  end

  @doc false
  def handle_continuation(continuation, socket) do
    case continuation do
      {:continue, state} ->
        _ = Hell.Socket.setopts(socket, active: :once)
        socket = arm_read_timer(socket, socket.read_timeout)
        {:noreply, {socket, state}}

      {:continue, state, {:continue, continue}} ->
        _ = Hell.Socket.setopts(socket, active: :once)
        socket = arm_read_timer(socket, socket.read_timeout)
        {:noreply, {socket, state}, {:continue, continue}}

      {:continue, state, {:persistent, timeout}} ->
        socket = %{socket | read_timeout: timeout}
        _ = Hell.Socket.setopts(socket, active: :once)
        socket = arm_read_timer(socket, timeout)
        {:noreply, {socket, state}}

      {:continue, state, timeout} ->
        _ = Hell.Socket.setopts(socket, active: :once)
        socket = arm_read_timer(socket, timeout)
        {:noreply, {socket, state}}

      {:pause, state} ->
        {:noreply, {pause_input(socket), state}}

      {:pause, state, {:continue, continue}} ->
        {:noreply, {pause_input(socket), state}, {:continue, continue}}

      {:switch_transport, {module, upgrade_opts}, state} ->
        handle_switch_continuation(socket, module, upgrade_opts, state, socket.read_timeout)

      {:switch_transport, {module, upgrade_opts}, state, {:continue, continue}} ->
        handle_switch_continuation(socket, module, upgrade_opts, state, {:continue, continue})

      {:switch_transport, {module, upgrade_opts}, state, {:persistent, timeout}} ->
        socket = %{socket | read_timeout: timeout}
        handle_switch_continuation(socket, module, upgrade_opts, state, timeout)

      {:switch_transport, {module, upgrade_opts}, state, timeout} ->
        handle_switch_continuation(socket, module, upgrade_opts, state, timeout)

      {:close, state} ->
        {:stop, {:shutdown, :local_closed}, {cancel_read_timer(socket), state}}

      {:error, :timeout, state} ->
        {:stop, {:shutdown, :read_timeout}, {cancel_read_timer(socket), state}}

      {:error, reason, state} ->
        socket = cancel_read_timer(socket)

        if socket.silent_terminate_on_error do
          {:stop, {:shutdown, {:silent_termination, reason}}, {socket, state}}
        else
          {:stop, reason, {socket, state}}
        end
    end
  end

  defp handle_switch_continuation(socket, module, upgrade_opts, state, timeout_or_continue) do
    case Hell.Socket.upgrade(socket, module, upgrade_opts) do
      {:ok, socket} ->
        handle_continuation({:continue, state, timeout_or_continue}, socket)

      {:error, reason} ->
        {:stop, {:shutdown, {:upgrade, reason}}, {socket, state}}
    end
  end
end
