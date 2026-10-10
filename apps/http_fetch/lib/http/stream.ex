defmodule HTTP.Stream do
  @moduledoc """
  Process-backed readable stream used for Fetch-style response and request bodies.

  Streamed responses expose this PID in `HTTP.Response.body`. Streaming uploads can
  pass a stream PID as `body` when `HTTP.fetch/2` is called with `duplex: "half"`.
  Producers write chunks with `chunk/3` and finish with `finish/1`; consumers read
  by sending `{:read_chunk, pid}` or `{:read_chunk, pid, :ack}`.
  """

  defstruct reader: nil,
            producer: nil,
            telemetry: true,
            decoders: [],
            reader_monitor: nil,
            reader_ack?: false,
            chunks: [],
            pending_ack: nil,
            trailers: nil,
            done?: false,
            error: nil,
            total_bytes: 0,
            start_time: nil

  @spec start_link(non_neg_integer()) :: {:ok, pid()}
  def start_link(content_length), do: start_link(content_length, [])

  @doc false
  def start_link(content_length, encodings, opts \\ []) do
    telemetry = Keyword.get(opts, :telemetry, true)
    start_time = System.monotonic_time(:microsecond)
    if telemetry, do: HTTP.Telemetry.streaming_start(content_length)

    Task.start_link(fn ->
      decoders = HTTP.ContentDecoder.open(encodings)

      Process.put(:stream_producer, nil)

      try do
        loop(%__MODULE__{start_time: start_time, decoders: decoders, telemetry: telemetry})
      after
        if producer = Process.get(:stream_producer), do: Process.exit(producer, :kill)
        HTTP.ContentDecoder.close(decoders)
      end
    end)
  end

  @doc """
  Creates a stream from an enumerable.

  Pass `telemetry: false` in the optional second argument to silence producer
  streaming events. The default is `true`.

  Each enumerable item is converted to binary and emitted with backpressure. The
  returned PID can be passed as a streaming request body:

      {:ok, stream} = HTTP.Stream.from_enumerable(["hello", " ", "world"])
      HTTP.fetch(url, method: :post, body: stream, duplex: "half")
  """
  @spec from_enumerable(Enumerable.t()) :: {:ok, pid()} | {:error, term()}
  @spec from_enumerable(Enumerable.t(), keyword()) :: {:ok, pid()} | {:error, term()}
  def from_enumerable(enumerable, opts \\ []) do
    with {:ok, stream} <- start_link(0, [], opts),
         {:ok, producer} <-
           Task.Supervisor.start_child(:http_fetch_task_supervisor, fn ->
             launch_monitor = Process.monitor(stream)

             receive do
               :produce ->
                 Process.demonitor(launch_monitor, [:flush])
                 produce_enumerable(stream, enumerable)

               {:DOWN, ^launch_monitor, :process, ^stream, _reason} ->
                 :ok
             end
           end) do
      send(stream, {:enumerable_producer, producer})
      {:ok, stream}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @spec chunk(pid(), binary(), timeout()) :: :ok | {:error, term()}
  def chunk(pid, chunk, timeout \\ HTTP.Config.streaming_timeout())
      when is_pid(pid) and is_binary(chunk) do
    ref = make_ref()
    monitor_ref = Process.monitor(pid)
    send(pid, {:chunk, self(), ref, chunk})

    receive do
      {:chunk_ack, ^ref} ->
        Process.demonitor(monitor_ref, [:flush])
        :ok

      {:chunk_error, ^ref, reason} ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, reason}

      {:DOWN, ^monitor_ref, :process, ^pid, reason} ->
        {:error, {:stream_down, reason}}

      :abort ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, :aborted}

      :deadline ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, :request_timeout}
    after
      timeout ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, :timeout}
    end
  end

  @spec finish(pid()) :: :ok
  def finish(pid) when is_pid(pid) do
    send(pid, :finish)
    :ok
  end

  @doc """
  Finishes a stream with ordered trailer fields (a list or `HTTP.Headers`).

  Validation limits trailers to 128 fields and 65,536 serialized bytes. Invalid
  trailers return an error without finishing the stream. For HTTP/1 uploads,
  every field must be declared in the request's `Trailer` header and the body
  must use chunk framing (no `Content-Length`). HTTP/2 and HTTP/3 uploads return
  `:request_trailers_unsupported`; their response trailer support is unchanged.
  Completion is signalled asynchronously, like `finish/1`.
  """
  @spec finish(pid(), HTTP.Headers.t() | HTTP.Headers.headers_list()) :: :ok | {:error, term()}
  def finish(pid, trailers) when is_pid(pid) do
    with {:ok, headers} <- HTTP.Trailers.validate(trailers) do
      if headers.headers == [], do: finish(pid), else: send(pid, {:finish, headers})
      :ok
    end
  end

  @doc "Sends response trailers to the reader before the terminal stream event."
  def trailers(pid, headers) when is_pid(pid), do: send(pid, {:trailers, headers})

  @spec error(pid(), term()) :: :ok
  def error(pid, reason) when is_pid(pid) do
    send(pid, {:error, reason})
    :ok
  end

  @doc false
  def stop(pid, reason) when is_pid(pid) do
    send(pid, {:request_lifecycle_stop, reason})
    :ok
  end

  defp produce_enumerable(stream, enumerable) do
    enumerable
    |> Enum.reduce_while(:ok, fn chunk, :ok ->
      case __MODULE__.chunk(stream, IO.iodata_to_binary(chunk)) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      :ok -> finish(stream)
      {:error, reason} -> error(stream, reason)
    end
  rescue
    error -> __MODULE__.error(stream, error)
  end

  defp loop(%__MODULE__{} = state) do
    receive do
      {:enumerable_producer, producer} ->
        Process.put(:stream_producer, producer)
        send(producer, :produce)
        loop(%{state | producer: producer})

      {:request_lifecycle, tracker, caller, ref} ->
        if state.producer, do: HTTP.RequestLifecycle.register(tracker, state.producer, :producer)
        send(caller, {:request_lifecycle_attached, ref})
        loop(state)

      {:request_lifecycle_stop, reason} ->
        _ =
          state
          |> reply_pending({:error, reason})
          |> Map.merge(%{error: reason, chunks: []})
          |> flush()

        :ok

      {:read_chunk, reader} when is_pid(reader) ->
        state
        |> monitor_reader(reader)
        |> Map.put(:reader_ack?, false)
        |> flush()
        |> maybe_continue()

      {:read_chunk, reader, :ack} when is_pid(reader) ->
        state
        |> monitor_reader(reader)
        |> Map.put(:reader_ack?, true)
        |> flush()
        |> maybe_continue()

      {:stream_chunk_ack, ref} ->
        state
        |> ack_reader_chunk(ref)
        |> flush()
        |> maybe_continue()

      {:chunk, sender, ref, chunk} ->
        case HTTP.ContentDecoder.decode(state.decoders, chunk) do
          {:ok, ""} when state.decoders != [] ->
            send(sender, {:chunk_ack, ref})
            loop(state)

          {:ok, decoded} ->
            chunk_size = byte_size(decoded)
            total_bytes = state.total_bytes + chunk_size
            if state.telemetry, do: HTTP.Telemetry.streaming_chunk(chunk_size, total_bytes)

            state
            |> Map.put(:total_bytes, total_bytes)
            |> push_chunk(decoded, {sender, ref})
            |> loop()

          {:error, reason} ->
            send(sender, {:chunk_error, ref, reason})
            fail(state, reason)
        end

      {:trailers, headers} ->
        loop(%{state | trailers: headers})

      {:finish, trailers} ->
        send(self(), :finish)
        loop(%{state | trailers: trailers})

      :finish ->
        duration = System.monotonic_time(:microsecond) - state.start_time
        if state.telemetry, do: HTTP.Telemetry.streaming_stop(state.total_bytes, duration)

        case HTTP.ContentDecoder.finish(state.decoders) do
          :ok ->
            state
            |> Map.put(:done?, true)
            |> flush()
            |> maybe_continue()

          {:error, reason} ->
            fail(state, reason)
        end

      {:error, reason} ->
        fail(state, reason)

      {:DOWN, monitor, :process, _reader, reason} when monitor == state.reader_monitor ->
        _ = reply_pending(state, {:error, {:reader_down, reason}})
        :ok
    after
      HTTP.Config.streaming_timeout() ->
        timeout(state)
    end
  end

  defp fail(state, reason) do
    state
    |> reply_pending({:error, reason})
    |> Map.merge(%{error: reason, chunks: []})
    |> flush()
    |> maybe_continue()
  end

  defp monitor_reader(%{reader: reader} = state, reader), do: state

  defp monitor_reader(state, reader) do
    if state.reader_monitor, do: Process.demonitor(state.reader_monitor, [:flush])
    %{state | reader: reader, reader_monitor: Process.monitor(reader)}
  end

  defp maybe_continue(%__MODULE__{done?: true, reader: reader, chunks: [], pending_ack: nil})
       when is_pid(reader),
       do: :ok

  defp maybe_continue(%__MODULE__{error: error, reader: reader, chunks: [], pending_ack: nil})
       when not is_nil(error) and is_pid(reader),
       do: :ok

  defp maybe_continue(%__MODULE__{} = state), do: loop(state)

  defp timeout(%__MODULE__{done?: true} = state), do: loop(state)
  defp timeout(%__MODULE__{error: error} = state) when not is_nil(error), do: loop(state)

  defp timeout(%__MODULE__{} = state) do
    duration = System.monotonic_time(:microsecond) - state.start_time
    if state.telemetry, do: HTTP.Telemetry.streaming_stop(state.total_bytes, duration)

    _state =
      state
      |> Map.put(:error, :timeout)
      |> flush()
      |> reply_pending({:error, :timeout})

    :ok
  end

  defp push_chunk(%__MODULE__{reader: nil, chunks: chunks} = state, chunk, ack) do
    %{state | chunks: [chunk | chunks], pending_ack: ack}
  end

  defp push_chunk(%__MODULE__{reader: reader, reader_ack?: true} = state, chunk, ack) do
    {_sender, ref} = ack
    send(reader, {:stream_chunk, self(), chunk, ref})
    %{state | pending_ack: ack}
  end

  defp push_chunk(%__MODULE__{reader: reader} = state, chunk, ack) do
    send(reader, {:stream_chunk, self(), chunk})
    reply_pending(%{state | pending_ack: ack}, :ok)
  end

  defp flush(%__MODULE__{reader: nil} = state), do: state

  defp flush(
         %__MODULE__{
           reader: reader,
           reader_ack?: true,
           chunks: [chunk],
           pending_ack: {_sender, ref}
         } =
           state
       ) do
    send(reader, {:stream_chunk, self(), chunk, ref})
    %{state | chunks: []}
  end

  defp flush(%__MODULE__{reader_ack?: true, pending_ack: {_sender, _ref}} = state), do: state

  defp flush(%__MODULE__{reader: reader, chunks: chunks, done?: done?, error: error} = state) do
    chunks
    |> Enum.reverse()
    |> Enum.each(fn chunk -> send(reader, {:stream_chunk, self(), chunk}) end)

    state = reply_pending(state, :ok)

    cond do
      error ->
        send(reader, {:stream_error, self(), error})
        %{state | chunks: [], pending_ack: nil}

      done? ->
        if state.trailers, do: send(reader, {:stream_trailers, self(), state.trailers})
        send(reader, {:stream_end, self()})
        %{state | chunks: [], pending_ack: nil, trailers: nil}

      true ->
        %{state | chunks: [], pending_ack: nil}
    end
  end

  defp ack_reader_chunk(%__MODULE__{pending_ack: {_sender, ref}} = state, ref) do
    reply_pending(state, :ok)
  end

  defp ack_reader_chunk(%__MODULE__{} = state, _ref), do: state

  defp reply_pending(%__MODULE__{pending_ack: nil} = state, _reply), do: state

  defp reply_pending(%__MODULE__{pending_ack: {sender, ref}} = state, :ok) do
    send(sender, {:chunk_ack, ref})
    %{state | pending_ack: nil}
  end

  defp reply_pending(%__MODULE__{pending_ack: {sender, ref}} = state, {:error, reason}) do
    send(sender, {:chunk_error, ref, reason})
    %{state | pending_ack: nil}
  end
end
