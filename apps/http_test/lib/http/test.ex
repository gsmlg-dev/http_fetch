defmodule HTTP.Test do
  @moduledoc """
  Owner-isolated fixtures for HTTP Family requests.

      HTTP.Test.expect(:service, fn request ->
        HTTP.Test.json(%{path: request.url.path})
      end)
      response = HTTP.fetch("https://service.test/items", adapter: {HTTP.Test, :service})
                 |> HTTP.Promise.await()
      HTTP.Test.verify!()

  Fixtures belong to the process that registers them. Tasks inherit their caller
  chain; authorize an independent GenServer with `allow/3`. Stub and expectation
  modes are mutually exclusive per owner/name. Expectations are claimed atomically
  in registration order; cancellation does not restore a claimed call.

  Call `verify_on_exit!/0` in ExUnit setup. Verification freezes claims, cancels
  and joins simulated resources with a finite budget, then checks counts and
  callback failures. Callback exceptions retain their cause and stacktrace and
  fail verification even when a Promise was never awaited. Intentional
  `transport_error/1` fixtures are ordinary client failures.

  Each Fetch attempt claims one expectation, so a `retry:` policy on
  `HTTP.fetch/2` is observable as consecutive claims; a retried fixture stream
  is stopped before the next attempt. Manual redirects are exposed; error
  redirects fail with `:redirect`; follow candidates fail with
  `{:unsupported_test_policy, :redirect_follow}`. Only 301/302/303/307/308 with a
  binary Location are candidates. Default nonredirect fixtures work normally.
  Default follow completion remains unsupported. Mock resource cleanup cannot
  establish socket, TLS or pool behavior.
  """
  @behaviour HTTP.Adapter
  alias HTTP.Test.Registry

  @context_key {__MODULE__, :context}
  @cleanup_budget 1_000

  @doc "Registers a repeatable fixture in the current owner's namespace."
  def stub(name, callback) when is_function(callback, 1),
    do: configure(name, :stub, 0, callback)

  @doc "Registers an ordered expectation, consumed exactly `count` times (default one)."
  def expect(name, count \\ 1, callback)
      when is_integer(count) and count > 0 and is_function(callback, 1),
      do: configure(name, :expect, count, callback)

  @doc "Authorizes `allowed` to use one fixture belonging to `owner`."
  def allow(name, owner, allowed) when is_pid(owner) and is_pid(allowed) do
    if owner != self(), do: raise(ArgumentError, "only the fixture owner may grant an allowance")
    check!(Registry.allow(name, owner, allowed))
  end

  @doc "Verifies and settles this owner's fixtures. Further claims are rejected."
  def verify! do
    self() |> Registry.token() |> finalize(false) |> verify_result!()
  end

  @doc "Registers an ExUnit exit verifier with an opaque token that survives owner exit."
  def verify_on_exit! do
    unless Code.ensure_loaded?(ExUnit.Callbacks),
      do: raise(ArgumentError, "verify_on_exit! requires ExUnit")

    token = Registry.token(self())
    :ok = Registry.retain(token)
    apply(ExUnit.Callbacks, :on_exit, [fn -> finalize(token, true) |> verify_result!() end])
    :ok
  end

  @doc false
  def finalize(token, delete?) do
    try do
      case Registry.freeze(token) do
        {:terminal, result} ->
          result

        {:ok, guardians} ->
          deadline = System.monotonic_time(:millisecond) + @cleanup_budget

          cleanup =
            Enum.reduce(guardians, :ok, fn guardian, acc ->
              remaining = max(deadline - System.monotonic_time(:millisecond), 0)

              case HTTP.Test.Guardian.cancel_and_await(guardian, remaining) do
                :ok -> acc
                error -> error
              end
            end)

          resources_cleanup = settle_resources(token, deadline)

          Registry.finish_verification(
            token,
            if(cleanup == :ok, do: resources_cleanup, else: cleanup)
          )

        error ->
          error
      end
    after
      if delete?, do: Registry.delete(token)
    end
  end

  @impl true
  def prepare(request, name) do
    with :ok <- validate_request(request),
         {:ok, token} <- Registry.resolve(name, [self() | Process.get(:"$callers", [])]) do
      {:ok, %{name: name, token: token, caller: self()}}
    else
      {:error, reason} -> {:error, {:http_test, reason}}
    end
  end

  @impl true
  def execute(request, context, signal) do
    tracker = HTTP.RequestLifecycle.current()

    timeout =
      Keyword.get(request.transport_options, :timeout) || HTTP.Config.default_request_timeout()

    {:ok, guardian} = HTTP.Test.Guardian.start(context, self(), tracker, timeout)

    case Registry.claim(context.token, context.name, self(), guardian) do
      {:ok, callback} ->
        context = Map.merge(context, %{guardian: guardian, tracker: tracker})
        Process.put(@context_key, context)

        try do
          attachment = attach_upload(context, request.body)
          if signal, do: HTTP.AbortController.set_request_id(signal, guardian)

          result =
            if signal && HTTP.AbortController.aborted?(signal) do
              {:error, :aborted}
            else
              with :ok <- attachment do
                callback.(request) |> validate_result!() |> redirect_policy(request)
              end
            end

          :ok = Registry.finished(context.token, self())

          case HTTP.Test.Guardian.cancellation(guardian) do
            nil -> result
            reason -> {:error, reason}
          end
        catch
          kind, reason ->
            stacktrace = __STACKTRACE__

            :ok =
              Registry.failed(
                context.token,
                self(),
                {:callback_failure, kind, reason, stacktrace}
              )

            send(guardian, :abort)
            :erlang.raise(kind, reason, stacktrace)
        after
          Process.delete(@context_key)
        end

      {:error, reason} ->
        send(guardian, :abort)
        {:error, {:http_test, reason}}
    end
  end

  @doc "Builds a buffered response, preserving ordered duplicate headers."
  def response(status, body \\ "", headers \\ []) when is_integer(status),
    do:
      HTTP.Response.new(
        status: status,
        body: IO.iodata_to_binary(body),
        headers: HTTP.Headers.new(headers)
      )

  @doc "Builds a JSON byte response; Fetch does not decode the body into a map."
  def json(value, status \\ 200),
    do: response(status, JSON.encode!(value), [{"content-type", "application/json"}])

  @doc "Builds a UTF-8 text response."
  def text(body, status \\ 200),
    do: response(status, body, [{"content-type", "text/plain; charset=utf-8"}])

  @doc "Builds a UTF-8 HTML response."
  def html(body, status \\ 200),
    do: response(status, body, [{"content-type", "text/html; charset=utf-8"}])

  @doc "Builds an empty response with the given status."
  def status(code), do: response(code)
  @doc "Replaces response headers, preserving duplicate fields and order."
  def headers(%HTTP.Response{} = response, headers),
    do: %{response | headers: HTTP.Headers.new(headers)}

  @doc "Creates an intentional transport failure, subject to Fetch's error mode."
  def transport_error(reason), do: {:error, reason}

  @doc """
  Creates a response using a real acknowledged `HTTP.Stream` inside a fixture.

  Steps are binary/iodata chunks, `{:gate, observer, tag}`, or `{:error, reason}`.
  A gate sends `{:http_test_gate, tag, producer, ref}` and waits for
  `{:http_test_release, ref}`. Each following step begins only after the previous
  chunk's acknowledgement. `trailers:` preserves field order. `observer:` receives
  `{:http_test_stream, stream, producer}` for deterministic cleanup assertions.
  The finite `timeout:` bounds each chunk and gate (default 5 seconds).
  """
  def stream(steps, opts \\ []) when is_list(steps) do
    context =
      Process.get(@context_key) ||
        raise ArgumentError, "stream must be created inside an HTTP.Test fixture"

    timeout = Keyword.get(opts, :timeout, 5_000)

    unless is_integer(timeout) and timeout > 0,
      do: raise(ArgumentError, "stream timeout must be finite and positive")

    {:ok, stream} =
      HTTP.Stream.start_link(0, [],
        response_body: true,
        telemetry: false,
        idle_timeout: timeout,
        ack_timeout: timeout
      )

    Process.unlink(stream)
    :ok = track(context, stream, :stream)

    {:ok, producer} =
      Task.Supervisor.start_child(:http_fetch_task_supervisor, fn ->
        receive do
          :produce -> produce(stream, steps, Keyword.get(opts, :trailers, []), timeout, context)
        end
      end)

    :ok = track(context, producer, :producer)
    send(stream, {:enumerable_producer, producer})

    :ok =
      HTTP.RequestLifecycle.attach_stream(
        context.tracker,
        stream,
        System.monotonic_time(:millisecond) + @cleanup_budget
      )

    if observer = opts[:observer], do: send(observer, {:http_test_stream, stream, producer})

    HTTP.Response.new(
      status: Keyword.get(opts, :status, 200),
      body: stream,
      headers: HTTP.Headers.new(Keyword.get(opts, :headers, []))
    )
  end

  @doc """
  Waits at a cooperative response-header gate. Abort returns `{:error, :aborted}`;
  the request deadline or the gate's own `timeout` returns `{:error, :timeout}`.
  """
  def gate(observer, tag, callback, timeout \\ 5_000) when is_function(callback, 0) do
    ref = make_ref()
    send(observer, {:http_test_gate, tag, self(), ref})

    receive do
      {:http_test_release, ^ref} -> callback.()
      :abort -> {:error, :aborted}
      :deadline -> {:error, :timeout}
    after
      timeout -> {:error, :timeout}
    end
  end

  @doc "Invokes an optional buffered Plug bridge with a finite body limit (default 1 MiB)."
  def plug(request, plug, opts \\ []), do: HTTP.Test.PlugBridge.call(request, plug, opts)

  defp attach_upload(context, body) when is_pid(body), do: track(context, body, :stream)
  defp attach_upload(_context, _body), do: :ok

  defp track(context, resource, kind) do
    :ok = Registry.track(context.token, resource, kind)
    :ok = HTTP.Test.Guardian.track(context.guardian, resource, kind)
    if kind == :stream, do: retain_stream_producer(resource), else: :ok
  end

  defp retain_stream_producer(stream) do
    ref = make_ref()
    monitor = Process.monitor(stream)
    send(stream, {:request_lifecycle, Registry, self(), ref})

    result =
      receive do
        {:request_lifecycle_attached, ^ref} -> :ok
        {:DOWN, ^monitor, :process, ^stream, _} -> {:error, :body_stream_closed}
      after
        @cleanup_budget -> {:error, :stream_attachment_timeout}
      end

    Process.demonitor(monitor, [:flush])
    result
  end

  defp settle_resources(token, deadline) do
    alive = Enum.filter(Registry.resources(token), fn {pid, _} -> Process.alive?(pid) end)

    case alive do
      [] ->
        :ok

      resources ->
        monitors =
          Map.new(resources, fn {pid, kind} ->
            monitor = Process.monitor(pid)
            if kind == :stream, do: HTTP.Stream.stop(pid, :aborted), else: send(pid, :abort)
            {monitor, pid}
          end)

        case stop_and_await(monitors, deadline) do
          :ok -> settle_resources(token, deadline)
          error -> error
        end
    end
  end

  defp stop_and_await(monitors, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    case await_resources(monitors, min(remaining, 100)) do
      :ok ->
        :ok

      {:pending, monitors} ->
        Enum.each(monitors, fn {_, pid} -> Process.exit(pid, :kill) end)
        remaining = max(deadline - System.monotonic_time(:millisecond), 0)

        case await_resources(monitors, remaining) do
          :ok ->
            :ok

          {:pending, pending} ->
            Enum.each(pending, fn {ref, _} -> Process.demonitor(ref, [:flush]) end)
            {:error, :cleanup_pending}
        end
    end
  end

  defp await_resources(monitors, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_resource_down(monitors, deadline)
  end

  defp await_resource_down(monitors, _deadline) when map_size(monitors) == 0, do: :ok

  defp await_resource_down(monitors, deadline) do
    receive do
      {:DOWN, monitor, :process, _, _} when is_map_key(monitors, monitor) ->
        await_resource_down(Map.delete(monitors, monitor), deadline)
    after
      max(deadline - System.monotonic_time(:millisecond), 0) -> {:pending, monitors}
    end
  end

  defp configure(name, mode, count, callback),
    do: check!(Registry.configure(self(), name, mode, count, callback))

  defp check!(:ok), do: :ok

  defp check!({:error, reason}),
    do: raise(ArgumentError, "HTTP.Test configuration failed: #{inspect(reason)}")

  defp verify_result!(:ok), do: :ok

  defp verify_result!({:error, failures}) do
    failures = List.wrap(failures)

    raise HTTP.Test.VerificationError,
      message: "HTTP.Test verification failed: #{inspect(failures)}",
      failures: failures
  end

  defp validate_request(%HTTP.Request{
         url: %URI{scheme: scheme, host: host},
         transport_options: opts
       })
       when scheme in ["http", "https"] and is_binary(host) and host != "" do
    cond do
      opts[:transport_scope] != nil -> {:error, :transport_scope_unsupported}
      opts[:pool] != nil -> {:error, :pool_unsupported}
      true -> :ok
    end
  end

  defp validate_request(_), do: {:error, :invalid_url}

  defp validate_result!(%HTTP.Response{} = response), do: response
  defp validate_result!({:error, _} = error), do: error

  defp validate_result!(other),
    do: raise(ArgumentError, "HTTP.Test callback returned an invalid response: #{inspect(other)}")

  defp redirect_policy(%HTTP.Response{} = response, request) do
    candidate? =
      response.status in [301, 302, 303, 307, 308] and
        is_binary(HTTP.Headers.get(response.headers, "location"))

    if candidate? do
      case Keyword.get(request.transport_options, :redirect, :follow) do
        :manual -> response
        :error -> discard_response(response, :redirect)
        :follow -> discard_response(response, {:unsupported_test_policy, :redirect_follow})
      end
    else
      response
    end
  end

  defp redirect_policy(error, _request), do: error

  defp discard_response(response, reason) do
    if is_pid(response.body), do: HTTP.Stream.stop(response.body, reason)
    {:error, reason}
  end

  defp produce(stream, steps, trailers, timeout, context) do
    result =
      Enum.reduce_while(steps, :ok, fn step, :ok ->
        case produce_step(stream, step, timeout) do
          :ok -> {:cont, :ok}
          {:error, _} = error -> {:halt, error}
        end
      end)

    case result do
      :ok -> HTTP.Stream.finish(stream, trailers)
      {:error, reason} -> HTTP.Stream.error(stream, reason)
    end
  catch
    kind, reason ->
      Registry.failed(context.token, self(), {:producer_failure, kind, reason, __STACKTRACE__})
      HTTP.Stream.error(stream, {:source_failure, kind, reason})
  end

  defp produce_step(_stream, {:gate, observer, tag}, timeout),
    do: gate(observer, tag, fn -> :ok end, timeout)

  defp produce_step(_stream, {:error, reason}, _timeout), do: {:error, reason}

  defp produce_step(stream, chunk, timeout),
    do: HTTP.Stream.chunk(stream, IO.iodata_to_binary(chunk), timeout)
end
