defmodule HTTP.QUIC.ExQuicTest do
  use ExUnit.Case, async: true
  alias HTTP.QUIC.ExQuic, as: Adapter

  defmodule Driver do
    # A strict script: an extra call (including a retry or connection close),
    # wrong handle, changed reference or altered argument fails immediately.
    for {name, arity} <- [
          connect: 3,
          attach: 3,
          ready: 1,
          info: 1,
          open_stream: 3,
          send_stream: 4,
          read: 3,
          events: 3,
          reset_stream: 3,
          stop_stream: 3,
          close: 4,
          operation_status: 2
        ] do
      args = Macro.generate_arguments(arity, __MODULE__)

      def unquote(name)(unquote_splicing(args)) do
        [{expected, arguments, result} | rest] = Process.get(:driver_script)
        true = expected == unquote(name)
        true = arguments == [unquote_splicing(args)]
        Process.put(:driver_script, rest)
        result
      end
    end
  end

  setup do
    connection = %{connection: make_ref(), generation: make_ref()}
    {:ok, connection: connection, stream: %{connection: connection, id: 2}}
  end

  test "admission, readiness, references and generation pass through unchanged", ctx do
    endpoint = self()
    ref = make_ref()
    opts = [ref: ref, timeout: 10, deadline: 20]
    metadata = %{alpn: "ex-quic-phase1", http3: false}

    script([
      {:connect, [endpoint, {{127, 0, 0, 1}, 443}, opts], {:ok, ctx.connection}},
      {:attach, [ctx.connection, self(), opts], :ok},
      {:ready, [ctx.connection], :pending},
      {:info, [ctx.connection], {:ok, metadata}},
      {:open_stream, [ctx.connection, :uni, opts], {:ok, ctx.stream}}
    ])

    assert {:ok, conn} = Adapter.connect(endpoint, {{127, 0, 0, 1}, 443}, opts, Driver)
    assert :ok = Adapter.attach(conn, self(), opts, Driver)
    assert :pending = Adapter.ready(conn, Driver)
    assert {:ok, ^metadata} = Adapter.info(conn, Driver)
    assert {:ok, ctx.stream} == Adapter.open_stream(conn, :uni, opts, Driver)
    done()
  end

  test "blocked and unknown writes never retry or become successful sends", ctx do
    ref = make_ref()
    opts = [ref: ref, timeout: 1, deadline: 100]
    bytes = :binary.copy("x", 16_384)
    result = %{status: :admitted, result: {:ok, ref}}

    script([
      {:send_stream, [ctx.stream, bytes, true, opts], {:blocked, :stream_credit}},
      {:send_stream, [ctx.stream, bytes, true, opts], {:unknown, ref}},
      {:operation_status, [ctx.connection, ref], result}
    ])

    assert {:blocked, :stream_credit} = Adapter.send_stream(ctx.stream, bytes, true, opts, Driver)
    assert {:unknown, ^ref} = Adapter.send_stream(ctx.stream, bytes, true, opts, Driver)
    assert ^result = Adapter.operation_status(ctx.connection, ref, Driver)
    done()
  end

  test "destructive read uncertainty retains the exact operation reference", ctx do
    ref = make_ref()
    opts = [ref: ref, timeout: 0]
    items = [{:data, 2, "bytes"}, {:fin, 2}]
    result = %{status: :completed, result: {:ok, items}}

    script([
      {:read, [ctx.stream, 1024, opts], {:unknown, ref}},
      {:operation_status, [ctx.connection, ref], result},
      {:events, [ctx.connection, 32, opts], {:ok, [{:readable, ctx.stream}]}}
    ])

    assert {:unknown, ^ref} = Adapter.read(ctx.stream, 1024, opts, Driver)
    assert ^result = Adapter.operation_status(ctx.connection, ref, Driver)
    assert {:ok, [{:readable, ctx.stream}]} == Adapter.events(ctx.connection, 32, opts, Driver)
    done()
  end

  test "reset and stop act on one stream; connection close is explicit", ctx do
    ref = make_ref()
    opts = [ref: ref]

    script([
      {:reset_stream, [ctx.stream, 42, opts], {:ok, ref}},
      {:stop_stream, [ctx.stream, 43, opts], {:ok, ref}},
      {:close, [ctx.connection, 44, <<255>>, opts], {:error, :closed}}
    ])

    assert {:ok, ^ref} = Adapter.reset_stream(ctx.stream, 42, opts, Driver)
    assert {:ok, ^ref} = Adapter.stop_stream(ctx.stream, 43, opts, Driver)
    assert {:error, :closed} = Adapter.close(ctx.connection, 44, <<255>>, opts, Driver)
    done()
  end

  test "invalid bounds reject before driver calls", ctx do
    script([])

    for bytes <- [:binary.copy("x", 16_385), ["iodata"]] do
      assert {:error, :invalid_write} = Adapter.send_stream(ctx.stream, bytes, false, [], Driver)
    end

    for size <- [0, -1, 16_385, :infinity] do
      assert {:error, :invalid_read_limit} = Adapter.read(ctx.stream, size, [], Driver)
    end

    for size <- [0, 129, :infinity] do
      assert {:error, :invalid_event_limit} = Adapter.events(ctx.connection, size, [], Driver)
    end

    done()
  end

  test "late or unrelated connection generations are not consumed", ctx do
    stale = %{ctx.connection | generation: make_ref()}

    assert {:ready, %{alpn: "raw"}} =
             Adapter.normalize_message(
               {:quic_ready, ctx.connection, %{alpn: "raw"}},
               ctx.connection
             )

    assert {:closed, :timeout} =
             Adapter.normalize_message({:quic_closed, ctx.connection, :timeout}, ctx.connection)

    assert :unknown = Adapter.normalize_message({:quic_closed, stale, :timeout}, ctx.connection)
    assert :unknown = Adapter.normalize_message({:quic_ready, stale, %{}}, ctx.connection)

    assert :unknown =
             Adapter.normalize_message({:quic_h3, ctx.connection, :connected}, ctx.connection)
  end

  test "endpoint options cannot replace normalized TLS or enable diagnostic delivery" do
    for options <- [
          [tls: []],
          [stream_observer: self()],
          [io: :anything],
          [streams: [], streams: []]
        ] do
      assert {:error, {:options, :invalid_endpoint_options}} =
               Adapter.client("localhost", [], options, Driver)
    end
  end

  test "adapter and TLS normalizer have no legacy QUIC or private-state imports" do
    for module <- [Adapter, HTTP.QUIC.TLSOptions] do
      {:ok, {^module, [imports: imports]}} =
        module |> :code.which() |> :beam_lib.chunks([:imports])

      refute Enum.any?(imports, fn {module, function, _arity} ->
               module in [:quic, :quic_h3] or
                 (module == :sys and function == :get_state) or
                 module in [Quic.Connection, Quic.Endpoint]
             end)
    end
  end

  defp script(steps), do: Process.put(:driver_script, steps)
  defp done, do: assert(Process.get(:driver_script) == [])
end
