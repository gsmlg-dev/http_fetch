defmodule Quic.OperationResourceAccountingTest do
  use ExUnit.Case, async: true

  alias Quic.{Connection, Streams}
  alias Quic.Runtime.{ConnectionHandle, StreamHandle}

  defmodule TLS do
    def new(_, _) do
      secret = %SSL.QUIC.Secret{
        level: :application,
        direction: :write,
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: :binary.copy(<<1>>, 32)
      }

      {:ok, :application, [secret, %{secret | direction: :read}]}
    end

    def info(_), do: %{receive_level: :application}
    def abort(state, _), do: state
  end

  defmodule Writer do
    def send(_, _, _), do: {:ok, System.monotonic_time(:microsecond)}
    def monotonic_time, do: System.monotonic_time(:microsecond)
  end

  test "accounts exact retained results across replay, rejection and oldest eviction" do
    for limit <- [1, 2, 256] do
      payload = :binary.copy("response", 128)
      {connection, stream} = connection(limit, payload)
      model = %{entries: [], peak: 0, limit: limit}
      assert_accounting(connection, model)

      read_ref = make_ref()
      <<first::binary-size(512), remaining::binary>> = payload
      first_result = {:ok, [{:data, 1, first}]}
      assert ^first_result = Quic.read(stream, 512, ref: read_ref)
      model = remember(connection, model, read_ref, :completed, first_result)

      # An already completed reference replays even after its new deadline expired.
      assert ^first_result = Quic.read(stream, 512, ref: read_ref, deadline: 0)
      assert_accounting(connection, model)

      assert {:error, :operation_ref_conflict} = Quic.read(stream, 511, ref: read_ref)
      assert_accounting(connection, model)

      assert %{status: :completed, result: ^first_result} =
               Quic.operation_status(connection, read_ref)

      invalid_ref = make_ref()
      assert {:error, :invalid_operation} = Quic.read(stream, 0, ref: invalid_ref)
      model = remember(connection, model, invalid_ref, :rejected, {:error, :invalid_operation})

      expired_ref = make_ref()

      assert {:error, :deadline_expired} =
               Quic.events(connection, 1, ref: expired_ref, deadline: 0)

      model = remember(connection, model, expired_ref, :rejected, {:error, :deadline_expired})

      next_ref = make_ref()
      next_result = {:ok, [{:data, 1, remaining}]}
      assert ^next_result = Quic.read(stream, 512, ref: next_ref)
      model = remember(connection, model, next_ref, :completed, next_result)

      empty_ref = make_ref()
      assert {:ok, []} = Quic.read(stream, 512, ref: empty_ref)
      model = remember(connection, model, empty_ref, :completed, {:ok, []})

      model =
        Enum.reduce(1..(limit + 2), model, fn _, model ->
          ref = make_ref()
          assert {:ok, []} = Quic.events(connection, 1, ref: ref)
          remember(connection, model, ref, :completed, {:ok, []})
        end)

      assert :unknown = Quic.operation_status(connection, read_ref)
      assert :unknown = Quic.operation_status(connection, next_ref)
      assert {:ok, %{resources: %{ready_bytes: 0}}} = Quic.info(connection)
      assert_accounting(connection, model)

      for {ref, status, result} <- model.entries do
        assert %{status: ^status, result: ^result} = Quic.operation_status(connection, ref)
      end
    end
  end

  test "invalid identities and status observations do not change result accounting" do
    {connection, stream} = connection(2, "body")
    ref = make_ref()
    result = {:ok, [{:data, 1, "body"}]}
    assert ^result = Quic.read(stream, 4, ref: ref)
    model = remember(connection, %{entries: [], peak: 0, limit: 2}, ref, :completed, result)

    stale = %{connection | generation: make_ref()}
    stale_ref = make_ref()
    assert {:error, :stale_handle} = Quic.events(stale, 1, ref: stale_ref)
    assert :unknown = Quic.operation_status(connection, stale_ref)

    assert {:error, :invalid_operation} = Quic.events(connection, 1, ref: :invalid)
    assert :unknown = Quic.operation_status(connection, :invalid)

    for _ <- 1..20 do
      assert %{status: :completed, result: ^result} = Quic.operation_status(connection, ref)
      assert_accounting(connection, model)
    end

    other_ref = make_ref()
    task = Task.async(fn -> Quic.events(connection, 1, ref: other_ref) end)
    assert {:error, :not_consumer} = Task.await(task)
    remember(connection, model, other_ref, :rejected, {:error, :not_consumer})
  end

  defp connection(limit, payload) do
    pid =
      start_supervised!(
        {Connection,
         owner: self(),
         role: :client,
         io: {Writer, self()},
         remote: {{127, 0, 0, 1}, 4433},
         handshake_timeout: 30_000,
         idle_timeout: :infinity,
         operation_limit: limit,
         scheduler: [
           dcid: <<1, 2, 3, 4>>,
           scid: <<5, 6, 7, 8>>,
           adapter: TLS,
           streams: [delivery: :manual]
         ]},
        id: make_ref()
      )

    generation = Connection.status(pid).generation

    # This prepares only the accounting fixture. It does not establish TLS authentication.
    :sys.replace_state(pid, fn {_, data} ->
      {:ok, streams, []} =
        Streams.receive(data.scheduler.streams, %{
          type: :stream,
          stream_id: 1,
          offset: 0,
          data: payload,
          fin: false
        })

      {:established,
       %{
         data
         | scheduler: %{data.scheduler | streams: streams},
           ready: true,
           ready_notified: true,
           parameters_valid: true
       }}
    end)

    handle = %ConnectionHandle{id: pid, generation: generation}
    assert :ok = Quic.attach(handle, self())
    {handle, %StreamHandle{connection: handle, id: 1}}
  end

  defp remember(connection, model, ref, status, result) do
    # Independent FIFO oracle contains only results expected from public operations.
    entries = model.entries ++ [{ref, status, result}]
    {discarded, retained} = Enum.split(entries, max(length(entries) - model.limit, 0))
    bytes = result_bytes(retained)
    next = %{model | entries: retained, peak: max(model.peak, bytes)}

    assert %{status: ^status, result: ^result} = Quic.operation_status(connection, ref)

    for {evicted, _, _} <- discarded do
      assert :unknown = Quic.operation_status(connection, evicted)
    end

    assert_accounting(connection, next)
    next
  end

  defp assert_accounting(connection, model) do
    expected_bytes = result_bytes(model.entries)
    expected_count = length(model.entries)
    expected_peak = model.peak

    assert {:ok,
            %{
              resources: %{
                operation_result_bytes: ^expected_bytes,
                operations: ^expected_count
              },
              highwaters: %{operation_result_bytes: ^expected_peak}
            }} = Quic.info(connection)
  end

  defp result_bytes(entries),
    do:
      Enum.reduce(entries, 0, fn {_, _, result}, total ->
        total + :erlang.external_size(result)
      end)
end
