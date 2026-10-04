defmodule Quic.Phase1OperationTest do
  use ExUnit.Case, async: true

  alias Quic.Connection

  defmodule TLS do
    def new(_, _), do: {:ok, 0, [{:emit, :initial, <<1, 2>>}]}
    def info(_), do: %{receive_level: :initial}
    def feed(state, :initial, _), do: {:ok, state + 1, []}
    def abort(state, _), do: state
  end

  defmodule Writer do
    def send(_, _, _), do: {:ok, System.monotonic_time(:microsecond)}
    def monotonic_time, do: System.monotonic_time(:microsecond)
  end

  test "public send timeout reports unknown operation reference" do
    {:ok, connection} =
      Connection.start_link(
        role: :client,
        io: {Writer, self()},
        remote: {{127, 0, 0, 1}, 4433},
        handshake_timeout: 1_000,
        scheduler: [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: TLS]
      )

    generation = Connection.status(connection).generation
    :sys.suspend(connection)
    ref = make_ref()

    assert {:unknown, ^ref} =
             Connection.send_public_stream(connection, generation, 0, "x", false,
               ref: ref,
               timeout: 1,
               deadline: 100
             )

    :sys.resume(connection)
    :ok = Connection.close(connection)
  end
end
