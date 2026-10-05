Code.require_file("admission.exs", __DIR__)
ExUnit.start()

defmodule Quic.Phase1.AdmissionTest do
  use ExUnit.Case, async: false
  alias Quic.Phase1.Admission

  setup do
    Process.put(:credit, %{0 => 64, 4 => 64})
    Process.put(:calls, [])
    Process.put(:accepted, [])
    :ok
  end

  defp send_chunk(stream, bytes, final, _options) do
    Process.put(:calls, Process.get(:calls) ++ [{stream.id, byte_size(bytes), final}])
    credit = Process.get(:credit)

    if byte_size(bytes) > Map.fetch!(credit, stream.id) do
      {:blocked, make_ref()}
    else
      Process.put(:credit, Map.update!(credit, stream.id, &(&1 - byte_size(bytes))))
      Process.put(:accepted, Process.get(:accepted) ++ [{stream.id, bytes, final}])
      {:ok, make_ref()}
    end
  end

  test "smaller same-stream DATA waits behind blocked bytes while sibling progresses" do
    first = {%{id: 0}, :binary.copy("a", 1024), false}
    later = {%{id: 0}, :binary.copy("b", 64), false}
    sibling = {%{id: 4}, "ok", true}

    {pending, nil, _} =
      Admission.run([first, later, sibling], :echoes, MapSet.new(), &send_chunk/4)

    assert pending == [first, later]
    assert Process.get(:calls) == [{0, 1024, false}, {4, 2, true}]
    assert Process.get(:accepted) == [{4, "ok", true}]

    Process.put(:credit, %{0 => 1088, 4 => 0})
    Process.put(:accepted, [])
    assert {[], nil, _} = Admission.run(pending, :echoes, MapSet.new(), &send_chunk/4)
    assert Process.get(:accepted) == [{0, elem(first, 1), false}, {0, elem(later, 1), false}]
  end

  test "same-stream FIN waits behind blocked DATA" do
    items = [{%{id: 0}, :binary.copy("a", 1024), false}, {%{id: 0}, <<>>, true}]
    assert {^items, nil, _} = Admission.run(items, :echoes, MapSet.new(), &send_chunk/4)
    assert Process.get(:calls) == [{0, 1024, false}]
    assert Process.get(:accepted) == []
  end

  test "unknown admission stops further sends and retains the original reference" do
    ref = make_ref()

    sender = fn stream, _bytes, _final, _options ->
      Process.put(:calls, Process.get(:calls) ++ [stream.id])
      {:unknown, ref}
    end

    assert {_, {:unknown, ^ref}, _} =
             Admission.run(
               [{%{id: 0}, "first", false}, {%{id: 4}, "sibling", false}],
               :echoes,
               MapSet.new(),
               sender
             )

    assert Process.get(:calls) == [0]
  end
end
