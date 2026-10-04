defmodule SSL.IodataCursorTest do
  use ExUnit.Case, async: true

  test "streams deeply mixed iodata into bounded chunks without flattening the whole input" do
    data = ["ab", [99, <<100, 101>>, [[], 102]], <<103, 104, 105>>]
    assert {:ok, cursor, 9} = SSL.IodataCursor.new(data)
    assert {chunks, []} = drain(cursor, 3, [])
    assert chunks == ["abc", "def", "ghi"]
  end

  test "retains binary tails and reports invalid iodata before transmission" do
    assert {:ok, cursor, 7} = SSL.IodataCursor.new(["abc" | "defg"])
    assert {chunks, []} = drain(cursor, 2, [])
    assert chunks == ["ab", "cd", "ef", "g"]

    assert {:error, :badarg} = SSL.IodataCursor.new(["valid", :invalid])
  end

  defp drain(cursor, size, chunks) do
    case SSL.IodataCursor.next(cursor, size) do
      :done -> {Enum.reverse(chunks), []}
      {:ok, chunk, cursor} -> drain(cursor, size, [chunk | chunks])
    end
  end
end
