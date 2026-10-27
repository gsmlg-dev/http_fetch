defmodule HTTP.FormDataStreamFileTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :tmp_dir

  alias HTTP.FormData

  test "construction never opens or reads a file", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "lazy.bin")
    File.write!(path, :binary.copy(<<0, 255, 10>>, 350_000))
    form = file_form(path)

    assert {:ok, envelope} = FormData.to_stream(form)
    File.rm!(path)

    assert_raise File.Error, fn -> Enum.to_list(envelope.body) end
  end

  test "default and large-chunk File.Streams preserve bytes with bounded output", %{
    tmp_dir: tmp_dir
  } do
    path = Path.join(tmp_dir, "binary.bin")
    content = :binary.copy(<<0, 255, 13, 10, 128>>, 40_001)
    File.write!(path, content)

    for file <- [File.stream!(path), File.stream!(path, 1_000_000)] do
      form =
        FormData.new()
        |> FormData.append_field("first", "one")
        |> FormData.append_file("file", "audio.bin", file)
        |> FormData.append_field("last", "two")
        |> Map.put(:boundary, "file-boundary")

      assert {:ok, envelope} = FormData.to_stream(form, chunk_size: 1_024)
      chunks = Enum.to_list(envelope.body)
      assert Enum.all?(chunks, &(is_binary(&1) and byte_size(&1) <= 1_024))
      assert {:multipart, buffered, "file-boundary"} = FormData.to_body(form)
      assert Enum.join(chunks) == IO.iodata_to_binary(buffered)
      assert envelope.content_length == IO.iodata_length(buffered)
    end
  end

  test "a suspended enumeration opens only the current file and halt closes it", %{
    tmp_dir: tmp_dir
  } do
    first = Path.join(tmp_dir, "first.bin")
    second = Path.join(tmp_dir, "second.bin")
    File.write!(first, :binary.copy("a", 100_000))
    File.write!(second, "later")

    form =
      file_form(first)
      |> FormData.append_file("second", "second.bin", File.stream!(second))

    assert {:ok, envelope} = FormData.to_stream(form, chunk_size: 1_024)
    parent = self()

    reader =
      spawn(fn ->
        receive do
          :start -> :ok
        end

        assert {:suspended, _chunks, continuation} =
                 Enumerable.reduce(envelope.body, {:cont, []}, fn chunk, acc ->
                   if length(acc) == 1,
                     do: {:suspend, [chunk | acc]},
                     else: {:cont, [chunk | acc]}
                 end)

        send(parent, {:suspended, self()})

        receive do
          :halt -> continuation.({:halt, []})
        end

        send(parent, {:halted, self()})
      end)

    trace_open(reader)
    send(reader, :start)
    assert_receive {:trace, ^reader, :return_from, {File, :open!, 2}, file}, 2_000
    assert is_pid(file)
    monitor = Process.monitor(file)
    assert_receive {:suspended, ^reader}, 2_000
    File.rm!(second)
    send(reader, :halt)
    assert_receive {:halted, ^reader}, 2_000
    assert_receive {:DOWN, ^monitor, :process, ^file, _}, 2_000
    assert {:error, :terminated} = :file.read(file, 1)
  end

  test "rejects transformed, remote, nonregular and missing files", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "source.bin")
    File.write!(path, "bytes")

    for source <- [
          File.stream!(path, 1_024, [:compressed]),
          File.stream!(path, 1_024, [:utf8]),
          %{File.stream!(path) | node: :other@host},
          %{File.stream!(path) | modes: [:write, :binary]}
        ] do
      assert {:error, :unsupported_multipart_file_stream} =
               FormData.new()
               |> FormData.append_file("file", "source.bin", source)
               |> FormData.to_stream()
    end

    assert {:error, {:unsupported_multipart_file_type, ^tmp_dir, :directory}} =
             tmp_dir |> file_form() |> FormData.to_stream()

    File.rm!(path)

    assert {:error, {:multipart_file_stat, ^path, :enoent}} =
             path |> file_form() |> FormData.to_stream()
  end

  defp file_form(path) do
    FormData.new()
    |> FormData.append_file("file", "audio.bin", File.stream!(path))
    |> Map.put(:boundary, "file-boundary")
  end

  defp trace_open(reader) do
    :erlang.trace_pattern({File, :open!, 2}, [{:_, [], [{:return_trace}]}], [])
    :erlang.trace(reader, true, [:call, {:tracer, self()}])

    on_exit(fn ->
      :erlang.trace_pattern({File, :open!, 2}, false, [])
      if Process.alive?(reader), do: Process.exit(reader, :kill)
    end)
  end
end
