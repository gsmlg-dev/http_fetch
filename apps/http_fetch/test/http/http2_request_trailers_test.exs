defmodule HTTP.HTTP2RequestTrailersTest do
  use ExUnit.Case, async: false

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "public TLS upload transmits DATA then ordered duplicate trailing HEADERS" do
    {peer, url} = peer()
    {:ok, source} = HTTP.Stream.start_link(4)
    promise = fetch(url, body: source, duplex: :half, headers: [{"content-length", "4"}])
    assert :ok = HTTP.Stream.chunk(source, "data", 2_000)
    assert :ok = HTTP.Stream.finish(source, [{"X-Checksum", "one"}, {"X-Checksum", "two"}])
    assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, 6_000)
    result = response |> HTTP.Response.read_all() |> JSON.decode!()
    assert result["body"] == Base.encode64("data")
    assert result["trailers"] == [["x-checksum", "one"], ["x-checksum", "two"]]
    assert event(peer, "end")["trailers"] == result["trailers"]
  end

  for backend <- [:ssl, :ex_ssl] do
    test "empty TLS upload and successive trailers preserve HPACK state with #{backend}" do
      {peer, url} = peer()

      for expected_id <- [1, 3, 5] do
        {:ok, source} = HTTP.Stream.start_link(0)

        promise =
          fetch(url,
            body: source,
            duplex: :half,
            tls_backend: unquote(backend),
            headers: [{"content-length", "0"}, {"x-initial", "repeated"}]
          )

        assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "repeated"}])
        assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, 6_000)
        result = response |> HTTP.Response.read_all() |> JSON.decode!()
        assert result["id"] == expected_id
        assert result["body"] == ""
        assert result["trailers"] == [["x-checksum", "repeated"]]
        assert event(peer, "end", expected_id)["trailers"] == result["trailers"]
      end
    end
  end

  test "invalid public trailers leave the upload usable beside an active sibling" do
    {peer, url} = peer()
    sibling = fetch(hold(url), [])
    sibling_id = event(peer, "headers")["id"]
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(url, body: source, duplex: :half)
    upload_id = event(peer, "headers")["id"]

    for fields <- [[{"content-length", "0"}], [{"Host", "other"}], [{"authorization", "secret"}]] do
      assert {:error, {:forbidden_trailer, _}} = HTTP.Stream.finish(source, fields)
    end

    for fields <- [[{":status", "200"}], [{"x-checksum", "bad\r\nvalue"}], [:invalid]] do
      assert {:error, :invalid_trailer} = HTTP.Stream.finish(source, fields)
    end

    assert {:error, :trailers_too_large} =
             HTTP.Stream.finish(source, List.duplicate({"x-checksum", "a"}, 129))

    assert {:error, :trailers_too_large} =
             HTTP.Stream.finish(source, [{"x-checksum", String.duplicate("a", 65_536)}])

    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "accepted"}])
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise, 6_000)
    assert event(peer, "end", upload_id)["trailers"] == [["x-checksum", "accepted"]]
    command(peer, "respond", sibling_id)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(sibling, 6_000)
  end

  test "maximum bounded trailers fragment into CONTINUATION beside an active sibling" do
    {peer, url} = peer()
    sibling = fetch(hold(url), [])
    sibling_id = event(peer, "headers")["id"]
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(hold(url), body: source, duplex: :half)
    upload_id = event(peer, "headers")["id"]
    # Exactly 65,536 serialized bytes: 2 + name(1) + value(65,529) + separators(4).
    value = String.duplicate("Z", 65_529)
    assert :ok = HTTP.Stream.finish(source, [{"x", value}])
    result = event(peer, "end", upload_id)
    assert result["trailers"] == [["x", value]]
    assert result["continuation"] >= 1
    command(peer, "respond", sibling_id)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(sibling, 6_000)
    command(peer, "respond", upload_id)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise, 6_000)
  end

  test "128 permitted duplicate fields reach the peer in order" do
    {peer, url} = peer()
    {:ok, source} = HTTP.Stream.start_link(0)
    fields = Enum.map(1..128, &{"x-checksum", Integer.to_string(&1)})
    promise = fetch(url, body: source, duplex: :half)
    assert :ok = HTTP.Stream.finish(source, fields)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise, 6_000)
    assert event(peer, "end")["trailers"] == Enum.map(fields, fn {k, v} -> [k, v] end)
  end

  test "peer header-list limit rejects only the upload and sends no trailers" do
    {peer, url} = peer(["--header-limit", "1024"])
    # Establish the connection and process the independent peer's SETTINGS first.
    assert %HTTP.Response{status: 200} = fetch(url, []) |> HTTP.Promise.await(6_000)
    sibling = fetch(hold(url), [])
    sibling_id = event(peer, "headers", 3)["id"]
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(hold(url), body: source, duplex: :half)
    upload_id = event(peer, "headers", 5)["id"]
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", String.duplicate("a", 1024)}])
    assert {:error, {:body_error, :trailers_too_large}} = HTTP.Promise.await(promise, 6_000)
    assert event(peer, "reset", upload_id)["code"] == 8
    command(peer, "snapshot", upload_id)
    assert event(peer, "snapshot", upload_id)["trailers"] == []
    command(peer, "respond", sibling_id)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(sibling, 6_000)
    assert %HTTP.Response{status: 200} = fetch(url, []) |> HTTP.Promise.await(6_000)
    assert event(peer, "end", 7)["trailers"] == []
  end

  test "short fixed-length body resets without sending trailers" do
    {peer, url} = peer()
    {:ok, source} = HTTP.Stream.start_link(4)
    promise = fetch(hold(url), body: source, duplex: :half, headers: [{"content-length", "4"}])
    upload_id = event(peer, "headers")["id"]
    assert :ok = HTTP.Stream.chunk(source, "abc", 2_000)
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "three"}])
    assert {:error, {:body_error, :content_length_mismatch}} = HTTP.Promise.await(promise, 6_000)
    event(peer, "reset", upload_id)
    command(peer, "snapshot", upload_id)
    result = event(peer, "snapshot", upload_id)
    assert result["body"] == Base.encode64("abc")
    assert result["trailers"] == []
    assert %HTTP.Response{status: 200} = fetch(url, []) |> HTTP.Promise.await(6_000)
  end

  test "flow-controlled DATA drains completely before trailing HEADERS" do
    {peer, url} = peer(["--window", "3"])
    {:ok, source} = HTTP.Stream.start_link(6)
    promise = fetch(url, body: source, duplex: :half, headers: [{"content-length", "6"}])
    upload_id = event(peer, "headers")["id"]
    # The tiny peer window applies after the client has received its SETTINGS.
    event(peer, "settings_ack")
    producer = Task.async(fn -> HTTP.Stream.chunk(source, "abcdef", 4_000) end)
    assert event(peer, "data", upload_id)["bytes"] == 3
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "six"}])
    assert Task.yield(producer, 0) == nil
    command(peer, "snapshot", upload_id)
    assert event(peer, "snapshot", upload_id)["trailers"] == []
    command(peer, "grant", upload_id, %{"bytes" => 3})
    assert Task.await(producer, 4_000) == :ok
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise, 6_000)
    result = event(peer, "end", upload_id)
    assert result["body"] == Base.encode64("abcdef")
    assert result["trailers"] == [["x-checksum", "six"]]
  end

  for outcome <- [:abort, :reset, :early_response, :timeout] do
    test "#{outcome} while DATA is blocked discards queued trailers and preserves a sibling" do
      {peer, url} = peer(["--window", "3"])
      sibling = fetch(hold(url), [])
      sibling_id = event(peer, "headers")["id"]
      event(peer, "settings_ack")
      {:ok, source} = HTTP.Stream.start_link(6)
      controller = HTTP.AbortController.new()

      promise =
        fetch(hold(url),
          body: source,
          duplex: :half,
          signal: controller,
          timeout: if(unquote(outcome) == :timeout, do: 500, else: 5_000)
        )

      upload_id = event(peer, "headers")["id"]
      producer = Task.async(fn -> HTTP.Stream.chunk(source, "abcdef", 4_000) end)
      assert event(peer, "data", upload_id)["bytes"] == 3
      assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "discard"}])

      case unquote(outcome) do
        :abort -> HTTP.AbortController.abort(controller)
        :reset -> command(peer, "reset", upload_id)
        :early_response -> command(peer, "respond", upload_id)
        :timeout -> :ok
      end

      result = HTTP.Promise.await(promise, 6_000)

      case unquote(outcome) do
        :abort -> assert result == {:error, :aborted}
        :reset -> assert result == {:error, {:stream_reset, :cancel}}
        :early_response -> assert %HTTP.Response{status: 200} = result
        :timeout -> assert result == {:error, :request_timeout}
      end

      assert {:error, _reason} = Task.await(producer, 4_000)
      unless unquote(outcome) == :reset, do: event(peer, "reset", upload_id)
      command(peer, "snapshot", upload_id)
      snapshot = event(peer, "snapshot", upload_id)
      assert snapshot["body"] == Base.encode64("abc")
      assert snapshot["trailers"] == []
      command(peer, "respond", sibling_id)
      assert %HTTP.Response{status: 200} = HTTP.Promise.await(sibling, 6_000)
      assert %HTTP.Response{status: 200} = fetch(url, []) |> HTTP.Promise.await(6_000)
    end
  end

  test "cancellation after trailing HEADERS resets only its response half" do
    {peer, url} = peer()
    controller = HTTP.AbortController.new()
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(hold(url), body: source, duplex: :half, signal: controller)
    upload_id = event(peer, "headers")["id"]
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "complete"}])
    assert event(peer, "end", upload_id)["trailers"] == [["x-checksum", "complete"]]
    assert :ok = HTTP.AbortController.abort(controller)
    assert {:error, :aborted} = HTTP.Promise.await(promise, 6_000)
    event(peer, "reset", upload_id)
    assert %HTTP.Response{status: 200} = fetch(url, []) |> HTTP.Promise.await(6_000)
    assert event(peer, "end", 3)["trailers"] == []
  end

  test "cancellation during fragmented trailer write completes its HPACK batch before reset" do
    {peer, url} = peer()
    sibling = fetch(hold(url), [])
    sibling_id = event(peer, "headers")["id"]
    controller = HTTP.AbortController.new()
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(hold(url), body: source, duplex: :half, signal: controller)
    upload_id = event(peer, "headers")["id"]
    owner = gate_trailer_write(url, upload_id, :complete)
    value = String.duplicate("Z", 50_000)
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", value}])
    assert_receive {:trailer_fragment_written, ^owner}, 2_000
    assert :ok = HTTP.AbortController.abort(controller)
    await_cancel_call(owner, upload_id, System.monotonic_time(:millisecond) + 2_000)
    send(owner, :release_trailer_write)
    assert {:error, :aborted} = HTTP.Promise.await(promise, 6_000)
    assert event(peer, "end", upload_id)["trailers"] == [["x-checksum", value]]
    event(peer, "reset", upload_id)
    command(peer, "respond", sibling_id)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(sibling, 6_000)
    assert %HTTP.Response{status: 200} = fetch(url, []) |> HTTP.Promise.await(6_000)
    assert event(peer, "end", 5)["trailers"] == []
  end

  test "writer queue rejects trailers before committing HPACK and keeps a sibling healthy" do
    {peer, url} = peer()
    sibling = fetch(hold(url), headers: [{"x-initial", "shared"}])
    sibling_id = event(peer, "headers")["id"]
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(hold(url), body: source, duplex: :half)
    upload_id = event(peer, "headers")["id"]
    owner = owner_for(url)
    :sys.replace_state(owner, &%{&1 | max_queue_bytes: 1024})
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", String.duplicate("Z", 5_000)}])
    assert {:error, {:body_error, :writer_queue_full}} = HTTP.Promise.await(promise, 6_000)
    event(peer, "reset", upload_id)
    command(peer, "snapshot", upload_id)
    assert event(peer, "snapshot", upload_id)["trailers"] == []
    command(peer, "respond", sibling_id)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(sibling, 6_000)

    assert %HTTP.Response{status: 200} =
             fetch(url, headers: [{"x-initial", "shared"}]) |> HTTP.Promise.await(6_000)
  end

  test "a failed partial trailer write retires the connection and fails both requests" do
    {peer, url} = peer()
    sibling = fetch(hold(url), [])
    event(peer, "headers")
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(hold(url), body: source, duplex: :half)
    upload_id = event(peer, "headers")["id"]
    owner = gate_trailer_write(url, upload_id, :fail)
    monitor = Process.monitor(owner)
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", String.duplicate("Z", 50_000)}])
    assert_receive {:trailer_fragment_written, ^owner}, 2_000
    send(owner, :release_trailer_write)
    assert {:error, {:transport_error, :timeout}} = HTTP.Promise.await(promise, 6_000)
    assert {:error, {:transport_error, :timeout}} = HTTP.Promise.await(sibling, 6_000)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 2_000
  end

  # Keep the real TLS socket and independent decoder, but gate between a trailer
  # HEADERS and its CONTINUATION frames inside the owner's single transport send.
  defp gate_trailer_write(url, id, outcome) do
    test_pid = self()
    owner = owner_for(url)

    :sys.replace_state(owner, fn state ->
      transport = state.transport

      gated = %{
        close: &transport.close/1,
        setopts: &transport.setopts/2,
        normalize_message: &transport.normalize_message/2,
        send: fn socket, frames ->
          wire = IO.iodata_to_binary(frames)

          case wire do
            <<size::24, 1, 1, ^id::32, _::binary>> ->
              <<first::binary-size(size + 9), rest::binary>> = wire
              :ok = transport.send(socket, first)
              send(test_pid, {:trailer_fragment_written, self()})

              receive do
                :release_trailer_write ->
                  if outcome == :complete,
                    do: transport.send(socket, rest),
                    else: {:error, :timeout}
              after
                3_000 -> {:error, :timeout}
              end

            _ ->
              transport.send(socket, frames)
          end
        end
      }

      %{state | transport: gated}
    end)

    owner
  end

  defp owner_for(url) do
    port = URI.parse(url).port

    :http_fetch_http2_pool
    |> :sys.get_state()
    |> Map.fetch!(:entries)
    |> Enum.find_value(fn {key, entry} ->
      if key.port == port, do: entry.connections |> Map.keys() |> List.first()
    end)
  end

  defp await_cancel_call(owner, id, deadline) do
    {:messages, messages} = Process.info(owner, :messages)

    if Enum.any?(messages, &match?({:"$gen_call", _, {:cancel, ^id}}, &1)) do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline,
             "public abort did not queue cancellation during the trailer write"

      :erlang.yield()
      await_cancel_call(owner, id, deadline)
    end
  end

  defp hold(url), do: String.replace_suffix(url, "/echo", "/hold")

  defp command(peer, op, id, fields \\ %{}) do
    assert Port.command(peer, JSON.encode!(Map.merge(%{"op" => op, "id" => id}, fields)) <> "\n")
  end

  defp fetch(url, opts) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          method: :post,
          http_version: :http2,
          http2_profile: :native_v1,
          redirect: :manual,
          tls_backend: :ssl,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          telemetry: false,
          timeout: 5_000
        ],
        opts
      )
    )
  end

  defp peer(opts \\ []) do
    python = System.find_executable("python3") || raise "python3 is required"
    script = Path.expand("../support/http2_upload_trailer_peer.py", __DIR__)

    args =
      [
        script,
        "--cert",
        Path.join(@fixtures, "localhost.pem"),
        "--key",
        Path.join(@fixtures, "localhost.key")
      ] ++ opts

    peer =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 1_000_000},
        args: args
      ])

    on_exit(fn -> if Port.info(peer), do: Port.close(peer) end)
    ready = event(peer, "ready")
    {peer, "https://localhost:#{ready["port"]}/echo"}
  end

  defp event(peer, type, id \\ nil) do
    key = {__MODULE__, peer}
    buffered = Process.get(key, [])

    case Enum.split_while(buffered, &(not matches?(&1, type, id))) do
      {before, [item | rest]} ->
        Process.put(key, before ++ rest)
        item

      _ ->
        receive do
          {^peer, {:data, {:eol, line}}} ->
            item = JSON.decode!(line)

            if matches?(item, type, id) do
              item
            else
              Process.put(key, buffered ++ [item])
              event(peer, type, id)
            end

          {^peer, {:exit_status, status}} ->
            flunk("independent HTTP/2 peer exited with #{status}")
        after
          6_000 -> flunk("independent HTTP/2 peer did not report #{type} for #{inspect(id)}")
        end
    end
  end

  defp matches?(item, type, id), do: item["event"] == type and (id == nil or item["id"] == id)
end
