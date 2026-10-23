defmodule HTTP.HTTP3RequestTrailersTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @fixtures Path.expand("../../../elixir_quic/test/fixtures/tls", __DIR__)

  for body <- ["abc", ""], declaration? <- [false, true] do
    test "ordered duplicate trailers after #{inspect(body)} with declaration=#{declaration?}" do
      {peer, url} = peer()
      {:ok, source} = HTTP.Stream.start_link(0)
      headers = if unquote(declaration?), do: [{"trailer", "x-check"}], else: []
      promise = fetch(url, body: source, duplex: :half, headers: headers)
      identity = event(peer, "headers")["id"]
      if unquote(body) != "", do: assert(:ok = HTTP.Stream.chunk(source, unquote(body), 2_000))
      assert :ok = HTTP.Stream.finish(source, [{"X-Check", "one"}, {"X-Check", "two"}])
      assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, 6_000)
      wire = response |> HTTP.Response.read_all() |> JSON.decode!()
      assert wire["body"] == Base.encode64(unquote(body))
      assert wire["trailers"] == [["x-check", "one"], ["x-check", "two"]]

      expected =
        if unquote(body) == "",
          do: ["headers", "trailers", "fin"],
          else: ["headers", "data", "trailers", "fin"]

      assert wire["events"] == expected
      assert wire["fin"] == 1
      assert wire["requests"] == 1
      assert event(peer, "trailers", identity)["ended"]
      assert event(peer, "end", identity)["fin"] == 1
      if unquote(declaration?), do: assert(["trailer", "x-check"] in wire["headers"])
    end
  end

  test "large trailing HEADERS fragment without DATA or duplicate FIN" do
    {peer, url} = peer()
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(url, body: source, duplex: :half)
    identity = event(peer, "headers")["id"]
    value = String.duplicate("Z", 30_000)
    assert :ok = HTTP.Stream.finish(source, [{"x-check", value}])
    assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, 6_000)
    wire = response |> HTTP.Response.read_all() |> JSON.decode!()
    assert wire["trailers"] == [["x-check", value]]
    assert wire["events"] == ["headers", "trailers", "fin"]
    assert wire["fin"] == 1
    assert event(peer, "end", identity)["requests"] == 1
  end

  test "invalid declarations fail through the public result before origin HEADERS" do
    {peer, url} = peer()

    for declaration <- ["content-length", "x-check, :status"] do
      {:ok, source} = HTTP.Stream.start_link(0)
      promise = fetch(url, body: source, duplex: :half, headers: [{"trailer", declaration}])
      assert {:error, reason} = HTTP.Promise.await(promise, 6_000)
      assert reason in [:forbidden_trailer_declaration, :invalid_trailer_declaration]
    end

    command(peer, "count", "")
    assert event(peer, "count")["requests"] == 0
  end

  test "early final response stops upload before trailers or FIN" do
    {peer, url} = peer()
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(String.replace(url, "/echo", "/early"), body: source, duplex: :half)
    identity = event(peer, "headers")["id"]
    assert %HTTP.Response{status: 413} = response = HTTP.Promise.await(promise, 6_000)
    assert response |> HTTP.Response.read_all() |> JSON.decode!() |> Map.fetch!("fin") == 0
    assert :ok = HTTP.Stream.finish(source, [{"x-check", "discarded"}])
    command(peer, "snapshot", identity)
    wire = event(peer, "snapshot", identity)
    assert wire["trailers"] == []
    assert wire["fin"] == 0
    assert wire["requests"] == 1
  end

  test "field-section budget rejection is reported asynchronously with no terminal HEADERS" do
    {peer, url} = peer()
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = fetch(url, body: source, duplex: :half)
    identity = event(peer, "headers")["id"]
    assert :ok = HTTP.Stream.finish(source, [{"x-check", String.duplicate("a", 65_500)}])
    assert {:error, :request_header_bytes_limit} = HTTP.Promise.await(promise, 6_000)
    command(peer, "snapshot", identity)
    wire = event(peer, "snapshot", identity)
    assert wire["trailers"] == []
    assert wire["fin"] == 0
    assert wire["requests"] == 1
  end

  for outcome <- [:abort, :timeout] do
    test "#{outcome} after trailers/FIN preserves no replay" do
      {peer, url} = peer()
      {:ok, source} = HTTP.Stream.start_link(0)
      controller = HTTP.AbortController.new()
      opts = if unquote(outcome) == :timeout, do: [timeout: 1_000], else: []

      promise =
        fetch(
          String.replace(url, "/echo", "/hold"),
          [body: source, duplex: :half, signal: controller] ++ opts
        )

      identity = event(peer, "headers")["id"]
      assert :ok = HTTP.Stream.finish(source, [{"x-check", "one"}])
      assert event(peer, "end", identity)["fin"] == 1
      if unquote(outcome) == :abort, do: assert(:ok = HTTP.AbortController.abort(controller))
      result = HTTP.Promise.await(promise, 6_000)

      if unquote(outcome) == :abort,
        do: assert(result == {:error, :aborted}),
        else: assert(result == {:error, :request_timeout})

      command(peer, "snapshot", identity)
      assert event(peer, "snapshot", identity)["requests"] == 1
    end
  end

  defp fetch(url, opts) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          method: :post,
          http_version: :http3,
          http3_reuse: false,
          redirect: :manual,
          request_mode: :proxy,
          stream_response: true,
          decode_body: false,
          telemetry: false,
          ssl: [
            cacertfile: Path.join(@fixtures, "root.pem"),
            reference_identity: {:dns_id, "example.test"}
          ],
          timeout: 5_000
        ],
        opts
      )
    )
  end

  defp peer do
    uv = System.find_executable("uv") || raise "uv is required for pinned aioquic"

    peer =
      Port.open({:spawn_executable, uv}, [
        :binary,
        :exit_status,
        {:line, 1_000_000},
        args: [
          "run",
          "--quiet",
          "--python",
          "3.12",
          "--with",
          "aioquic==1.2.0",
          "python3",
          Path.expand("../support/http3_upload_trailer_peer.py", __DIR__),
          "--cert",
          Path.join(@fixtures, "leaf.pem"),
          "--key",
          Path.join(@fixtures, "leaf-key.pem")
        ]
      ])

    on_exit(fn ->
      try do
        Port.close(peer)
      rescue
        ArgumentError -> :ok
      end
    end)

    {peer, "https://127.0.0.1:#{event(peer, "ready")["port"]}/echo"}
  end

  defp command(peer, op, id), do: Port.command(peer, JSON.encode!(%{op: op, id: id}) <> "\n")

  defp event(peer, type, id \\ nil) do
    key = {__MODULE__, peer}
    buffered = Process.get(key, [])

    case Enum.split_while(buffered, &(&1["event"] != type or (id != nil and &1["id"] != id))) do
      {before, [item | rest]} ->
        Process.put(key, before ++ rest)
        item

      _ ->
        receive do
          {^peer, {:data, {:eol, line}}} ->
            item = JSON.decode!(line)
            Process.put(key, buffered ++ [item])
            event(peer, type, id)

          {^peer, {:exit_status, status}} ->
            flunk("independent aioquic peer exited with #{status}")
        after
          10_000 -> flunk("independent aioquic peer did not report #{type}")
        end
    end
  end
end
