defmodule HTTP3PublicGate do
  alias HTTP.HTTP3.{ConnectionOwner, Pool}

  def run do
    fixture = Path.expand("../../apps/elixir_quic/test/fixtures/tls", __DIR__)

    ssl = [
      cacertfile: System.get_env("HTTP3_PEER_CA_FILE", Path.join(fixture, "root.pem")),
      reference_identity: {:dns_id, "example.test"}
    ]

    for {name, port} <- [
          {"aioquic-1.2.0", System.fetch_env!("HTTP3_AIOQUIC_PORT")},
          {"caddy-2.9.1", System.fetch_env!("HTTP3_CADDY_PORT")}
        ] do
      base = "https://127.0.0.1:#{port}"
      options = [http_version: :http3, ssl: ssl, timeout: 30_000]
      basic(base, name, options)
      multiplex(base, name, options)
      negatives(base, options)
      IO.puts("HTTP3 #{name} public integrity/multiplex/TLS: PASS")
    end

    aioquic = "https://127.0.0.1:#{System.fetch_env!("HTTP3_AIOQUIC_PORT")}"
    options = [http_version: :http3, ssl: ssl, timeout: 30_000]
    protocol(aioquic, options)
    sequential(aioquic, options)
    cleanup()
    IO.puts("HTTP3 public acceptance result: PASS")
  end

  defp fetch(base, path, options) do
    case HTTP.fetch(base <> path, options) |> HTTP.Promise.await() do
      %HTTP.Response{http_version: :http3} = response -> response
      other -> raise "strict public HTTP3 failed: #{inspect(other)}"
    end
  end

  defp basic(base, name, options) do
    response = fetch(base, "/", options)
    assert(response.status == 200, "GET status")
    assert(HTTP.Response.get_header(response, "x-peer") == name, "independent peer identity")
    assert(byte_size(HTTP.Response.text(response)) > 0, "GET body")
    assert(HTTP.Response.text(fetch(base, "/empty", options)) == "", "empty FIN")
    body = :binary.copy(<<0, 255, 127, 128, 1, 2, 3>>, 8_817)

    for method <- [:post, :put] do
      response = fetch(base, "/echo", Keyword.merge(options, method: method, body: body))
      assert(HTTP.Response.text(response) == body, "binary #{method} integrity")
    end

    chunks = for n <- 1..128, do: :binary.copy(<<rem(n, 256), 255, 0, 128>>, 4_096)
    {:ok, producer} = HTTP.Stream.from_enumerable(chunks)

    response =
      fetch(base, "/digest", Keyword.merge(options, method: :post, body: producer, duplex: :half))

    digest = :crypto.hash(:sha256, chunks) |> Base.encode16(case: :lower)
    assert(HTTP.Response.text(response) == digest, "2MiB demand upload digest")

    response = fetch(base, "/large", options)
    assert(is_pid(response.body), "large download must stream")

    destination =
      Path.join(System.tmp_dir!(), "http3-public-#{System.unique_integer([:positive])}")

    try do
      assert(HTTP.Response.write_to(response, destination) == :ok, "streamed file")
      expected = :binary.copy(:binary.list_to_bin(Enum.to_list(0..255)), 32_768)
      assert(File.stat!(destination).size == byte_size(expected), "large file size")

      assert(
        :crypto.hash(:sha256, File.read!(destination)) == :crypto.hash(:sha256, expected),
        "large file integrity"
      )
    after
      File.rm(destination)
    end
  end

  defp multiplex(base, name, options) do
    tasks =
      for n <- 1..32 do
        Task.async(fn ->
          body = :binary.copy(<<n, 255, 0, 128>>, 15_432)
          response = fetch(base, "/echo", Keyword.merge(options, method: :put, body: body))
          assert(HTTP.Response.get_header(response, "x-peer") == name, "multiplex peer")
          assert(HTTP.Response.text(response) == body, "multiplex binary integrity")
        end)
      end

    Task.await_many(tasks, 60_000)
    cleanup()
  end

  defp negatives(base, options) do
    for ssl <- [
          [
            cacertfile: System.fetch_env!("HTTP3_WRONG_CA_FILE"),
            reference_identity: {:dns_id, "example.test"}
          ],
          Keyword.put(options[:ssl], :reference_identity, {:dns_id, "wrong.test"})
        ] do
      assert_error(
        HTTP.fetch(base <> "/", Keyword.put(options, :ssl, ssl))
        |> HTTP.Promise.await()
      )
    end

    assert_error(
      HTTP.fetch(base <> "/", Keyword.put(options, :tls_backend, :ssl))
      |> HTTP.Promise.await()
    )

    for key <- ["HTTP3_EXPIRED_PORT", "HTTP3_WRONG_ALPN_PORT"] do
      target = "https://127.0.0.1:#{System.fetch_env!(key)}/"

      assert_error(
        HTTP.fetch(target, Keyword.put(options, :http3_reuse, false))
        |> HTTP.Promise.await()
      )
    end
  end

  defp protocol(base, options) do
    response = fetch(base, "/informational", options)
    assert(match?([{103, _}], response.informational), "informational fields")
    HTTP.Response.text(response)
    response = fetch(base, "/trailers", options)
    assert(HTTP.Response.text(response) == "abc", "trailer body")
    digest = :crypto.hash(:sha256, "abc") |> Base.encode16(case: :lower)
    assert(HTTP.Headers.get(response.trailers, "x-checksum") == digest, "buffered trailers")

    controller = HTTP.AbortController.new()
    pending = HTTP.fetch(base <> "/hold", Keyword.put(options, :signal, controller))
    HTTP.AbortController.abort(controller)
    assert_error(HTTP.Promise.await(pending))
    assert_error(HTTP.fetch(base <> "/reset", options) |> HTTP.Promise.await())
    HTTP.Response.text(fetch(base, "/", options))

    source = HTTP.EventSource.new(base <> "/sse", Keyword.put(options, :reconnect_time, 30_000))

    try do
      receive do
        {HTTP.EventSource, ^source,
         %HTTP.EventSource.Event.Message{data: "h3-event", last_event_id: "42"}} ->
          :ok
      after
        10_000 -> raise "independent H3 SSE message missing"
      end

      assert(HTTP.EventSource.http_version(source) == :http3, "actual SSE H3")
    after
      HTTP.EventSource.close(source)
    end

    port = URI.parse(base).port

    previous_owners =
      Enum.filter(owners(), fn owner -> :sys.get_state(owner).opts[:port] == port end)

    assert(previous_owners != [], "GOAWAY owner identity")
    before = HTTP.Response.get_header(fetch(base, "/goaway", options), "x-connection")
    # A ready owner may not have consumed the GOAWAY yet. Its exit proves draining
    # and terminal cleanup before the next request is admitted.
    wait(fn -> Enum.all?(previous_owners, &(not Process.alive?(&1))) end)

    after_id = HTTP.Response.get_header(fetch(base, "/", options), "x-connection")
    assert(before != after_id, "GOAWAY connection rotation")
  end

  defp sequential(base, options) do
    {ids, count} =
      Enum.reduce(1..10_000, {MapSet.new(), 0}, fn n, {ids, _} ->
        response = fetch(base, "/empty", options)
        assert(HTTP.Response.text(response) == "", "sequential FIN")
        id = HTTP.Response.get_header(response, "x-connection")
        assert(is_binary(id), "connection identity")

        if rem(n, 1_000) == 0 do
          cleanup()
          IO.puts("HTTP3 sequential: #{n}/10000")
        end

        {MapSet.put(ids, id), n}
      end)

    assert(count == 10_000 and MapSet.size(ids) >= 11, "deliberate lifetime rotation")
    IO.puts("HTTP3 10000 sequential across #{MapSet.size(ids)} connections: PASS")
  end

  defp owners do
    for {_, pid, _, _} <-
          DynamicSupervisor.which_children(:http_fetch_http3_connection_supervisor),
        is_pid(pid),
        do: pid
  end

  defp cleanup do
    wait(fn ->
      status = Pool.status(:http_fetch_http3_pool)

      status.leases == 0 and status.pending == 0 and
        Enum.all?(owners(), fn owner ->
          try do
            state = ConnectionOwner.status(owner)

            state.requests == 0 and state.pending == false and state.queued == 0 and
              state.continuations == 0
          catch
            :exit, _ -> true
          end
        end)
    end)
  end

  defp wait(check), do: wait(check, System.monotonic_time(:millisecond) + 5_000)

  defp wait(check, deadline) do
    if check.() do
      :ok
    else
      assert(System.monotonic_time(:millisecond) < deadline, "state barrier timeout")

      receive do
      after
        1 -> wait(check, deadline)
      end
    end
  end

  defp assert_error({:error, _}), do: :ok
  defp assert_error(other), do: raise("negative case unexpectedly succeeded: #{inspect(other)}")
  defp assert(true, _), do: :ok
  defp assert(false, message), do: raise(message)
end

HTTP3PublicGate.run()
