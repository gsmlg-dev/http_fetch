defmodule HTTP3ResumptionGate do
  @moduledoc false
  # Public Fetch with `http3_resumption` and `early_data` against an independent
  # aioquic 1.2.0 peer that issues 0-RTT tickets (scripts/http3/resumption_peer.py).

  def run do
    base = "https://127.0.0.1:#{System.fetch_env!("HTTP3_PEER_PORT")}"

    options = [
      http_version: :http3,
      timeout: 30_000,
      http3_resumption: true,
      http3_reuse: false,
      ssl: [
        cacertfile: "apps/elixir_quic/test/fixtures/tls/root.pem",
        reference_identity: {:dns_id, "example.test"}
      ]
    ]

    early = Keyword.put(options, :early_data, true)

    full = fetch(base, "/r", options)
    expect(full, 200, %{resumed: false, early_data: false}, "0", "first connection")
    settle()
    resumed = fetch(base, "/r", options)
    expect(resumed, 200, %{resumed: true, early_data: false}, "0", "resumed connection")

    # The early partition is distinct; its first connection learns the ticket
    # and the peer SETTINGS that bound later 0-RTT requests.
    expect(fetch(base, "/r", early), 200, %{resumed: false, early_data: false}, "0", "early seed")
    settle()
    zero = fetch(base, "/r", early)
    expect(zero, 200, %{resumed: true, early_data: true}, "1", "0-RTT GET")
    settle()
    head = fetch(base, "/r", Keyword.put(early, :method, :head))
    expect(head, 200, %{resumed: true, early_data: true}, "1", "0-RTT HEAD")
    settle()

    retried = fetch(base, "/too-early", early)
    expect(retried, 200, %{early_data: false}, "0", "425 retried after handshake")
    settle()

    always = fetch(base, "/always-425", options)
    expect(always, 425, %{early_data: false}, "0", "425 without 0-RTT returned as is")

    expect(fetch(base, "/reject-next", options), 200, %{}, "0", "arm ticket miss")
    rejected = trace_resend(fn -> fetch(base, "/r", early) end)
    expect(rejected, 200, %{resumed: false, early_data: false}, "0", "rejected 0-RTT re-sent")

    stats = base |> fetch("/stats", options) |> HTTP.Response.text() |> JSON.decode!()
    requests = stats["requests"]

    assert(
      Enum.count(requests, &(&1["path"] == "/too-early")) == 2 and
        Enum.any?(requests, &(&1["path"] == "/too-early" and &1["early"])) and
        Enum.any?(requests, &(&1["path"] == "/too-early" and not &1["early"])),
      "425 to a 0-RTT request was retried exactly once after the handshake"
    )

    assert(
      Enum.count(requests, &(&1["path"] == "/always-425")) == 1,
      "425 to a non-early request was not retried"
    )

    assert(
      not Enum.any?(requests, &(&1["early"] and &1["method"] not in ["GET", "HEAD", "OPTIONS"])),
      "only safe methods were received in 0-RTT"
    )

    rejected_connection = String.to_integer(HTTP.Response.get_header(rejected, "x-connection"))

    assert(
      Enum.filter(requests, &(&1["connection"] == rejected_connection)) |> length() == 1,
      "rejected 0-RTT request was delivered once on its connection"
    )

    IO.puts("HTTP/3 resumption peer records: #{inspect(stats["connections"])}")

    IO.puts(
      "HTTP/3 resumption/0-RTT aioquic 1.2.0 full, resumed, 0-RTT GET/HEAD, 425 retry, " <>
        "425 passthrough, rejected 0-RTT re-send: PASS"
    )
  end

  # Proves the request was admitted in 0-RTT and re-sent by the session after
  # the peer rejected early data, rather than queued for the handshake.
  defp trace_resend(fun) do
    tracer = self()
    :erlang.trace(:all, true, [:call, {:tracer, tracer}])

    :erlang.trace_pattern(
      {QuicHttp3.Session, :early_disposition, 1},
      [{:_, [], [{:return_trace}]}],
      [:local]
    )

    try do
      response = fun.()

      resent =
        receive do
          {:trace, _pid, :return_from, {QuicHttp3.Session, :early_disposition, 1},
           {%{early: %{status: :rejected}}, steps}} ->
            length(steps)
        after
          1_000 -> 0
        end

      assert(resent == 1, "rejected 0-RTT request re-sent by the session: #{resent}")
      response
    after
      :erlang.trace_pattern({QuicHttp3.Session, :early_disposition, 1}, false, [:local])
      :erlang.trace(:all, false, [:call])
    end
  end

  # Tickets and SETTINGS are recorded asynchronously after a response completes.
  defp settle, do: Process.sleep(200)

  defp fetch(base, path, options) do
    case HTTP.fetch(base <> path, options) |> HTTP.Promise.await() do
      %HTTP.Response{http_version: :http3} = response -> response
      other -> raise "strict HTTP/3 fetch failed for #{path}: #{inspect(other, limit: 8)}"
    end
  end

  defp expect(response, status, http3, early_header, label) do
    assert(response.status == status, "#{label}: status #{response.status}")

    assert(
      Map.take(response.http3 || %{}, Map.keys(http3)) == http3,
      "#{label}: http3 #{inspect(response.http3)}"
    )

    assert(
      HTTP.Response.get_header(response, "x-early") == early_header,
      "#{label}: peer x-early #{inspect(HTTP.Response.get_header(response, "x-early"))}"
    )

    IO.puts("#{label}: #{response.status} #{inspect(response.http3)}")
  end

  defp assert(true, _message), do: :ok
  defp assert(_, message), do: raise("HTTP/3 resumption gate failed: " <> message)
end

HTTP3ResumptionGate.run()
