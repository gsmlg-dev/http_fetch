defmodule HTTP3QpackDynamicGate do
  @moduledoc false
  # Public Fetch against an independent aioquic 1.2.0 peer whose pylsqpack
  # encoder uses the dynamic table advertised by the default client profile.

  @large binary_part(:binary.copy("abcdefghijklmnopqrstuvwxyz0123456789-_", 100), 0, 3_000)

  def run do
    port = System.fetch_env!("HTTP3_PEER_PORT")
    base = "https://127.0.0.1:#{port}"

    options = [
      http_version: :http3,
      timeout: 30_000,
      ssl: [
        cacertfile: "apps/elixir_quic/test/fixtures/tls/root.pem",
        reference_identity: {:dns_id, "example.test"}
      ]
    ]

    for id <- 1..40, do: verify(fetch(base, "/qpack?id=#{id}", options), id)

    1_001..1_064
    |> Enum.map(fn id -> Task.async(fn -> {id, fetch(base, "/qpack?id=#{id}", options)} end) end)
    |> Task.await_many(60_000)
    |> Enum.each(fn {id, response} -> verify(response, id) end)

    for id <- 2_001..2_020, do: verify(fetch(base, "/qpack?id=#{id}", options), id)

    stats = base |> fetch("/qpack-stats", options) |> HTTP.Response.text() |> JSON.decode!()

    assert(
      stats["encoder_bytes_sent"] > 0,
      "peer encoder used the dynamic table: #{inspect(stats)}"
    )

    assert(
      stats["decoder_bytes_received"] > 0,
      "client decoder stream acknowledged sections: #{inspect(stats)}"
    )

    IO.puts("HTTP/3 QPACK peer stats: #{inspect(stats)}")

    IO.puts(
      "HTTP/3 dynamic QPACK aioquic 1.2.0 repeated/large/custom headers, 124 requests: PASS"
    )
  end

  defp fetch(base, path, options) do
    case HTTP.fetch(base <> path, options) |> HTTP.Promise.await() do
      %HTTP.Response{http_version: :http3, status: 200} = response -> response
      other -> raise "strict HTTP/3 QPACK fetch failed for #{path}: #{inspect(other, limit: 8)}"
    end
  end

  defp verify(response, id) do
    id = Integer.to_string(id)

    expected =
      [
        {"x-peer", "aioquic-1.2.0"},
        {"x-qpack-static", String.duplicate("s", 64)},
        {"x-qpack-large", @large},
        {"x-qpack-request", id},
        {"cache-control", "private, max-age=" <> id}
      ] ++ for(index <- 0..19, do: {"x-qpack-repeat-#{index}", "repeat-value-#{index}"})

    for {name, value} <- expected do
      actual = HTTP.Response.get_header(response, name)
      assert(actual == value, "header #{name} for request #{id}: #{inspect(actual, limit: 4)}")
    end

    assert(HTTP.Response.text(response) == "qpack-" <> id, "body for request #{id}")
  end

  defp assert(true, _message), do: :ok
  defp assert(_, message), do: raise("HTTP/3 dynamic QPACK gate failed: " <> message)
end

HTTP3QpackDynamicGate.run()
