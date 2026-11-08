defmodule HTTP3AltSvcGate do
  @moduledoc false
  # Public `HTTP.fetch(url, http_version: :auto, alt_svc: true)` against an
  # independent Python `ssl` HTTP/1.1 origin advertising Alt-Svc and an
  # independent aioquic 1.2.0 HTTP/3 alternative. Launched by alt_svc_gate.py.

  @tcp [:http1, :http2]
  @large :binary.copy(:binary.list_to_bin(Enum.to_list(0..255)), 32_768)

  def run do
    options = [
      http_version: :auto,
      alt_svc: true,
      timeout: 30_000,
      ssl: [cacertfile: env("ALT_SVC_CA_FILE")]
    ]

    positive(env("ALT_SVC_POSITIVE_ORIGIN"), env("ALT_SVC_H3_PORT"), options)
    negative("blackhole", env("ALT_SVC_BLACKHOLE_ORIGIN"), env("ALT_SVC_BLACKHOLE_UDP"), options)
    negative("closed", env("ALT_SVC_CLOSED_ORIGIN"), env("ALT_SVC_CLOSED_UDP"), options)
    IO.puts("Alt-Svc independent acceptance result: PASS")
  end

  defp positive(origin_port, h3_port, options) do
    base = "https://127.0.0.1:#{origin_port}"

    first = fetch(base, "/", options)
    assert(first.http_version in @tcp, "first request over TCP: #{first.http_version}")
    assert(peer(first) == "python-ssl-h1", "first request served by TCP origin")
    assert(HTTP.Response.text(first) == "python-ssl-h1", "TCP body integrity")

    assert(
      HTTP.Response.get_header(first, "alt-svc") == ~s(h3=":#{h3_port}"; ma=60),
      "origin advertised h3 alternative"
    )

    second = fetch(base, "/", options)
    assert(second.http_version == :http3, "second request over HTTP/3: #{second.http_version}")
    assert(peer(second) == "aioquic-1.2.0", "second request served by aioquic alternative")
    assert(HTTP.Response.text(second) == "aioquic HTTP/3", "HTTP/3 body integrity")

    authority = h3(fetch(base, "/authority", options))
    assert(HTTP.Response.text(authority) == "127.0.0.1:#{origin_port}", "origin :authority kept")

    body = :binary.copy(<<0, 255, 127, 128, 1, 2, 3>>, 8_817)
    digest = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)
    upload = h3(fetch(base, "/digest", Keyword.merge(options, method: :post, body: body)))
    assert(HTTP.Response.text(upload) == digest, "HTTP/3 binary POST digest")

    large(h3(fetch(base, "/large", options)))

    1..16
    |> Enum.map(fn n -> Task.async(fn -> {n, fetch(base, "/echo", post(options, n))} end) end)
    |> Task.await_many(60_000)
    |> Enum.each(fn {n, response} ->
      assert(HTTP.Response.text(h3(response)) == "concurrent-#{n}", "concurrent #{n} integrity")
    end)

    IO.puts(
      "Alt-Svc positive: TCP #{first.http_version} learned h3=:#{h3_port}; " <>
        "21 subsequent requests HTTP/3 via aioquic-1.2.0 with origin authority: PASS"
    )
  end

  defp negative(name, origin_port, udp_port, options) do
    base = "https://127.0.0.1:#{origin_port}"
    connect_timeout = 2_000
    deadline = 10_000
    options = Keyword.merge(options, connect_timeout: connect_timeout, timeout: deadline)

    learn = tcp(fetch(base, "/", options), "#{name} learn")

    assert(
      HTTP.Response.get_header(learn, "alt-svc") == ~s(h3=":#{udp_port}"; ma=60),
      "#{name} origin advertised unreachable h3"
    )

    {fallback_ms, fallback} = timed(fn -> fetch(base, "/", options) end)
    tcp(fallback, "#{name} fallback")
    assert(fallback_ms < deadline, "#{name} fallback within deadline: #{fallback_ms}ms")

    {broken_ms, broken} = timed(fn -> fetch(base, "/large", options) end)
    large(tcp(broken, "#{name} broken-marked"))
    assert(broken_ms < connect_timeout, "#{name} broken origin skips H3: #{broken_ms}ms")

    IO.puts(
      "Alt-Svc negative #{name} udp=#{udp_port}: fallback #{fallback.http_version} " <>
        "in #{fallback_ms}ms (deadline #{deadline}ms, connect_timeout #{connect_timeout}ms); " <>
        "next request #{broken.http_version} in #{broken_ms}ms: PASS"
    )
  end

  defp fetch(base, path, options) do
    case HTTP.fetch(base <> path, options) |> HTTP.Promise.await(60_000) do
      %HTTP.Response{status: 200} = response -> response
      other -> raise "Alt-Svc gate fetch #{path} failed: #{inspect(other, limit: 8)}"
    end
  end

  defp post(options, n), do: Keyword.merge(options, method: :post, body: "concurrent-#{n}")

  defp h3(response) do
    assert(response.http_version == :http3, "expected HTTP/3, got #{response.http_version}")
    assert(peer(response) == "aioquic-1.2.0", "HTTP/3 peer identity")
    response
  end

  defp tcp(response, label) do
    assert(response.http_version in @tcp, "#{label} over TCP: #{response.http_version}")
    assert(peer(response) == "python-ssl-h1", "#{label} served by TCP origin")
    response
  end

  defp large(response) do
    destination = Path.join(System.tmp_dir!(), "alt-svc-#{System.unique_integer([:positive])}")

    try do
      assert(HTTP.Response.write_to(response, destination) == :ok, "large write")
      assert(File.read!(destination) == @large, "8MiB large body integrity")
    after
      File.rm(destination)
    end
  end

  defp timed(fun) do
    {micros, result} = :timer.tc(fun)
    {div(micros, 1_000), result}
  end

  defp peer(response), do: HTTP.Response.get_header(response, "x-peer")
  defp env(name), do: System.fetch_env!(name)

  defp assert(true, _message), do: :ok
  defp assert(_, message), do: raise("Alt-Svc gate failed: " <> message)
end

HTTP3AltSvcGate.run()
