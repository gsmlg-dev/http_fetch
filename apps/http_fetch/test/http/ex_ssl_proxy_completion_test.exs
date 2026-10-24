defmodule HTTP.ExSSLProxyCompletionTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :p3_proxy_ex_ssl
  alias HTTP.{Promise, RequestCompletion, Response}
  @fixtures Path.expand("../support/fixtures", __DIR__)
  @peer Path.expand("../support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}],
      {protocol, alpn, route, scheme} <- [
        {:http1, "http/1.1", "connect", :http},
        {:http2, "h2", "connect", :http},
        {:http1, "http/1.1", "forward", :https}
      ],
      behavior <- [:success, :wrong_ca, :wrong_identity, :timeout, :cancellation, :shutdown] do
    if version == :"tlsv1.3" and protocol == :http1 and route == "connect" and
         behavior == :success,
       do: @tag(:p3_proxy_ex_ssl_red)

    test "#{wire} #{route} #{protocol} #{behavior} authenticates the actual TLS leg and completion" do
      exercise_case(
        unquote(version),
        unquote(wire),
        unquote(protocol),
        unquote(alpn),
        unquote(route),
        unquote(scheme),
        unquote(behavior)
      )
    end
  end

  defp exercise_case(version, wire, protocol, alpn, route, scheme, behavior) do
    {peer, port} = peer(wire, alpn, route)

    try do
      {url, opts} = scenario_options(port, version, protocol, route, scheme, behavior)

      promise = HTTP.fetch(url, opts)
      completion = Promise.completion(promise)

      case behavior do
        failure when failure in [:wrong_ca, :wrong_identity] ->
          assert {:error, %HTTP.RequestError{phase: :unknown, request_started: :unknown} = error} =
                   Promise.await(promise, 5_000)

          expected_alert =
            if version == :"tlsv1.2",
              do: :bad_certificate,
              else: %{wrong_ca: :unknown_ca, wrong_identity: :certificate_unknown}[failure]

          assert {:tls_alert, {^expected_alert, _}} = error.reason
          refute HTTP.RequestError.pre_send?(error)
          assert :ok = RequestCompletion.await(completion, 2_000)
          state = stats(peer, &(&1["closed_connections"] == 1))
          assert state["requests"] == []
          assert state["accepted_connections"] == 1
          assert length(state["errors"]) == 1
          assert hd(state["errors"])["kind"] == "tls"

        :success ->
          assert %Response{status: 200, body: <<0, 255, 13, 10>>} = Promise.await(promise, 5_000)
          assert :ok = RequestCompletion.await(completion, 2_000)
          state = stats(peer, &(length(&1["requests"]) == 1))
          assert_wire(state, wire, alpn, route)

          assert [%{"body" => "AP8NCg==", "headers" => headers, "target" => target}] =
                   state["requests"]

          assert target ==
                   if(route == "forward",
                     do: "http://origin.invalid:8080/entity?",
                     else: "/entity?"
                   )

          assert credential(headers, "authorization") == "Bearer origin"

          assert credential(headers, "proxy-authorization") ==
                   if(route == "forward", do: "Basic proxy", else: nil)

          later = HTTP.fetch(url(route, "/later"), Keyword.drop(opts, [:method, :body]))
          assert :ok = RequestCompletion.abort_and_await(completion, 0)
          assert %Response{body: "ok"} = Promise.await(later, 5_000)
          assert :ok = RequestCompletion.await(Promise.completion(later), 2_000)
          state = stats(peer, &(length(&1["requests"]) == 2))
          assert state["accepted_connections"] == 1
          assert Enum.all?(state["requests"], &(&1["connection"] == 1))

        terminal ->
          state = stats(peer, &(length(&1["requests"]) == 1))
          assert_wire(state, wire, alpn, route)
          handles = completion.tracker |> :sys.get_state() |> Map.fetch!(:providers) |> Map.keys()
          assert length(handles) == 1

          case terminal do
            :cancellation ->
              assert :ok = RequestCompletion.abort_and_await(completion, 2_000)
              assert {:error, %HTTP.RequestError{phase: :unknown}} = Promise.await(promise, 2_000)

            :timeout ->
              assert {:error, %HTTP.RequestError{phase: :unknown}} = Promise.await(promise, 2_000)
              assert :ok = RequestCompletion.await(completion, 2_000)

            :shutdown ->
              monitor = Process.monitor(promise.task.pid)
              Process.exit(promise.task.pid, :kill)
              assert_receive {:DOWN, ^monitor, :process, _, :killed}, 1_000
              assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(completion, 2_000)
          end

          for handle <- handles,
              do:
                assert(
                  {:ok, %{cleanup: :confirmed}} =
                    SSL.Lifecycle.await(
                      handle,
                      {:abs_ms, System.monotonic_time(:millisecond) + 2_000}
                    )
                )

          state = stats(peer, &(&1["closed_connections"] == 1))
          assert state["accepted_connections"] == 1
          assert length(state["requests"]) == 1
      end
    after
      stop_peer(peer)
    end
  end

  defp scenario_options(port, version, protocol, route, scheme, behavior) do
    opts = options(port, version, protocol, scheme)

    opts =
      Keyword.merge(opts,
        error_mode: :structured,
        headers: [{"Authorization", "Bearer origin"}]
      )

    reuse_key = if protocol == :http2, do: :http2_reuse, else: :http1_reuse
    opts = Keyword.put(opts, reuse_key, behavior == :success)

    {url, opts} =
      case behavior do
        :wrong_ca ->
          {url(route, "/never"),
           put_ssl(opts, :cacertfile, Path.join(@fixtures, "pinned-ca.pem"))}

        :wrong_identity ->
          {url(route, "/never"), put_ssl(opts, :server_name_indication, ~c"wrong.invalid")}

        terminal when terminal in [:timeout, :cancellation, :shutdown] ->
          {url(route, "/hold"),
           Keyword.put(opts, :timeout, if(terminal == :timeout, do: 500, else: 5_000))}

        :success ->
          {url(route, "/entity?"), opts}
      end

    opts =
      if behavior == :success,
        do: Keyword.merge(opts, method: :post, body: <<0, 255, 13, 10>>),
        else: opts

    {url, opts}
  end

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}] do
    test "#{wire} H2 CONNECT cancellation resets one stream and retains sibling and later reuse" do
      {peer, port} = peer(unquote(wire), "h2", "connect")

      try do
        opts = options(port, unquote(version), :http2, :http)
        first = HTTP.fetch(url("connect", "/hold"), opts)
        state = stats(peer, &(length(&1["requests"]) == 1))
        assert_wire(state, unquote(wire), "h2", "connect")

        sibling =
          HTTP.fetch(url("connect", "/sibling"), Keyword.put(opts, :stream_response, true))

        assert %Response{} = response = Promise.await(sibling, 5_000)
        assert is_pid(response.stream)
        assert :ok = RequestCompletion.abort_and_await(Promise.completion(first), 2_000)
        assert {:error, :aborted} = Promise.await(first, 2_000)
        assert Response.read_all(response) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(sibling), 2_000)
        later = HTTP.fetch(url("connect", "/later"), opts)
        assert %Response{body: "ok"} = Promise.await(later, 5_000)
        assert :ok = RequestCompletion.await(Promise.completion(later), 2_000)
        state = stats(peer, &(length(&1["requests"]) == 3 and length(&1["resets"]) == 1))
        assert state["accepted_connections"] == 1
        assert Enum.all?(state["requests"], &(&1["connection"] == 1))
        assert [%{"stream" => 1, "error" => 8}] = state["resets"]
      after
        stop_peer(peer)
      end
    end
  end

  test "raw refused proxy dial retains one attempt and never falls back to reachable origin" do
    {:ok, origin} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, origin_port} = :inet.port(origin)
    {:ok, unused} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(unused)
    :gen_tcp.close(unused)

    try do
      promise =
        HTTP.fetch(
          "https://127.0.0.1:#{origin_port}/never",
          options(port, :"tlsv1.3", :http1, :http)
        )

      assert {:error, :econnrefused} = Promise.await(promise, 2_000)
      assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
      assert {:error, :timeout} = :gen_tcp.accept(origin, 0)
    after
      :gen_tcp.close(origin)
    end
  end

  test "all four unsafe CONNECT response shapes stop before TLS and origin HTTP" do
    for {mode, reason} <- [
          {"rejected", {:proxy_connect_status, 407}},
          {"oversized", :proxy_response_too_large},
          {"buffered", :proxy_buffered_plaintext},
          {"malformed", :invalid_proxy_response}
        ] do
      {peer, port} = peer("TLSv1.3", "http/1.1", "connect", mode)

      try do
        promise = HTTP.fetch(url("connect", "/never"), options(port, :"tlsv1.3", :http1, :http))
        assert {:error, ^reason} = Promise.await(promise, 3_000)
        assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
        state = stats(peer, &(&1["closed_connections"] == 1))
        assert state["accepted_connections"] == 1
        assert state["handshakes"] == []
        assert state["requests"] == []
      after
        stop_peer(peer)
      end
    end
  end

  for terminal <- [:abort, :creator_death] do
    test "raw CONNECT #{terminal} before upgrade cannot allocate a later TLS connection" do
      exercise_raw_terminal(unquote(terminal))
    end
  end

  defp exercise_raw_terminal(terminal) do
    {peer, port} = peer("TLSv1.3", "http/1.1", "connect", "pre-upgrade")

    try do
      promise = HTTP.fetch(url("connect", "/never"), options(port, :"tlsv1.3", :http1, :http))
      stats(peer, &(length(&1["connects"]) == 1))

      if terminal == :abort do
        assert :ok = RequestCompletion.abort_and_await(Promise.completion(promise), 2_000)
        assert {:error, :aborted} = Promise.await(promise, 2_000)
      else
        monitor = Process.monitor(promise.task.pid)
        Process.exit(promise.task.pid, :kill)
        assert_receive {:DOWN, ^monitor, :process, _, :killed}, 1_000

        assert {:error, :cleanup_unconfirmed} =
                 RequestCompletion.await(Promise.completion(promise), 2_000)
      end

      state = stats(peer, &(&1["closed_connections"] == 1))
      assert state["accepted_connections"] == 1
      assert state["handshakes"] == []
      assert state["requests"] == []
    after
      stop_peer(peer)
    end
  end

  defp url("connect", path), do: "https://localhost:8443" <> path
  defp url("forward", path), do: "http://origin.invalid:8080" <> path
  defp put_ssl(opts, key, value), do: Keyword.update!(opts, :ssl, &Keyword.put(&1, key, value))

  defp credential(headers, name),
    do:
      Enum.find_value(headers, fn {key, value} -> if String.downcase(key) == name, do: value end)

  defp assert_wire(state, version, protocol, route) do
    assert [%{"tls" => ^version, "alpn" => ^protocol, "sni" => "localhost"}] = state["handshakes"]
    assert state["errors"] == []
    assert state["accepted_connections"] == 1

    if route == "connect" do
      assert [%{"head" => connect}] = state["connects"]

      assert connect ==
               "CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\nProxy-Authorization: Basic proxy\r\n\r\n"

      refute connect =~ "Bearer origin"
    else
      assert state["connects"] == []
    end
  end

  defp options(port, version, protocol, scheme) do
    [
      tls_backend: :ex_ssl,
      redirect: :manual,
      http_version: protocol,
      proxy: {scheme, "localhost", port, [headers: [{"Proxy-Authorization", "Basic proxy"}]]},
      ssl: [
        cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
        versions: [version],
        alpn_advertised_protocols: [if(protocol == :http2, do: "h2", else: "http/1.1")]
      ],
      telemetry: false,
      decode_body: false,
      timeout: 5_000
    ]
  end

  defp peer(version, protocol, route, mode \\ "normal") do
    port =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          @peer,
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key"),
          "--tls",
          version,
          "--protocol",
          protocol,
          "--route",
          route,
          "--mode",
          mode
        ]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    assert %{"event" => "ready", "port" => number} = event(port)
    {port, number}
  end

  defp event(peer) do
    receive do
      {^peer, {:data, {:eol, line}}} ->
        if System.get_env("P3_PROXY_PEER_EVIDENCE"), do: IO.puts("P3_PROXY_PEER " <> line)
        JSON.decode!(line)

      {^peer, {:exit_status, code}} ->
        flunk("independent proxy peer exit #{code}")
    after
      5_000 -> flunk("independent proxy peer timeout")
    end
  end

  defp stats(peer, predicate),
    do: stats(peer, predicate, System.monotonic_time(:millisecond) + 2_000)

  defp stats(peer, predicate, deadline) do
    assert Port.command(peer, JSON.encode!(%{command: "stats"}) <> "\n")
    result = event(peer)

    if predicate.(result) do
      result
    else
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        2 -> stats(peer, predicate, deadline)
      end
    end
  end

  defp stop_peer(peer) do
    assert Port.command(peer, JSON.encode!(%{command: "stop"}) <> "\n")
    assert event(peer)["event"] == "stop"
    assert_receive {^peer, {:exit_status, 0}}, 5_000
  end
end

defmodule HTTP.ExSSLProxyCompletionEligibilityTest do
  use ExUnit.Case, async: true
  alias HTTP.{FetchOptions, Request, RequestCompletion}
  @tag :p3_proxy_ex_ssl_unit_red
  test "supported ExSSL CONNECT completion reserves a request tracker" do
    options =
      FetchOptions.new(
        tls_backend: :ex_ssl,
        redirect: :manual,
        proxy: {:http, "localhost", 8080, []}
      )

    request = %Request{
      url: URI.parse("https://localhost/"),
      transport_options: [proxy: options.proxy]
    }

    completion = RequestCompletion.new(options, request)
    assert is_pid(completion.tracker)

    task =
      Task.async(fn ->
        HTTP.RequestLifecycle.enter(completion.tracker, :owner)
        HTTP.RequestLifecycle.complete(completion.tracker)
      end)

    Task.await(task)
    assert :ok = RequestCompletion.await(completion, 1_000)
  end

  test "a failed proxy request launch retains uncertain cleanup" do
    options =
      FetchOptions.new(
        tls_backend: :ex_ssl,
        redirect: :manual,
        proxy: {:http, "localhost", 8080, []}
      )

    request = %Request{
      url: URI.parse("https://localhost/"),
      transport_options: [proxy: options.proxy]
    }

    completion = RequestCompletion.new(options, request)
    assert is_pid(completion.tracker)
    send(completion.tracker, :launch_failed)
    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(completion, 1_000)
  end
end
