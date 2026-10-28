defmodule HTTP.TLSSetupEvidenceTest do
  use ExUnit.Case, async: true

  alias ExSSL.TestSupport.ManagedLifecycleProbe, as: Probe

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @tls12_peer Path.expand("../support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

  @tag :integration
  test "certificate rejection proves no HTTP while cleanup joins the original provider resources" do
    {listener, second, port} = paired_listeners()
    parent = self()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        result = :ssl.handshake(tcp, untrusted_server_options(), 3_000)
        send(parent, {:peer_result, result})
        :gen_tcp.close(tcp)
      end)

    verify = bad_cert_verifier(parent)
    attempt_options = options(verify_fun: {verify, nil})
    {:ok, upload} = HTTP.Stream.from_enumerable(["once"], telemetry: false)
    upload_monitor = Process.monitor(upload)
    deadline = System.monotonic_time(:millisecond) + 4_000

    promise =
      HTTP.fetch(
        "https://pinned.invalid:#{port}/mutation",
        attempt_options ++ [method: :post, body: upload, duplex: "half"]
      )

    handle = HTTP.Promise.completion(promise)
    assert_receive {:verify_ready, verifier}, 3_000
    assert_receive {:bad_certificate, :unknown_ca}, 3_000
    graph = provider_graph(handle)
    assert verifier == graph.connection
    assert true = Probe.suspend(graph, :writer)

    on_exit(fn ->
      Probe.resume(graph, :writer)
      Probe.resume(graph, :observer)
      Probe.release_monitors(graph)
    end)

    send(verifier, :reject)
    await_setup_proof(graph.handle, deadline)
    assert Probe.alive?(graph, :writer)
    assert {:pending, _} = SSL.Lifecycle.await(graph.handle, {:abs_ms, now()})
    assert {:error, :cleanup_pending} = HTTP.RequestCompletion.await(handle, 0)
    assert Task.yield(promise.task, 0) == nil

    # ExSSL eagerly terminates Writer after its bounded fatal alert. Hold the
    # original Observer instead to prove that the returned TLS error still does
    # not authorize cleanup until the provider's final evidence is joined.
    assert true = Probe.suspend(graph, :observer)
    Probe.resume(graph, :writer)

    assert {:error,
            %HTTP.RequestError{
              phase: :tls_setup,
              request_started: false,
              reason: {:tls_alert, {:unknown_ca, _}}
            } = error} =
             HTTP.Promise.await(promise, 3_000)

    assert HTTP.RequestError.pre_send?(error)
    Probe.await_down(graph, [:connection, :writer, :tcp], 3_000)
    assert Probe.alive?(graph, :observer)
    assert {:error, :cleanup_pending} = HTTP.RequestCompletion.await(handle, 0)
    Probe.resume(graph, :observer)
    Probe.await_down(graph, [:observer], 3_000)
    assert :ok = HTTP.RequestCompletion.await(handle, 3_000)
    Probe.release_monitors(graph)
    assert_receive {:peer_result, {:error, {:tls_alert, _}}}, 3_000
    Task.await(peer)
    assert_receive {:DOWN, ^upload_monitor, :process, ^upload, _}, 3_000
    refute Process.alive?(upload)

    # A caller may now try the separately validated, already reserved IPv6 pin
    # with a fresh body. No automatic fallback may have queued a connection.
    assert {:error, :timeout} = :gen_tcp.accept(second, 0)

    fallback =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(second, 2_000)
        {:ok, socket} = :ssl.handshake(tcp, server_options(), 2_000)
        {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
        assert info[:sni_hostname] == ~c"pinned.invalid"
        bytes = receive_request(socket, "")
        assert bytes =~ "Host: pinned.invalid:#{port}\r\n"
        assert bytes =~ "POST /mutation HTTP/1.1\r\n"
        assert length(:binary.matches(bytes, "once")) == 1

        :ok =
          :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

        :ssl.close(socket)
      end)

    {:ok, fresh_upload} = HTTP.Stream.from_enumerable(["once"], telemetry: false)
    refute fresh_upload == upload
    assert System.monotonic_time(:millisecond) < deadline
    remaining = deadline - System.monotonic_time(:millisecond)

    fallback_opts =
      Keyword.merge(attempt_options,
        connect_address: {0, 0, 0, 0, 0, 0, 0, 1},
        timeout: remaining,
        method: :post,
        body: fresh_upload,
        duplex: "half"
      )

    assert fallback_opts[:ssl] == attempt_options[:ssl]
    fallback_promise = HTTP.fetch("https://pinned.invalid:#{port}/mutation", fallback_opts)
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(fallback_promise, remaining)
    assert_receive {:verified_peer, _}, 3_000

    assert :ok =
             HTTP.RequestCompletion.await(HTTP.Promise.completion(fallback_promise), remaining)

    Task.await(fallback)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    assert {:error, :timeout} = :gen_tcp.accept(second, 0)
  end

  @tag :integration
  test "fatal alert before ServerHello has unknown request phase and confirmed provider cleanup" do
    {listener, port} = listener()
    parent = self()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        assert {:ok, _hello} = :gen_tcp.recv(tcp, 0, 2_000)
        send(parent, {:before_alert, self()})

        receive do
          :fatal_alert -> :ok
        after
          2_000 -> flunk("fatal alert gate expired")
        end

        :ok = :gen_tcp.send(tcp, <<21, 3, 3, 0, 2, 2, 40>>)
        :gen_tcp.close(tcp)
      end)

    promise = HTTP.fetch("https://pinned.invalid:#{port}/", options())
    handle = HTTP.Promise.completion(promise)
    assert_receive {:before_alert, peer_pid}, 2_000
    graph = provider_graph(handle)
    on_exit(fn -> Probe.release_monitors(graph) end)
    send(peer_pid, :fatal_alert)

    assert {:error, %HTTP.RequestError{phase: :unknown} = error} =
             HTTP.Promise.await(promise, 3_000)

    refute HTTP.RequestError.pre_send?(error)

    Probe.await_down(graph, [:connection, :writer, :tcp, :observer], 3_000)
    assert :ok = HTTP.RequestCompletion.await(handle, 3_000)
    Probe.release_monitors(graph)

    Task.await(peer)
  end

  for cancellation <- [:abort, :deadline] do
    @tag :integration
    test "queued #{cancellation} wins over a proof-bearing TLS result" do
      {listener, port} = listener()

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
          assert {:error, _} = :ssl.handshake(tcp, server_options(), 3_000)
          :gen_tcp.close(tcp)
        end)

      verify = rejecting_verifier(self())
      promise = HTTP.fetch("https://pinned.invalid:#{port}/", options(verify_fun: {verify, nil}))
      handle = HTTP.Promise.completion(promise)
      assert_receive {:verify_ready, receiver}, 3_000
      resources = :sys.get_state(handle.tracker).resources

      owner =
        Enum.find_value(resources, fn
          {_, {pid, :owner}} -> pid
          _ -> nil
        end)

      true = :erlang.suspend_process(owner)
      on_exit(fn -> if Process.alive?(owner), do: :erlang.resume_process(owner) end)
      send(receiver, :reject)
      await_proof_message(owner, System.monotonic_time(:millisecond) + 2_000)
      send(owner, unquote(cancellation))
      true = :erlang.resume_process(owner)

      assert {:error, %HTTP.RequestError{phase: :unknown} = error} =
               HTTP.Promise.await(promise, 3_000)

      refute HTTP.RequestError.pre_send?(error)
      assert :ok = HTTP.RequestCompletion.await(handle, 3_000)
      Task.await(peer)
    end
  end

  for {name, request_opts} <- [
        {:pooled, [http1_reuse: true]},
        {:http2, [http_version: :http2]},
        {:raw, [error_mode: :raw]}
      ] do
    @tag :integration
    test "#{name} does not expose confirmed TLS setup evidence" do
      {listener, port} = listener()

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
          assert {:error, {:tls_alert, _}} = :ssl.handshake(tcp, server_options(), 3_000)
          :gen_tcp.close(tcp)
        end)

      # Empty trust is an option error in ExSSL. A valid unrelated CA reaches
      # the certificate rejection that these excluded-route cases exercise.
      ssl_opts = [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
      request_opts = Keyword.merge(options(), unquote(request_opts))
      request_opts = Keyword.put(request_opts, :ssl, ssl_opts)
      promise = HTTP.fetch("https://pinned.invalid:#{port}/", request_opts)
      assert {:error, error} = HTTP.Promise.await(promise, 3_000)
      refute HTTP.RequestError.pre_send?(error)

      if unquote(name) == :raw do
        refute match?(%HTTP.RequestError{}, error)
        assert {:tls_alert, {:unknown_ca, _}} = error
      else
        assert %HTTP.RequestError{
                 phase: :unknown,
                 request_started: :unknown,
                 reason: {:tls_alert, {:unknown_ca, _}}
               } = error
      end

      Task.await(peer, 4_000)
      assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 3_000)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    end
  end

  for {name, option} <- [
        {:custom_handshake, {:handshake, :full}},
        {:early_data, {:early_data, "must not transmit"}}
      ] do
    @tag :integration
    test "unsupported #{name} grants no setup evidence and makes no connection" do
      {listener, port} = listener()
      key = unquote(elem(option, 0))
      promise = HTTP.fetch("https://pinned.invalid:#{port}/", options([unquote(option)]))

      assert {:error,
              %HTTP.RequestError{
                reason: {:options, {^key, :unsupported_or_invalid}},
                phase: :unknown,
                request_started: :unknown
              } = error} = HTTP.Promise.await(promise, 3_000)

      refute HTTP.RequestError.pre_send?(error)
      assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 3_000)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    end
  end

  @tag :integration
  test "a continuation alert accepted after the absolute connect deadline stays unknown" do
    {listener, port} = listener()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        result = :ssl.handshake(tcp, server_options(), 3_000)
        :gen_tcp.close(tcp)
        result
      end)

    verify = rejecting_verifier(self())

    promise =
      HTTP.fetch(
        "https://pinned.invalid:#{port}/",
        options(verify_fun: {verify, nil}) ++ [connect_timeout: 1_000]
      )

    handle = HTTP.Promise.completion(promise)
    assert_receive {:verify_ready, receiver}, 3_000
    # The connect deadline already exists when certificate verification begins.
    expiry = System.monotonic_time(:millisecond) + 1_000

    dial =
      Enum.find_value(:sys.get_state(handle.tracker).resources, fn
        {_, {pid, :dial}} -> pid
        _ -> nil
      end)

    true = :erlang.suspend_process(dial)
    on_exit(fn -> if Process.alive?(dial), do: :erlang.resume_process(dial) end)
    send(receiver, :reject)
    assert {:error, _} = Task.await(peer, 3_000)
    # Delay acceptance, not native traffic or process termination, past the limit.
    timer = make_ref()
    Process.send_after(self(), timer, max(expiry - System.monotonic_time(:millisecond) + 20, 0))
    assert_receive ^timer, 2_000
    true = :erlang.resume_process(dial)

    assert {:error, %HTTP.RequestError{phase: :unknown} = error} =
             HTTP.Promise.await(promise, 3_000)

    refute HTTP.RequestError.pre_send?(error)
    assert :ok = HTTP.RequestCompletion.await(handle, 3_000)
  end

  test "TLS evidence tokens belong to exactly one request" do
    token = make_ref()
    reason = {:tls_alert, {:unknown_ca, ~c"test"}}

    assert %HTTP.RequestError{phase: :tls_setup, reason: ^reason} =
             HTTP.RequestError.new({:tls_setup_failure, token, reason}, token)

    forged = HTTP.RequestError.new({:tls_setup_failure, make_ref(), reason}, token)
    refute HTTP.RequestError.pre_send?(forged)
  end

  @tag :integration
  test "TLS peer closure after actual POST bytes remains unknown and is never replayed" do
    {listener, port} = listener()
    parent = self()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        {:ok, socket} = :ssl.handshake(tcp, server_options(), 2_000)
        bytes = receive_request(socket, "")
        send(parent, {:post_sent, bytes})
        :ssl.close(socket)
      end)

    {:ok, upload} = HTTP.Stream.from_enumerable(["once"], telemetry: false)

    promise =
      HTTP.fetch(
        "https://pinned.invalid:#{port}/mutation",
        options() ++ [method: :post, body: upload, duplex: "half"]
      )

    assert_receive {:post_sent, bytes}, 3_000
    assert bytes =~ "POST /mutation HTTP/1.1\r\n"
    assert length(:binary.matches(bytes, "once")) == 1

    assert {:error, %HTTP.RequestError{phase: :unknown} = error} =
             HTTP.Promise.await(promise, 3_000)

    refute HTTP.RequestError.pre_send?(error)
    assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 3_000)
    Task.await(peer)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  defp await_proof_message(owner, deadline) do
    {:messages, messages} = Process.info(owner, :messages)

    if Enum.any?(
         messages,
         &match?({:connect_result, _, {:error, {:tls_setup_failure, _, _}}}, &1)
       ) do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        1 -> await_proof_message(owner, deadline)
      end
    end
  end

  defp bad_cert_verifier(parent) do
    fn
      _, {:bad_cert, reason}, _ ->
        send(parent, {:verify_ready, self()})
        send(parent, {:bad_certificate, reason})

        receive do
          :reject -> {:fail, reason}
        after
          3_000 -> {:fail, :test_gate_timeout}
        end

      _, {:extension, _}, state ->
        {:unknown, state}

      _, :valid, state ->
        {:valid, state}

      _, :valid_peer, state ->
        send(parent, {:verified_peer, self()})
        {:valid, state}
    end
  end

  defp rejecting_verifier(parent) do
    fn
      _, {:bad_cert, reason}, _ ->
        {:fail, reason}

      _, {:extension, _}, state ->
        {:unknown, state}

      _, :valid, state ->
        {:valid, state}

      _, :valid_peer, _ ->
        send(parent, {:verify_ready, self()})

        receive do
          :reject -> {:fail, :rejected_for_test}
        after
          3_000 -> {:fail, :test_gate_timeout}
        end
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    @tag :integration
    test "ordinary successful #{version} preserves verified authority and supports a rebuilt upload" do
      version = unquote(version)
      {peer, port} = success_peer(version)
      {:ok, upload} = HTTP.Stream.from_enumerable(["once"], telemetry: false)
      upload_monitor = Process.monitor(upload)

      promise =
        HTTP.fetch(
          "https://pinned.invalid:#{port}/mutation",
          options(versions: [version], alpn_advertised_protocols: ["http/1.1"]) ++
            [method: :post, body: upload, duplex: "half"]
        )

      assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise, 3_000)
      assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 3_000)
      assert_receive {:DOWN, ^upload_monitor, :process, ^upload, _}, 3_000
      assert_successful_peer(peer, port, version)
    end
  end

  defp provider_graph(completion) do
    [handle] = completion.tracker |> :sys.get_state() |> Map.fetch!(:providers) |> Map.keys()
    Probe.graph_handle(handle)
  end

  defp await_setup_proof(handle, deadline) do
    case SSL.Lifecycle.setup_failure(handle) do
      {:ok, %{phase: :tls_setup}} ->
        :ok

      :unknown ->
        assert now() < deadline

        receive do
        after
          1 -> await_setup_proof(handle, deadline)
        end
    end
  end

  # The OTP TLS1.2 reference lacks EMS. Keep its TLS1.3 control and use the
  # existing independent peer for TLS1.2 with the same chunked upload/authority.
  defp success_peer(:"tlsv1.2") do
    peer =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          @tls12_peer,
          "--cert",
          Path.join(@fixtures, "pinned.pem"),
          "--key",
          Path.join(@fixtures, "pinned.key"),
          "--tls",
          "TLSv1.2",
          "--protocol",
          "http/1.1",
          "--route",
          "forward"
        ]
      ])

    on_exit(fn -> if Port.info(peer), do: Port.close(peer) end)
    assert %{"event" => "ready", "port" => port} = peer_event(peer, 2_000)
    {{:openssl, peer}, port}
  end

  defp success_peer(:"tlsv1.3" = version) do
    {listener, port} = listener()
    parent = self()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        {:ok, socket} = :ssl.handshake(tcp, [versions: [version]] ++ server_options(), 2_000)
        {:ok, info} = :ssl.connection_information(socket, [:sni_hostname, :protocol])
        send(parent, {:identity, info})
        send(parent, {:request, receive_request(socket, "")})

        :ok =
          :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

        :ssl.close(socket)
      end)

    {{:otp, peer}, port}
  end

  defp assert_successful_peer({:otp, peer}, port, version) do
    assert_receive {:identity, info}
    assert info[:sni_hostname] == ~c"pinned.invalid"
    assert info[:protocol] == version
    assert_receive {:request, bytes}
    assert bytes =~ "Host: pinned.invalid:#{port}\r\n"
    assert bytes =~ "POST /mutation HTTP/1.1\r\n"
    assert length(:binary.matches(bytes, "once")) == 1
    Task.await(peer)
  end

  defp assert_successful_peer({:openssl, peer}, port, :"tlsv1.2") do
    state = peer_closed(peer, now() + 2_000)
    assert state["accepted_connections"] == 1
    assert state["closed_connections"] == 1
    assert state["active_connections"] == 0
    assert state["errors"] == []

    assert [%{"tls" => "TLSv1.2", "sni" => "pinned.invalid", "alpn" => "http/1.1"}] =
             state["handshakes"]

    assert [%{"method" => "POST", "target" => "/mutation", "body" => body, "headers" => headers}] =
             state["requests"]

    assert Base.decode64!(body) == "once"
    headers = Map.new(headers, fn {key, value} -> {String.downcase(key), value} end)
    assert headers["host"] == "pinned.invalid:#{port}"
    assert headers["transfer-encoding"] == "chunked"
    refute Map.has_key?(headers, "content-length")
    assert Port.command(peer, JSON.encode!(%{command: "stop"}) <> "\n")
    assert %{"event" => "stop"} = peer_event(peer, 2_000)
    assert_receive {^peer, {:exit_status, 0}}, 3_000
  end

  defp peer_closed(peer, deadline) do
    assert now() < deadline
    assert Port.command(peer, JSON.encode!(%{command: "stats"}) <> "\n")
    state = peer_event(peer, max(deadline - now(), 0))

    if state["closed_connections"] == 1 do
      state
    else
      receive do
      after
        2 -> peer_closed(peer, deadline)
      end
    end
  end

  defp peer_event(peer, timeout) do
    receive do
      {^peer, {:data, {:eol, line}}} -> JSON.decode!(line)
      {^peer, {:exit_status, code}} -> flunk("TLS1.2 setup peer exited with #{code}")
    after
      timeout -> flunk("TLS1.2 setup peer event timeout")
    end
  end

  defp now, do: System.monotonic_time(:millisecond)

  defp receive_request(socket, bytes) do
    if String.ends_with?(bytes, "0\r\n\r\n") do
      bytes
    else
      {:ok, next} = :ssl.recv(socket, 0, 2_000)
      receive_request(socket, bytes <> next)
    end
  end

  defp options(extra \\ []) do
    [
      connect_address: {127, 0, 0, 1},
      redirect: :manual,
      error_mode: :structured,
      tls_backend: :ex_ssl,
      telemetry: false,
      timeout: 4_000,
      ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")] ++ extra
    ]
  end

  defp paired_listeners(attempts \\ 10) do
    {:ok, first} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(first)

    case :gen_tcp.listen(port, [
           :inet6,
           :binary,
           active: false,
           ipv6_v6only: true,
           ip: {0, 0, 0, 0, 0, 0, 0, 1}
         ]) do
      {:ok, second} ->
        on_exit(fn ->
          :gen_tcp.close(first)
          :gen_tcp.close(second)
        end)

        {first, second, port}

      {:error, :eaddrinuse} when attempts > 1 ->
        :gen_tcp.close(first)
        paired_listeners(attempts - 1)

      {:error, reason} ->
        :gen_tcp.close(first)
        flunk("could not reserve TLS pin pair: #{inspect(reason)}")
    end
  end

  defp listener do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    {listener, port}
  end

  defp untrusted_server_options do
    Keyword.merge(server_options(),
      certfile: Path.join(@fixtures, "localhost.pem"),
      keyfile: Path.join(@fixtures, "localhost.key")
    )
  end

  defp server_options do
    [
      certfile: Path.join(@fixtures, "pinned.pem"),
      keyfile: Path.join(@fixtures, "pinned.key"),
      active: false,
      mode: :binary
    ]
  end
end
