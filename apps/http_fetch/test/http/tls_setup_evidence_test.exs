defmodule HTTP.TLSSetupEvidenceTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "certificate rejection after ServerHello proves no HTTP and cleanup observes TLS processes" do
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
    assert_receive {:verify_ready, receiver}, 3_000
    assert_receive {:bad_certificate, :unknown_ca}, 3_000
    tls = for {_, {pid, :tls}} <- :sys.get_state(handle.tracker).resources, do: pid
    assert receiver in tls
    assert length(tls) == 2
    sender = Enum.find(tls, &(&1 != receiver))
    monitors = Enum.map(tls, &{&1, Process.monitor(&1)})
    true = :erlang.suspend_process(sender)
    on_exit(fn -> if Process.alive?(sender), do: :erlang.resume_process(sender) end)
    send(receiver, :reject)

    assert {:error, %HTTP.RequestError{phase: :tls_setup, request_started: false} = error} =
             HTTP.Promise.await(promise, 3_000)

    assert HTTP.RequestError.pre_send?(error)
    assert Process.alive?(sender)
    assert {:error, :cleanup_pending} = HTTP.RequestCompletion.await(handle, 0)
    true = :erlang.resume_process(sender)

    for {pid, monitor} <- monitors,
        do: assert_receive({:DOWN, ^monitor, :process, ^pid, _}, 3_000)

    assert :ok = HTTP.RequestCompletion.await(handle, 3_000)
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

  test "fatal alert before ServerHello remains unknown and cleanup unconfirmed" do
    {listener, port} = listener()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        assert {:ok, _hello} = :gen_tcp.recv(tcp, 0, 2_000)
        :ok = :gen_tcp.send(tcp, <<21, 3, 3, 0, 2, 2, 40>>)
        :gen_tcp.close(tcp)
      end)

    promise = HTTP.fetch("https://pinned.invalid:#{port}/", options())

    assert {:error, %HTTP.RequestError{phase: :unknown} = error} =
             HTTP.Promise.await(promise, 3_000)

    refute HTTP.RequestError.pre_send?(error)

    assert {:error, :cleanup_unconfirmed} =
             HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 3_000)

    Task.await(peer)
  end

  for cancellation <- [:abort, :deadline] do
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

  for {name, request_opts, ssl_opts} <- [
        {:pooled, [http1_reuse: true], []},
        {:http2, [http_version: :http2], []},
        {:custom_handshake, [], [handshake: :full]},
        {:raw, [error_mode: :raw], []}
      ] do
    test "#{name} does not expose confirmed TLS setup evidence" do
      {listener, port} = listener()

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
          result = :ssl.handshake(tcp, server_options(), 3_000)
          :gen_tcp.close(tcp)
          result
        end)

      # An untrusted CA makes verification fail without custom test callbacks.
      ssl_opts = [cacerts: []] ++ unquote(ssl_opts)
      request_opts = Keyword.merge(options(), unquote(request_opts))
      request_opts = Keyword.put(request_opts, :ssl, ssl_opts)
      promise = HTTP.fetch("https://pinned.invalid:#{port}/", request_opts)
      assert {:error, error} = HTTP.Promise.await(promise, 3_000)
      refute HTTP.RequestError.pre_send?(error)

      if unquote(name) == :raw do
        refute match?(%HTTP.RequestError{}, error)
        assert match?({:tls_alert, _}, error)
      else
        assert %HTTP.RequestError{phase: :unknown} = error
      end

      Task.await(peer, 4_000)
    end
  end

  test "early_data does not expose confirmed TLS setup evidence" do
    {_listener, port} = listener()
    request_opts = Keyword.put(options(), :ssl, cacerts: [], early_data: <<"must not transmit">>)

    # OTP rejects early_data with disabled session tickets before starting TLS.
    # The raw TCP connect may already have been aborted when a peer accepts it;
    # requiring a successful accept/handshake here races that option rejection.
    # No peer task is needed: keep the listener owned until the public result,
    # and assert this option failure never grants caller-managed replay evidence.
    promise = HTTP.fetch("https://pinned.invalid:#{port}/", request_opts)

    assert {:error,
            %HTTP.RequestError{
              reason: {:options, :incompatible, [:early_data, {:session_tickets, :disabled}]},
              phase: :unknown,
              request_started: :unknown
            } = error} = HTTP.Promise.await(promise, 3_000)

    refute HTTP.RequestError.pre_send?(error)
  end

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
    test "ordinary successful #{version} preserves verified authority and supports a rebuilt upload" do
      {listener, port} = listener()
      parent = self()
      version = unquote(version)

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
          {:ok, socket} = :ssl.handshake(tcp, [versions: [version]] ++ server_options(), 2_000)
          {:ok, info} = :ssl.connection_information(socket, [:sni_hostname, :protocol])
          send(parent, {:identity, info})
          request = receive_request(socket, "")
          send(parent, {:request, request})

          :ok =
            :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

          :ssl.close(socket)
        end)

      {:ok, upload} = HTTP.Stream.from_enumerable(["once"], telemetry: false)

      promise =
        HTTP.fetch(
          "https://pinned.invalid:#{port}/mutation",
          options(versions: [version]) ++ [method: :post, body: upload, duplex: "half"]
        )

      assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise, 3_000)
      assert :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 3_000)
      assert_receive {:identity, info}
      assert info[:sni_hostname] == ~c"pinned.invalid"
      assert info[:protocol] == version
      assert_receive {:request, bytes}
      assert bytes =~ "Host: pinned.invalid:#{port}\r\n"
      assert bytes =~ "POST /mutation HTTP/1.1\r\n"
      assert length(:binary.matches(bytes, "once")) == 1
      Task.await(peer)
    end
  end

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
      tls_backend: :ssl,
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
