defmodule ExSSL.TestSupport.IdentityCompletionFixtures do
  @moduledoc false
  import ExUnit.Assertions

  alias ExSSL.TestSupport.{EncryptedIdentityFixtures, MultiIdentityFixtures}

  @support Path.expand(__DIR__)
  @schemes "rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256:rsa_pkcs1_sha256"
  @body "identity-completion-ok"

  def create(directory) do
    File.mkdir_p!(directory)
    manifest = MultiIdentityFixtures.create(directory)
    password = "IC_PRIVATE_PASSWORD_#{System.unique_integer([:positive])}"

    encrypted =
      Map.new(["rsa2048-a", "p256-a", "p256-b", "chain-a", "large-a"], fn name ->
        entry = manifest["identities"][name]
        identity = %{certificate: entry["cert"], key: entry["key"]}
        {name, EncryptedIdentityFixtures.encrypt(identity, directory, name, password)}
      end)

    executable = Path.join(directory, "identity-completion-peer")
    {flags, 0} = System.cmd("pkg-config", ["--cflags", "--libs", "openssl"])

    {output, status} =
      System.cmd(
        "cc",
        [
          "-std=c11",
          "-D_DARWIN_C_SOURCE",
          "-D_GNU_SOURCE",
          "-Wall",
          "-Wextra",
          "-Werror",
          "-Wno-misleading-indentation",
          Path.join(@support, "identity_completion_peer.c"),
          "-o",
          executable
        ] ++ String.split(flags),
        stderr_to_stdout: true
      )

    assert status == 0, "independent TLS witness compilation failed: #{output}"
    refute manifest["roots"]["server-root"]["sha256"] == manifest["roots"]["client-a"]["sha256"]

    %{
      manifest: manifest,
      encrypted: encrypted,
      executable: executable,
      private: [
        directory,
        password,
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----"
      ]
    }
  end

  def body, do: @body
  def wire("tls12"), do: :"tlsv1.2"
  def wire("tls13"), do: :"tlsv1.3"
  def alpn(:http1), do: "http/1.1"
  def alpn(:http2), do: "h2"

  def credentials(fixtures, version, protocol, selection) do
    counts = :atomics.new(3, [])
    {names, expected} = selection(selection)

    entries =
      names
      |> Enum.with_index(1)
      |> Enum.map(fn {name, index} ->
        encrypted = fixtures.encrypted[name]
        file = fixtures.manifest["identities"][name]

        %{
          certfile: if(name == "chain-a", do: file["partial_cert"], else: file["cert"]),
          keyfile: encrypted.encrypted_key,
          password: fn ->
            :atomics.add_get(counts, index, 1)
            encrypted.password
          end
        }
      end)

    legacy? = selection in [:single_rsa, :single_ec]

    identity =
      if legacy? do
        Map.to_list(hd(entries))
      else
        [
          certs_keys: entries,
          password: fn ->
            :atomics.add_get(counts, 3, 1)
            flunk("ignored top-level password callback was invoked")
          end
        ]
      end

    ssl =
      [
        verify: :verify_peer,
        cacerts: [MultiIdentityFixtures.root(fixtures.manifest, "server-root")],
        server_name_indication: ~c"r47.server",
        versions: [wire(version)],
        alpn_advertised_protocols: [alpn(protocol)],
        active: false,
        mode: :binary
      ] ++ identity

    ssl =
      if selection in [:single_ec, :ec_scheme] do
        Keyword.put(ssl, :signature_algs, [:ecdsa_secp256r1_sha256, :rsa_pss_rsae_sha256])
      else
        ssl
      end

    {ssl, expected, {counts, length(entries)}}
  end

  def peer_options(selection) when selection in [:single_ec, :ec_scheme],
    do: [schemes: "ecdsa_secp256r1_sha256:rsa_pkcs1_sha256"]

  def peer_options(:single_rsa), do: [schemes: "rsa_pss_rsae_sha256:rsa_pkcs1_sha256"]

  def peer_options(_selection), do: []

  def http2_options(:http1, _label), do: []

  def http2_options(:http2, label),
    do: [http2_scope: "identity-#{label}-#{System.unique_integer([:positive])}"]

  # Function-valued TLS options deliberately make the existing H2 pool key
  # non-reusable. Isolation checks use static per-map passwords; A01 separately
  # proves callback-once semantics without widening that pool policy.
  def shared_credentials(fixtures, version) do
    {options, expected, _unused_callback_counts} =
      credentials(fixtures, version, :http2, :later_rsa_ca)

    entries =
      Enum.zip_with(options[:certs_keys], ["p256-b", "chain-a"], fn entry, name ->
        Map.put(entry, :password, fixtures.encrypted[name].password)
      end)

    {options |> Keyword.put(:certs_keys, entries) |> Keyword.delete(:password), expected}
  end

  defp selection(:single_rsa), do: {["rsa2048-a"], "rsa2048-a"}
  defp selection(:single_ec), do: {["p256-a"], "p256-a"}
  defp selection(:later_rsa_ca), do: {["p256-b", "chain-a"], "chain-a"}
  defp selection(:ec_scheme), do: {["rsa2048-a", "p256-a"], "p256-a"}
  defp selection(:large_rsa), do: {["p256-b", "large-a"], "large-a"}
  defp selection(:no_eligible), do: {["chain-a"], "chain-a"}

  def assert_callbacks({counts, length}) do
    assert Enum.map(1..length, &:atomics.get(counts, &1)) == List.duplicate(1, length)
    assert :atomics.get(counts, 3) == 0
  end

  def start(fixtures, version, protocol, application, options \\ []) do
    app =
      open("python3", [
        Path.join(@support, "identity_completion_application.py"),
        "--protocol",
        Atom.to_string(protocol),
        "--application",
        Atom.to_string(application)
      ])

    app_ready = event_port(app, "ready", 2_000)
    manifest = fixtures.manifest
    schemes = Keyword.get(options, :schemes, @schemes)
    hint = Keyword.get(options, :hint, "client-a")

    tls =
      open(fixtures.executable, [
        manifest["server"]["cert"],
        manifest["server"]["key"],
        manifest["client_trust"],
        if(hint, do: manifest["roots"][hint]["cert"], else: "none"),
        version,
        Keyword.get(options, :auth, "required"),
        schemes,
        alpn(protocol),
        Integer.to_string(app_ready["port"]),
        cond do
          Keyword.get(options, :gate, false) -> "gate"
          Keyword.get(options, :rejection_gate, false) -> "reject"
          true -> "normal"
        end
      ])

    ready = event_port(tls, "ready", 2_000)
    authority = "#{Keyword.get(options, :authority_host, "127.0.0.1")}:#{ready["port"]}"
    true = Port.command(app, JSON.encode!(%{authority: authority}) <> "\n")

    %{
      tls: tls,
      app: app,
      port: ready["port"],
      authority: authority,
      version: version,
      protocol: protocol,
      application: application
    }
  end

  def url(peer, scheme \\ "https", suffix \\ ""),
    do: "#{scheme}://#{peer.authority}/identity-completion#{suffix}"

  def event(peer, source, name, timeout \\ 3_000),
    do: event_port(Map.fetch!(peer, source), name, timeout)

  def command(peer, source, command), do: Port.command(Map.fetch!(peer, source), command <> "\n")

  def events(peer, source), do: Process.get({__MODULE__, Map.fetch!(peer, source), :events}, [])

  def start_proxy(peer, counts) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)
    parent = self()
    reference = make_ref()

    {pid, monitor} =
      spawn_monitor(fn ->
        {:ok, client} = :gen_tcp.accept(listener, 5_000)

        try do
          expected = "CONNECT #{peer.authority} HTTP/1.1\r\n"
          assert String.starts_with?(proxy_head(client), expected)
          if counts, do: assert_callbacks(counts)
          send(parent, {reference, :connect_exact})

          {:ok, upstream} =
            :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 3_000)

          try do
            :ok = :gen_tcp.send(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
            :ok = :inet.setopts(client, active: :once)
            :ok = :inet.setopts(upstream, active: :once)
            proxy_forward(client, upstream)
          after
            :gen_tcp.close(upstream)
          end
        after
          :gen_tcp.close(client)
        end
      end)

    %{port: port, listener: listener, pid: pid, monitor: monitor, reference: reference}
  end

  def route_proxy(:direct, _peer, _counts), do: nil
  def route_proxy(:connect, peer, counts), do: start_proxy(peer, counts)

  def proxy_options(nil), do: []
  def proxy_options(proxy), do: [proxy: {:http, "127.0.0.1", proxy.port, []}]

  def stop_proxy(nil), do: :ok

  def stop_proxy(proxy) do
    send(proxy.pid, :stop)
    :ok = :gen_tcp.close(proxy.listener)
    monitor = proxy.monitor
    pid = proxy.pid

    receive do
      {:DOWN, ^monitor, :process, ^pid, reason} -> assert reason == :normal
    after
      3_000 -> flunk("CONNECT relay did not join")
    end

    reference = proxy.reference
    _ = assert_receive {^reference, :connect_exact}, 0
    refute Process.alive?(pid)
  end

  # Only test instrumentation reads provider internals. Public completion is
  # retained separately and is never inferred from this graph.
  def provider_handle(%{tracker: tracker}) do
    state = :sys.get_state(tracker, 1_000)

    providers =
      case state do
        %{client?: true, children: children} ->
          [entry] = children |> Map.values() |> Enum.filter(&is_pid(&1.child))
          :sys.get_state(entry.child, 1_000).providers

        %{providers: providers} ->
          providers
      end

    [handle] = Map.keys(providers)
    handle
  end

  def client_deadline(pid) do
    state = await_state(pid, now() + 1_000, fn state -> is_integer(state.opening_deadline) end)
    state.opening_deadline
  end

  def await_pending_read(socket) do
    await_state(socket.pid, now() + 1_000, fn
      {:connected, %{recv: receiver}} -> is_map(receiver)
      _ -> false
    end)

    :ok
  end

  def with_shared_owner(pool, peer, fun) do
    %{providers: providers} = :sys.get_state(pool, 1_000)

    [{owner, %{carrier: %{handle: handle}}}] =
      Enum.filter(providers, fn {_owner, provider} -> provider.key.port == peer.port end)

    shared = %{
      owner: owner,
      monitor: Process.monitor(owner),
      handle: handle,
      graph: monitor_graph(handle)
    }

    try do
      fun.(shared)
      await_state(owner, now() + 1_000, fn state -> map_size(state.streams) == 0 end)
    after
      if Process.alive?(owner), do: GenServer.stop(owner, :normal, 1_000)

      _ =
        assert_receive {:DOWN, monitor, :process, ^owner, _} when monitor == shared.monitor, 1_000

      assert_graph_down(shared.graph, now() + 2_000)

      _ =
        assert {:ok, %{cleanup: :confirmed} = receipt} =
                 SSL.Lifecycle.await(handle, {:abs_ms, now() + 1_000})

      assert {:ok, ^receipt} = SSL.Lifecycle.await(handle, {:abs_ms, now()})
    end

    %{
      shared_owner_joined: true,
      provider_cleanup: "confirmed",
      typed_resources_joined: graph_counts(shared.graph)
    }
  end

  def block_authentication(peer, handle_or_receipt, fixtures) do
    _ = event(peer, :tls, "client_hello_gate")

    handle =
      case handle_or_receipt do
        %SSL.Lifecycle.Handle{} = handle -> handle
        receipt -> provider_handle(receipt)
      end

    graph = monitor_graph(handle)
    connection = graph.connection.object
    writer = graph.writer.object

    initial =
      await_state(connection, now() + 1_000, fn
        {:handshaking, %{output: nil}} -> true
        _ -> false
      end)

    {:handshaking, initial} = initial
    true = :erlang.suspend_process(writer)
    true = command(peer, :tls, "go")
    _ = event(peer, :tls, "certificate_request")

    try do
      {:handshaking, blocked} =
        await_state(connection, initial.deadline, fn
          {:handshaking, %{output: %{kind: :client_finished}}} ->
            true

          {:handshaking,
           %{output: %{kind: :handshake}, machine: %SSL.Protocol.TLS12{phase: :await_server_ccs}}} ->
            true

          _ ->
            false
        end)

      large = MultiIdentityFixtures.der(fixtures.manifest, "large-a")
      assert byte_size(large) > 16_384
      assert blocked.output.size > byte_size(large)
      assert blocked.deadline == initial.deadline
      assert Process.info(writer, :status) == {:status, :suspended}
      remaining = Process.read_timer(blocked.output.timer)
      assert is_integer(remaining) and remaining > 0
      assert remaining <= SSL.Options.remaining(initial.deadline) + 1
      assert now() < initial.deadline

      %{
        graph: graph,
        connection: connection,
        writer: writer,
        handle: handle,
        deadline: initial.deadline,
        output_timer: blocked.output.timer,
        handshake_timer: initial.handshake_timer,
        output_size: blocked.output.size
      }
    rescue
      error ->
        if Process.alive?(writer), do: :erlang.resume_process(writer)
        reraise error, __STACKTRACE__
    end
  end

  defp monitor_graph(handle) do
    %{resources: resources} = :sys.get_state(handle.receipt.observer, 1_000)

    graph =
      Map.new(resources, fn {role, %{identity: {_, type, object}}} ->
        monitor =
          case type do
            :socket -> :socket.monitor(object)
            :port -> :erlang.monitor(:port, object)
            :process -> Process.monitor(object)
          end

        {role, %{type: type, object: object, monitor: monitor}}
      end)

    observer = handle.receipt.observer

    Map.put(graph, :observer, %{
      type: :process,
      object: observer,
      monitor: Process.monitor(observer)
    })
  end

  def assert_authentication_cleanup(blocked) do
    limit = blocked.deadline + 1_000
    assert_graph_down(blocked.graph, limit)
    assert Process.read_timer(blocked.output_timer) == false
    assert Process.read_timer(blocked.handshake_timer) == false

    _ =
      assert {:ok, %{cleanup: :confirmed} = receipt} =
               SSL.Lifecycle.await(blocked.handle, {:abs_ms, limit})

    _ = assert {:ok, ^receipt} = SSL.Lifecycle.await(blocked.handle, {:abs_ms, now()})
    receipt
  end

  defp assert_graph_down(graph, limit) do
    Enum.each(graph, fn {_role, %{type: type, object: object, monitor: monitor}} ->
      _ = assert_receive {:DOWN, ^monitor, ^type, ^object, _}, max(limit - now(), 0)

      case type do
        :process -> refute Process.alive?(object)
        :port -> assert Port.info(object) == nil
        :socket -> refute object in :socket.which_sockets()
      end
    end)
  end

  def assert_peer_authentication_closed(peer) do
    terminal = event(peer, :tls, "transport_terminal", 2_000)
    assert terminal["observed"] in ["eof", "reset"]
    refute Enum.any?(events(peer, :tls), &(&1["event"] in ["authenticated", "client_cv"]))
    terminal["observed"]
  end

  def resume_authentication(blocked) do
    if Process.alive?(blocked.writer), do: :erlang.resume_process(blocked.writer)

    Enum.each(blocked.graph, fn
      {_role, %{type: :socket, monitor: monitor}} -> :socket.cancel_monitor(monitor)
      {_role, %{monitor: monitor}} -> Process.demonitor(monitor, [:flush])
    end)
  end

  def assert_rejected(peer) do
    assert Enum.count(events(peer, :tls), &(&1["event"] == "accepted")) == 1
    refute Enum.any?(events(peer, :tls), &(&1["event"] == "authenticated"))

    refute Enum.any?(
             events(peer, :app),
             &(&1["event"] in ["application_connected", "request", "response"])
           )
  end

  def stop(peer) do
    Enum.each([peer.tls, peer.app], fn port ->
      if Port.info(port) do
        try do
          Port.command(port, "stop\n")
        rescue
          ArgumentError -> :ok
        end
      end
    end)

    Enum.each([peer.tls, peer.app], fn port ->
      assert join(port, now() + 3_000) == 0, "independent peer did not exit successfully"
      pid = Process.get({__MODULE__, port, :pid})
      {_, status} = System.cmd("kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true)
      assert status != 0, "independent peer PID remains alive"
    end)

    :ok
  end

  def assert_authenticated(fixtures, peer, expected, requests \\ 1) do
    tls = events(peer, :tls)
    application = events(peer, :app)
    [auth] = Enum.filter(tls, &(&1["event"] == "authenticated"))
    [negotiated] = Enum.filter(tls, &(&1["event"] == "negotiated"))
    [wire] = Enum.filter(tls, &(&1["event"] == "wire_client_chain"))
    manifest = fixtures.manifest
    leaf = manifest["identities"][expected]["sha256"]

    chain =
      if expected == "chain-a",
        do: [leaf, manifest["intermediates"]["a"]["sha256"]],
        else: [leaf]

    scheme = if expected == "p256-a", do: 0x0403, else: 0x0804
    assert auth["client_leaf_sha256"] == leaf
    assert auth["verify_result"] == 0
    assert wire["sha256"] == chain
    _ = assert [%{"scheme" => ^scheme}] = Enum.filter(tls, &(&1["event"] == "client_cv"))
    assert auth["version"] == if(peer.version == "tls12", do: "TLSv1.2", else: "TLSv1.3")
    assert negotiated["alpn"] == alpn(peer.protocol)
    assert negotiated["sni"] == "r47.server"

    if peer.version == "tls12" do
      assert auth["ems"] == 1
      assert auth["secure_renegotiation"] == 1
    end

    assert Enum.count(tls, &(&1["event"] == "accepted")) == 1
    assert Enum.count(application, &(&1["event"] == "application_connected")) == 1
    actual_requests = Enum.filter(application, &(&1["event"] == "request"))
    assert length(actual_requests) == requests

    assert Enum.all?(actual_requests, fn row ->
             row["request_exact"] and row["authority_exact"] and row["scheme"] == "https"
           end)

    assert Enum.count(application, &(&1["event"] == "response" and &1["response_written"])) ==
             requests

    refute Enum.any?(application, &(&1["event"] == "application_error"))
    assert_public_redacted({tls, application}, fixtures)
  end

  def assert_no_identity_authenticated(peer) do
    tls = events(peer, :tls)
    application = events(peer, :app)

    _ =
      assert [%{"client_leaf_sha256" => nil, "verify_result" => 0, "version" => "TLSv1.3"}] =
               Enum.filter(tls, &(&1["event"] == "authenticated"))

    _ =
      assert [%{"alpn" => "http/1.1", "sni" => "r47.server"}] =
               Enum.filter(tls, &(&1["event"] == "negotiated"))

    refute Enum.any?(
             tls,
             &(&1["event"] in ["wire_client_chain", "client_cv", "certificate_request"])
           )

    assert Enum.count(tls, &(&1["event"] == "accepted")) == 1
    assert Enum.count(application, &(&1["event"] == "application_connected")) == 1

    _ =
      assert [%{"request_exact" => true, "authority_exact" => true, "scheme" => "https"}] =
               Enum.filter(application, &(&1["event"] == "request"))

    _ =
      assert [%{"response_written" => true}] =
               Enum.filter(application, &(&1["event"] == "response"))

    refute Enum.any?(application, &(&1["event"] == "application_error"))
  end

  def assert_public_redacted(value, fixtures) do
    assert_source_redacted(value, fixtures)
    refute private_structure?(value), "public evidence contains private identity material"
  end

  # Prepared credentials necessarily retain the signing key. Their public
  # Inspect and source/password/callback retention have a separate contract.
  def assert_credential_snapshot_redacted(value, fixtures) do
    assert_source_redacted(value, fixtures)
    displayed = inspect(value, limit: :infinity, printable_limit: :infinity)
    refute String.contains?(displayed, ["private_key", "RSAPrivateKey", "ECPrivateKey"])
  end

  defp assert_source_redacted(value, fixtures) do
    encoded = :erlang.term_to_binary(value)
    displayed = inspect(value, limit: :infinity, printable_limit: :infinity)

    private_free? =
      Enum.all?(fixtures.private, &(not contains?(encoded, &1) and not contains?(displayed, &1)))

    assert private_free?, "public evidence contains private credential material"
    refute has_function?(value), "public evidence contains a callback closure"
  end

  def concurrent_reads(reader, expected) do
    deadline = now() + 1_000
    readers = for _ <- 1..2, do: Task.async(reader)

    Enum.each(readers, fn task ->
      assert Task.await(task, max(deadline - now(), 0)) == expected
    end)
  end

  def record_blocked(id, blocked, completion, terminal) do
    record(id, %{
      public_completion: if(completion == :ok, do: "confirmed", else: "cleanup_unconfirmed"),
      provider_cleanup: "confirmed",
      typed_resources_joined: graph_counts(blocked.graph),
      selected_authentication_output_bytes: blocked.output_size,
      provider_original_deadline_retained: true,
      peer_transport_terminal: terminal
    })
  end

  def record(id, details \\ %{}) do
    IO.puts(
      "IDENTITY_COMPLETION_CASE_PASS " <>
        JSON.encode!(Map.merge(details, %{id: id, provisional: true}))
    )
  end

  defp graph_counts(graph), do: graph |> Map.values() |> Enum.frequencies_by(& &1.type)

  defp contains?(value, marker), do: :binary.match(value, marker) != :nomatch

  defp await_state(connection, deadline, predicate) do
    remaining = deadline - now()

    assert remaining > 0,
           "selected client authentication output did not block under original deadline"

    state = :sys.get_state(connection, remaining)

    if predicate.(state) do
      state
    else
      receive do
      after
        1 -> await_state(connection, deadline, predicate)
      end
    end
  end

  defp proxy_head(socket, bytes \\ <<>>) do
    assert byte_size(bytes) <= 16_384

    if :binary.match(bytes, "\r\n\r\n") != :nomatch do
      bytes
    else
      {:ok, chunk} = :gen_tcp.recv(socket, 0, 3_000)
      proxy_head(socket, bytes <> chunk)
    end
  end

  defp proxy_forward(client, upstream) do
    receive do
      {:tcp, socket, bytes} when socket in [client, upstream] ->
        other = if socket == client, do: upstream, else: client

        case :gen_tcp.send(other, bytes) do
          :ok ->
            :ok = :inet.setopts(socket, active: :once)
            proxy_forward(client, upstream)

          {:error, :closed} ->
            :ok
        end

      {:tcp_closed, socket} when socket in [client, upstream] ->
        :ok

      {:tcp_error, socket, _} when socket in [client, upstream] ->
        :ok

      :stop ->
        :ok
    after
      10_000 -> flunk("CONNECT relay forwarding deadline")
    end
  end

  defp has_function?(value) when is_function(value), do: true

  defp has_function?(value) when is_map(value),
    do:
      Enum.any?(Map.to_list(value), fn {key, item} ->
        has_function?(key) or has_function?(item)
      end)

  defp has_function?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.any?(&has_function?/1)

  defp has_function?(value) when is_list(value), do: Enum.any?(value, &has_function?/1)
  defp has_function?(_), do: false

  defp private_structure?(value) when is_map(value) do
    Map.has_key?(value, :private_key) or Map.has_key?(value, :identities) or
      Enum.any?(Map.to_list(value), fn {key, item} ->
        private_structure?(key) or private_structure?(item)
      end)
  end

  defp private_structure?(value) when is_tuple(value) do
    (tuple_size(value) > 0 and
       elem(value, 0) in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo, :OneAsymmetricKey]) or
      value |> Tuple.to_list() |> Enum.any?(&private_structure?/1)
  end

  defp private_structure?(value) when is_list(value), do: Enum.any?(value, &private_structure?/1)
  defp private_structure?(_), do: false

  defp open(executable, arguments) do
    executable = System.find_executable(executable) || executable

    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        {:line, 65_536},
        :stderr_to_stdout,
        args: arguments
      ])

    # A peer may finish between Port.info and the bounded stop write. Its
    # explicit exit_status is still joined and asserted; an EPIPE must not kill
    # the test process before that independent result is collected.
    Process.unlink(port)
    {:os_pid, pid} = Port.info(port, :os_pid)
    Process.put({__MODULE__, port, :pid}, pid)
    Process.put({__MODULE__, port, :events}, [])
    port
  end

  defp event_port(port, name, timeout) do
    deadline = now() + timeout
    receive_event(port, name, deadline)
  end

  defp receive_event(port, name, deadline) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        row = decode(line)
        save(port, row)
        if row["event"] == name, do: row, else: receive_event(port, name, deadline)

      {^port, {:exit_status, status}} ->
        Process.put({__MODULE__, port, :exit}, status)
        flunk("independent peer exited before expected #{name} event")
    after
      max(deadline - now(), 0) -> flunk("independent peer #{name} event deadline")
    end
  end

  defp join(port, deadline) do
    case Process.get({__MODULE__, port, :exit}) do
      nil ->
        receive do
          {^port, {:data, {:eol, line}}} ->
            save(port, decode(line))
            join(port, deadline)

          {^port, {:exit_status, status}} ->
            Process.put({__MODULE__, port, :exit}, status)
            status
        after
          max(deadline - now(), 0) -> flunk("independent peer shutdown deadline")
        end

      status ->
        status
    end
  end

  defp decode(line) do
    case JSON.decode(line) do
      {:ok, row} when is_map(row) -> row
      _ -> flunk("independent peer emitted invalid public event")
    end
  end

  defp save(port, row) do
    Process.put(
      {__MODULE__, port, :events},
      Process.get({__MODULE__, port, :events}, []) ++ [row]
    )
  end

  defp now, do: System.monotonic_time(:millisecond)
end
