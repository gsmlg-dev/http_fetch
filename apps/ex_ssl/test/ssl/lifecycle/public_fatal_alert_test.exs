defmodule SSL.Lifecycle.PublicFatalAlertTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias SSL.Lifecycle

  @ip {127, 0, 0, 1}
  @fixtures Path.expand("../../../../http_fetch/test/support/fixtures", __DIR__)
  @peer Path.expand("../../../../http_fetch/test/support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      transport <- [:native, :adopted],
      rejection <- [:wrong_ca, :wrong_identity] do
    test "#{version} #{transport} #{rejection} writes the fatal alert before public retirement" do
      assert_fatal_alert(unquote(version), unquote(transport), unquote(rejection))
    end
  end

  for transport <- [:native, :adopted], trigger <- [:output_timeout, :cancel, :deadline] do
    test "#{transport} pending fatal output retains #{trigger} cleanup authority" do
      assert_pending_output(unquote(transport), unquote(trigger))
    end
  end

  defp assert_pending_output(transport, trigger) do
    {peer, port} = peer("TLSv1.3", "http/1.1", "forward")
    parent = self()
    ref = make_ref()
    {:abs_ms, expiry} = setup_deadline = deadline(2_000)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: setup_deadline)

    verify = fn _, event, state ->
      if event == :valid_peer do
        send(parent, {ref, :verification, self()})
        receive do: ({^ref, :reject} -> {:fail, :rejected})
      else
        {:valid, state}
      end
    end

    options = [
      verify: :verify_peer,
      cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
      server_name_indication: ~c"localhost",
      versions: [:"tlsv1.3"],
      alpn_advertised_protocols: ["http/1.1"],
      verify_fun: {verify, nil},
      ex_ssl: [lifecycle: {handle, lease}]
    ]

    caller = Task.async(fn -> connect(transport, port, options) end)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
    end)

    assert_receive {^ref, :verification, connection}, 1_000
    # Provider fault instrumentation holds the original enrolled Writer. The
    # terminal assertion uses the public join, including actual resource DOWN.
    %{resources: resources} = :sys.get_state(handle.receipt.observer)
    %{identity: {_, :process, writer}} = resources.writer
    writer_monitor = Process.monitor(writer)
    assert true = :erlang.suspend_process(writer)

    if trigger == :deadline do
      remaining = max(expiry - System.monotonic_time(:millisecond) - 100, 0)

      receive do
      after
        remaining -> :ok
      end
    end

    sent = System.monotonic_time(:millisecond)
    send(connection, {ref, :reject})
    assert {:closing, pending} = :sys.get_state(connection)
    assert pending.output.kind == :fatal_alert
    assert pending.output.deadline <= sent + 300
    assert pending.lifecycle.tls.outcome_pending
    assert Task.yield(caller, 0) == nil

    if trigger == :cancel, do: assert(:ok = Lifecycle.cancel(lease, deadline(500)))

    assert {:error, _} = Task.await(caller, 1_000)

    assert {:ok, %{cleanup: :confirmed, losses: 0}} =
             Lifecycle.await(handle, deadline(1_000))

    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000
    refute Process.alive?(connection)
    assert System.monotonic_time(:millisecond) - sent < 1_000
    if trigger == :deadline, do: assert(System.monotonic_time(:millisecond) < expiry + 200)
    stop_peer(peer)
  end

  defp assert_fatal_alert(version, transport, rejection) do
    {peer, port} = peer(wire(version), "http/1.1", "forward")
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))
    on_exit(fn -> Lifecycle.cancel(lease, deadline(500)) end)

    options = [
      verify: :verify_peer,
      cacertfile: Path.join(@fixtures, authority(rejection)),
      server_name_indication: identity(rejection),
      versions: [version],
      alpn_advertised_protocols: ["http/1.1"],
      active: false,
      mode: :binary,
      ex_ssl: [lifecycle: {handle, lease}]
    ]

    expected = alert(version, rejection)
    assert {:error, {:tls_alert, {^expected, _}}} = connect(transport, port, options)
    state = stats(peer, &(&1["closed_connections"] == 1))
    assert state["accepted_connections"] == 1
    assert state["requests"] == []
    assert [%{"kind" => "tls", "reason" => reason}] = state["errors"]
    assert reason =~ expected |> Atom.to_string() |> String.upcase()
    assert reason =~ "ALERT"
    stop_peer(peer)

    assert {:ok, %{setup: :failed, setup_failure: :tls, cleanup: :confirmed, losses: 0}} =
             Lifecycle.await(handle, deadline(1_000))
  end

  defp connect(:native, port, options), do: SSL.connect(@ip, port, options, 2_000)

  defp connect(:adopted, port, options) do
    {:ok, tcp} = :gen_tcp.connect(@ip, port, [:binary, active: false], 1_000)
    SSL.connect(tcp, options, 2_000)
  end

  defp authority(:wrong_ca), do: "pinned-ca.pem"
  defp authority(:wrong_identity), do: "localhost-ca.pem"
  defp identity(:wrong_ca), do: ~c"localhost"
  defp identity(:wrong_identity), do: ~c"wrong.invalid"
  defp alert(:"tlsv1.2", _), do: :bad_certificate
  defp alert(:"tlsv1.3", :wrong_ca), do: :unknown_ca
  defp alert(:"tlsv1.3", :wrong_identity), do: :certificate_unknown
  defp wire(:"tlsv1.2"), do: "TLSv1.2"
  defp wire(:"tlsv1.3"), do: "TLSv1.3"

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp peer(version, protocol, route) do
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
          route
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
