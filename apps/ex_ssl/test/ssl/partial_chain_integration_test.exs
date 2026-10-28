defmodule SSL.PartialChainIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      choice <- [:intermediate, :unknown, :unmatched, :raise, :throw, :malformed] do
    test "#{version} #{route} selected #{choice} preserves bounded candidate trust", %{
      directory: directory
    } do
      selected_path(directory, unquote(version), unquote(route), unquote(choice))
    end
  end

  defp selected_path(directory, version, route, choice) do
    peer = RevocationPeer.start(directory, version)
    parent = self()
    reference = make_ref()
    intermediate = File.read!(Path.join(directory, "intermediate.der"))
    leaf = File.read!(Path.join(directory, "leaf.der"))
    root = File.read!(Path.join(directory, "root.der"))

    callback = fn candidate ->
      send(parent, {reference, candidate})

      case choice do
        :intermediate -> {:trusted_ca, intermediate}
        :unknown -> :unknown_ca
        :unmatched -> {:trusted_ca, root}
        :raise -> raise "R49_PRIVATE_PARTIAL"
        :throw -> throw("R49_PRIVATE_PARTIAL")
        :malformed -> %{private: "R49_PRIVATE_PARTIAL"}
      end
    end

    options =
      RevocationFixtures.options(directory, version)
      |> Keyword.put(:cacerts, [])
      |> Keyword.put(:partial_chain, callback)

    try do
      result = connect(peer.port, options, route)
      assert_receive {^reference, [^intermediate, ^leaf]}, 500
      refute_receive {^reference, _}, 0

      if choice == :intermediate do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        assert {:ok, response} = SSL.recv(socket, 0, 2_000)
        assert response =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
        refute inspect(result) =~ "R49_PRIVATE_PARTIAL"
      end
    after
      RevocationPeer.stop(peer)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{version} trusted-root callback sees completed root-to-leaf path", %{
      directory: directory
    } do
      parent = self()
      reference = make_ref()
      root = File.read!(Path.join(directory, "root.der"))
      intermediate = File.read!(Path.join(directory, "intermediate.der"))
      leaf = File.read!(Path.join(directory, "leaf.der"))

      callback = fn path ->
        send(parent, {reference, path})
        :unknown_ca
      end

      peer = RevocationPeer.start(directory, unquote(version))

      options =
        RevocationFixtures.options(directory, unquote(version)) ++ [partial_chain: callback]

      try do
        assert {:ok, socket} = connect(peer.port, options, :direct)
        assert_receive {^reference, [^root, ^intermediate, ^leaf]}, 500
        assert :ok = SSL.close(socket)
      after
        RevocationPeer.stop(peer)
      end
    end

    test "#{version} partial anchor does not skip origin hostname", %{directory: directory} do
      intermediate = File.read!(Path.join(directory, "intermediate.der"))
      callback = fn _ -> {:trusted_ca, intermediate} end
      peer = RevocationPeer.start(directory, unquote(version))

      options =
        RevocationFixtures.options(directory, unquote(version))
        |> Keyword.put(:cacerts, [])
        |> Keyword.put(:partial_chain, callback)
        |> Keyword.put(:server_name_indication, ~c"wrong.example")

      try do
        assert {:error, {:tls_alert, _}} = connect(peer.port, options, :direct)
      after
        RevocationPeer.stop(peer)
      end
    end
  end

  defp connect(port, options, :direct), do: SSL.connect(~c"127.0.0.1", port, options, 5_000)

  defp connect(port, options, :prepared) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    SSL.connect_prepared(tcp, prepared, 5_000)
  end
end

defmodule SSL.PartialLeafAnchorIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      check <- [
        :correct,
        :wrong_dns,
        :wrong_ip,
        :crl,
        :ocsp,
        :wrong_eku,
        :wrong_key_usage,
        :unknown_critical,
        :expired,
        :ip_positive,
        :invalid_basic_constraints,
        :duplicate_san,
        :critical_policy_constraints
      ] do
    test "#{version} #{route} selected leaf keeps mandatory #{check} without callback replay" do
      run_case(unquote(version), unquote(route), unquote(check))
    end
  end

  defp run_case(version, route, check) do
    directory = RevocationFixtures.directory!()

    variant = leaf_variant(check)

    variants = if variant, do: RevocationFixtures.leaf_variants!()

    leaf =
      File.read!(
        if variant,
          do: Path.join(variants, variant <> ".der"),
          else: Path.join(directory, "leaf.der")
      )

    intermediate = File.read!(Path.join(directory, "intermediate.der"))
    parent = self()
    ref = make_ref()

    partial = fn path ->
      send(parent, {ref, :path, path})
      {:trusted_ca, leaf}
    end

    verify = fn _, _, event, state ->
      send(parent, {ref, :event, event})

      case event do
        {:bad_cert, _} -> {:fail, :rejected}
        {:extension, _} -> {:unknown, state}
        _ -> {:valid, state}
      end
    end

    options =
      RevocationFixtures.options(directory, version)
      |> Keyword.put(:cacerts, [])
      |> Keyword.put(:partial_chain, partial)
      |> Keyword.put(:verify_fun, {verify, :initial})

    options = case_options(check, options)

    extra = if variant, do: ["-cert", Path.join(variants, variant <> ".pem")], else: []
    peer = RevocationPeer.start(directory, version, extra)

    try do
      result = connect(peer.port, options, route)

      if check == :wrong_key_usage do
        refute_receive {^ref, :path, _}, 0
      else
        assert_receive {^ref, :path, [^intermediate, ^leaf]}, 500
      end

      if check == :expired do
        # This is public_key's real anchor-validity callback, not a replay.
        assert_receive {^ref, :event, {:bad_cert, :cert_expired}}, 500
      end

      refute_receive {^ref, :event, _}, 0

      if check in [:correct, :ip_positive] do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = File.read!(Path.join(directory, "root.der"))
        bytes = receive_bytes(socket, <<>>, byte_size(expected))
        assert [_, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
      end
    after
      RevocationPeer.stop(peer)
    end
  end

  defp connect(port, options, :direct), do: SSL.connect(~c"127.0.0.1", port, options, 5_000)

  defp connect(port, options, :prepared) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    SSL.connect_prepared(tcp, prepared, 5_000)
  end

  defp receive_bytes(socket, bytes, expected) do
    assert byte_size(bytes) <= expected + 8_192

    complete =
      case :binary.split(bytes, "\r\n\r\n") do
        [_, body] -> byte_size(body) >= expected
        _ -> false
      end

    if complete do
      bytes
    else
      {:ok, more} = SSL.recv(socket, 0, 2_000)
      receive_bytes(socket, bytes <> more, expected)
    end
  end

  defp leaf_variant(check) do
    case check do
      :wrong_eku -> "wrong-eku"
      :wrong_key_usage -> "wrong-key-usage"
      :unknown_critical -> "unknown-critical"
      :expired -> "expired"
      :ip_positive -> "ip-san"
      :invalid_basic_constraints -> "invalid-basic-constraints"
      :duplicate_san -> "duplicate-san"
      :critical_policy_constraints -> "critical-policy-constraints"
      _ -> nil
    end
  end

  defp case_options(check, options) do
    case check do
      :wrong_dns -> Keyword.put(options, :server_name_indication, ~c"wrong.example")
      :wrong_ip -> Keyword.put(options, :ex_ssl, reference_identity: {:ip, {127, 0, 0, 1}})
      :crl -> Keyword.put(options, :crl_check, true)
      :ocsp -> Keyword.put(options, :stapling, :staple)
      :ip_positive -> Keyword.put(options, :ex_ssl, reference_identity: {:ip, {127, 0, 0, 1}})
      _ -> options
    end
  end
end

defmodule SSL.PartialChainAdditionalIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, _), do: []
  def select(_, _), do: []
  def fresh_crl(_, current), do: current

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      scenario <- [
        :unknown_nocallback,
        :known_choose_i,
        :known_unknown,
        :unrelated,
        :misordered,
        :duplicate,
        :branch_valid,
        :branch_pathlen,
        :branch_name_constraint,
        :branch_critical,
        :bad_signature,
        :expired,
        :wrong_eku,
        :unknown_critical,
        :exit,
        :improper,
        :selfsigned,
        :selfsigned_override,
        :cross_retry,
        :cross_both,
        :trust_i_nocallback,
        :missing_i
      ] do
    test "#{version} #{route} #{scenario} partial chain constraint and callback contract", %{
      directory: base
    } do
      run_case(base, unquote(version), unquote(route), unquote(scenario))
    end
  end

  defp run_case(base, version, route, scenario) do
    read = fn name -> File.read!(Path.join(base, name <> ".der")) end
    root = read.("root")
    intermediate = read.("intermediate")
    other = read.("other-root")

    branch =
      scenario in [:branch_valid, :branch_pathlen, :branch_name_constraint, :branch_critical]

    variant = leaf_variant(scenario)

    certificate = leaf_certificate(scenario, variant, branch, base)

    leaf = File.read!(certificate <> ".der")

    chain = peer_chain(scenario)

    trust = trusted_certificates(scenario, branch, intermediate, root, other)

    labels =
      for name <- [
            "root",
            "intermediate",
            "other-root",
            "intermediate-cross",
            "intermediate-cross-expired",
            "branch-a",
            "branch-a-valid",
            "branch-a-name-constraint",
            "branch-a-critical",
            "branch-b"
          ],
          into: %{},
          do: {read.(name), name}

    labels = Map.put(labels, leaf, "leaf")
    ref = make_ref()
    owner = self()

    partial = fn candidate ->
      send(owner, {ref, :partial, Enum.map(candidate, &Map.get(labels, &1, "unexpected"))})

      select_partial_anchor(scenario, intermediate, other, leaf)
    end

    verify = fn cert, event, state ->
      der = :public_key.pkix_encode(:OTPCertificate, cert, :otp)
      role = Map.get(labels, der, "unexpected")

      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, reason} ->
          reason = if is_atom(reason), do: reason, else: elem(reason, 0)
          send(owner, {ref, :verify, {role, reason, state}})
          if scenario == :selfsigned_override, do: {:valid, state}, else: {:fail, :rejected}

        event ->
          send(owner, {ref, :verify, {role, event, state}})
          {:valid, state + 1}
      end
    end

    options =
      RevocationFixtures.options(base, version)
      |> Keyword.put(:cacerts, trust)
      |> Keyword.put(:verify_fun, {verify, 0})

    options =
      if scenario in [:unknown_nocallback, :trust_i_nocallback],
        do: options ++ [crl_check: :best_effort, crl_cache: {__MODULE__, {nil, []}}],
        else: options ++ [partial_chain: partial]

    peer =
      RevocationPeer.start(base, version, ["-cert", certificate <> ".pem", "-cert_chain", chain])

    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              5_000
            )

          :prepared ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
        end

      case result do
        {:ok, socket} ->
          assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
          body = read.("root")
          bytes = receive_body(socket, <<>>, byte_size(body))
          assert [header, ^body] = :binary.split(bytes, "\r\n\r\n")
          assert header =~ "HTTP/1.0 200"
          assert :ok = SSL.close(socket)

        {:error, {:tls_alert, _}} ->
          :ok
      end

      accepted =
        scenario in [
          :known_choose_i,
          :known_unknown,
          :misordered,
          :duplicate,
          :branch_valid,
          :selfsigned_override,
          :cross_retry,
          :cross_both,
          :trust_i_nocallback,
          :missing_i
        ]

      assert match?({:ok, _}, result) == accepted
      refute inspect(result) =~ "private_r49_callback"
      assert collect(ref, []) == expected_trace(scenario)

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: mask, observed_down: mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      assert mask == if(route == :direct, do: 31, else: 30)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
  end

  defp collect(ref, acc) do
    receive do
      {^ref, :partial, paths} ->
        collect(ref, [%{partial: paths} | acc])

      {^ref, :verify, {role, event, state}} ->
        collect(ref, [%{role: role, event: event, state: state} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp expected_trace(scenario) do
    {paths, events} =
      case scenario do
        :unknown_nocallback ->
          {[], [{"intermediate", :unknown_ca, 0}]}

        :trust_i_nocallback ->
          {[], [{"leaf", :valid_peer, 0}]}

        :missing_i ->
          {[["intermediate", "leaf"]], [{"leaf", :valid_peer, 0}]}

        :cross_both ->
          {[["other-root", "intermediate-cross", "leaf"], ["root", "intermediate", "leaf"]],
           [{"intermediate-cross", :valid, 0}, {"leaf", :valid_peer, 1}]}

        :cross_retry ->
          {[
             ["other-root", "intermediate-cross-expired", "leaf"],
             ["root", "intermediate", "leaf"]
           ],
           [
             {"intermediate-cross-expired", :cert_expired, 0},
             {"intermediate", :valid, 0},
             {"leaf", :valid_peer, 1}
           ]}

        :known_choose_i ->
          {[["root", "intermediate", "leaf"]], [{"leaf", :valid_peer, 0}]}

        value when value in [:known_unknown, :misordered, :duplicate] ->
          {[["root", "intermediate", "leaf"]],
           [{"intermediate", :valid, 0}, {"leaf", :valid_peer, 1}]}

        value when value in [:unrelated, :exit, :improper] ->
          {[["intermediate", "leaf"]], [{"intermediate", :unknown_ca, 0}]}

        value
        when value in [:branch_valid, :branch_pathlen, :branch_name_constraint, :branch_critical] ->
          branch_trace(value)

        :bad_signature ->
          {[["intermediate", "leaf"]], [{"leaf", :invalid_signature, 0}]}

        :expired ->
          {[["intermediate", "leaf"]], [{"leaf", :cert_expired, 0}]}

        :wrong_eku ->
          {[["intermediate", "leaf"]], [{"leaf", :ca_invalid_ext_keyusage, 0}]}

        :unknown_critical ->
          {[["intermediate", "leaf"]], []}

        value when value in [:selfsigned, :selfsigned_override] ->
          {[], [{"leaf", :selfsigned_peer, 0}]}
      end

    Enum.map(paths, &%{partial: &1}) ++
      Enum.map(events, fn {role, event, state} -> %{role: role, event: event, state: state} end)
  end

  defp receive_body(socket, bytes, expected) do
    assert byte_size(bytes) <= expected + 8_192

    case :binary.split(bytes, "\r\n\r\n") do
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, more} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> more, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp leaf_variant(scenario) do
    case scenario do
      :expired -> "expired"
      :wrong_eku -> "wrong-eku"
      :unknown_critical -> "unknown-critical"
      _ -> nil
    end
  end

  defp leaf_certificate(scenario, variant, branch, base) do
    cond do
      variant -> Path.join(RevocationFixtures.leaf_variants!(), variant)
      branch -> Path.join(base, "leaf-branch")
      scenario == :bad_signature -> Path.join(base, "leaf-bad-signature")
      scenario in [:selfsigned, :selfsigned_override] -> Path.join(base, "leaf-selfsigned")
      true -> Path.join(base, "leaf")
    end
  end

  defp peer_chain(scenario) do
    case scenario do
      :missing_i ->
        "root.pem"

      value when value in [:misordered, :duplicate] ->
        "partial-" <> if(value == :duplicate, do: "duplicated", else: "misordered") <> ".pem"

      value
      when value in [
             :cross_retry,
             :cross_both,
             :branch_valid,
             :branch_pathlen,
             :branch_name_constraint,
             :branch_critical
           ] ->
        "partial-" <> (value |> Atom.to_string() |> String.replace("_", "-")) <> ".pem"

      _ ->
        "intermediate.pem"
    end
  end

  defp trusted_certificates(scenario, branch, intermediate, root, other) do
    cond do
      scenario == :trust_i_nocallback -> [intermediate]
      scenario == :missing_i -> [intermediate, root]
      scenario in [:known_choose_i, :known_unknown, :misordered, :duplicate] or branch -> [root]
      scenario in [:cross_retry, :cross_both] -> [root, other]
      true -> []
    end
  end

  defp select_partial_anchor(scenario, intermediate, other, leaf) do
    case scenario do
      value
      when value in [:known_choose_i, :bad_signature, :expired, :wrong_eku, :unknown_critical] ->
        {:trusted_ca, intermediate}

      :unrelated ->
        {:trusted_ca, other}

      :exit ->
        exit(:private_r49_callback)

      :improper ->
        [:trusted_ca | intermediate]

      value when value in [:selfsigned, :selfsigned_override] ->
        {:trusted_ca, leaf}

      _ ->
        :unknown_ca
    end
  end

  defp branch_trace(scenario) do
    case scenario do
      :branch_valid ->
        {[["root", "branch-a-valid", "branch-b", "leaf"]],
         [{"branch-a-valid", :valid, 0}, {"branch-b", :valid, 1}, {"leaf", :valid_peer, 2}]}

      :branch_pathlen ->
        {[["root", "branch-a", "branch-b", "leaf"]],
         [
           {"branch-a", :valid, 0},
           {"branch-b", :valid, 1},
           {"leaf", :max_path_length_reached, 2}
         ]}

      :branch_name_constraint ->
        {[["root", "branch-a-name-constraint", "branch-b", "leaf"]],
         [
           {"branch-a-name-constraint", :valid, 0},
           {"branch-b", :valid, 1},
           {"leaf", :name_not_permitted, 2}
         ]}

      :branch_critical ->
        {[["root", "branch-a-critical", "branch-b", "leaf"]], []}
    end
  end
end

defmodule SSL.PartialSelectionControlsIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {{good, revoked}, []}) do
    if Process.get({__MODULE__, :count}, 0) == 2, do: [good], else: [revoked]
  end

  def select(_, reference), do: lookup(nil, nil, reference)
  def fresh_crl(_, current), do: current

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      scenario <- [:cache, :fuel_zero, :fuel_one, :fuel_two] do
    test "#{version} #{route} #{scenario} selections precede policy with one shared budget", %{
      directory: base
    } do
      selection_case(base, unquote(version), unquote(route), unquote(scenario))
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      trigger <- [:cancel, :deadline] do
    test "#{version} #{route} blocked partial selection honors #{trigger} before another candidate",
         %{directory: base} do
      cutoff_case(base, unquote(version), unquote(route), unquote(trigger))
    end
  end

  defp selection_case(base, version, route, scenario) do
    owner = self()
    ref = make_ref()

    partial = fn _ ->
      count = Process.get({__MODULE__, :count}, 0) + 1
      Process.put({__MODULE__, :count}, count)
      send(owner, {ref, :partial, count})

      if count == 1 and scenario != :cache do
        left =
          case scenario do
            :fuel_zero -> 0
            :fuel_one -> 1
            :fuel_two -> 2
          end

        :ok = SSL.PolicyIO.charge(:paths, SSL.PolicyIO.path_budget() - left, 4_096)
      end

      :unknown_ca
    end

    verify = fn _, event, state ->
      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, _} ->
          send(owner, {ref, :verify, event})
          {:fail, :rejected}

        _ ->
          send(owner, {ref, :verify, event})
          {:valid, state}
      end
    end

    read = fn name -> File.read!(Path.join(base, name)) end

    options =
      RevocationFixtures.options(base, version)
      |> Keyword.put(:cacerts, [read.("root.der"), read.("other-root.der")])

    options = options ++ [partial_chain: partial, verify_fun: {verify, nil}]

    options =
      if scenario == :cache,
        do:
          options ++
            [
              crl_check: :peer,
              crl_cache:
                {__MODULE__, {{read.("leaf-good.crl.der"), read.("leaf-revoked.crl.der")}, []}}
            ],
        else: options

    peer = RevocationPeer.start(base, version, ["-cert_chain", "partial-cross-both.pem"])
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      result = connect(peer.port, options, route, handle, lease, 5_000)

      if scenario == :fuel_zero do
        assert {:error, {:tls_alert, _}} = result
        assert collect(ref, []) == [{:partial, 1}]
      else
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        body = read.("root.der")
        bytes = receive_body(socket, <<>>, byte_size(body))
        assert [_, ^body] = :binary.split(bytes, "\r\n\r\n")
        assert :ok = SSL.close(socket)

        assert collect(ref, []) == [
                 {:partial, 1},
                 {:partial, 2},
                 {:verify, :valid},
                 {:verify, :valid_peer}
               ]
      end

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: mask, observed_down: mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      assert mask == if(route == :direct, do: 31, else: 30)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
  end

  defp cutoff_case(base, version, route, trigger) do
    owner = self()
    ref = make_ref()

    partial = fn _ ->
      send(owner, {ref, :entered, self()})

      receive do
        {^ref, :release} -> :unknown_ca
      end
    end

    verify = fn _, event, state ->
      send(owner, {ref, :unexpected_verify, event})
      {:valid, state}
    end

    options = RevocationFixtures.options(base, version)

    options =
      Keyword.update!(options, :cacerts, &(&1 ++ [File.read!(Path.join(base, "other-root.der"))])) ++
        [partial_chain: partial, verify_fun: {verify, nil}]

    peer = RevocationPeer.start(base, version, ["-cert_chain", "partial-cross-both.pem"])
    setup_deadline = if trigger == :deadline, do: deadline(3_000), else: :infinity
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: setup_deadline)
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)
    caller = Task.async(fn -> connect(peer.port, options, route, handle, lease, :infinity) end)

    try do
      assert_receive {^ref, :entered, connection}, 1_000
      monitor = Process.monitor(connection)
      mask = if route == :direct, do: 31, else: 30
      assert {:pending, %{roles: ^mask, cleanup: :pending}} = SSL.Lifecycle.status(handle)
      assert Task.yield(caller, 0) == nil

      cutoff =
        case trigger do
          :cancel ->
            assert :ok = SSL.Lifecycle.cancel(lease, deadline(1_000))
            System.monotonic_time(:millisecond) + 1_000

          :deadline ->
            {:abs_ms, expiry} = setup_deadline
            assert System.monotonic_time(:millisecond) < expiry
            expiry + 1_000
        end

      expected_reason = if trigger == :deadline, do: :timeout, else: :closed

      assert {:error, ^expected_reason} =
               Task.await(caller, max(0, cutoff - System.monotonic_time(:millisecond)))

      assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 500
      assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 500
      failure = if trigger == :cancel, do: :cancelled, else: :timeout
      scope = if route == :direct, do: :dial, else: :upgrade

      assert {:ok,
              %{
                version: 1,
                scope: ^scope,
                setup: :cancelled,
                setup_failure: ^failure,
                logical: :closed,
                cleanup: :confirmed,
                roles: ^mask,
                observed_down: ^mask,
                losses: 0,
                epoch: 0
              }} =
               SSL.Lifecycle.await(handle, {:abs_ms, cutoff})

      refute_receive {^ref, :entered, _}, 0
      refute_receive {^ref, :unexpected_verify, _}, 0
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
      RevocationPeer.stop(peer)
    end
  end

  defp connect(port, options, :direct, handle, lease, timeout),
    do:
      SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], timeout)

  defp connect(port, options, :prepared, handle, lease, timeout) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1_000)
    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], timeout)
  end

  defp receive_body(socket, bytes, expected) do
    assert byte_size(bytes) <= expected + 8_192

    case :binary.split(bytes, "\r\n\r\n") do
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, more} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> more, expected)
    end
  end

  defp collect(ref, acc) do
    receive do
      {^ref, kind, event} -> collect(ref, [{kind, event} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.PartialChainWireIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for route <- [:direct, :prepared],
      anchor <- [:intermediate, :leaf],
      scenario <- [:good, :cv, :finished, :aead, :sni_other, :origin_other] do
    test "TLS13 #{route} selected #{anchor} preserves #{scenario} authentication" do
      run_case(unquote(route), unquote(anchor), unquote(scenario))
    end
  end

  defp run_case(route, anchor, scenario) do
    directory = RevocationFixtures.directory!()
    intermediate = File.read!(Path.join(directory, "intermediate.der"))
    leaf = File.read!(Path.join(directory, "leaf.der"))
    selected = if anchor == :leaf, do: leaf, else: intermediate
    owner = self()
    reference = make_ref()

    partial = fn path ->
      send(owner, {reference, :partial, path})
      {:trusted_ca, selected}
    end

    verify = fn _, event, state ->
      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, _} ->
          send(owner, {reference, :verify, event, state})
          {:fail, :rejected}

        _ ->
          send(owner, {reference, :verify, event, state})
          {:valid, state + 1}
      end
    end

    options =
      RevocationFixtures.options(directory, :"tlsv1.3")
      |> Keyword.put(:cacerts, [])
      |> Keyword.put(:partial_chain, partial)
      |> Keyword.put(:verify_fun, {verify, 0})

    sni = if scenario == :sni_other, do: "wire-only.example", else: "r49.example"
    origin = if scenario == :origin_other, do: "wrong-origin.example", else: "r49.example"
    options = Keyword.put(options, :server_name_indication, String.to_charlist(sni))
    peer = RevocationPeer.start_tls13(directory, placement: :absent, corrupt: scenario)
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
    ex_ssl = [reference_identity: {:dns_id, origin}]

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: ex_ssl ++ [lifecycle: {handle, lease}]],
              5_000
            )

          :prepared ->
            {:ok, prepared} = SSL.prepare_upgrade(options ++ [ex_ssl: ex_ssl])

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
        end

      assert_exchange(scenario, result, anchor)

      assert_receive {^reference, :partial, [^intermediate, ^leaf]}, 500
      refute_receive {^reference, :partial, _}, 0

      assert_verify_events(anchor, scenario, reference)

      assert %{result: peer_result, status_request_count: 0, sni_extension: {0, encoded}} =
               RevocationPeer.join_tls13(peer)

      assert encoded == <<byte_size(sni) + 3::16, 0, byte_size(sni)::16, sni::binary>>

      if scenario in [:good, :sni_other],
        do: assert(peer_result == :authenticated),
        else: assert(match?({:rejected, _}, peer_result) or peer_result == :client_closed)

      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp assert_exchange(scenario, result, anchor) do
    if scenario in [:good, :sni_other] do
      assert {:ok, socket} = result
      assert :ok = SSL.send(socket, "R49 ping")
      assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
      assert :ok = SSL.close(socket)
    else
      assert {:error, {:tls_alert, {alert, _}}} = result

      case scenario do
        value when value in [:cv, :finished] ->
          assert alert == :decrypt_error

        :aead ->
          assert alert == :bad_record_mac

        :origin_other ->
          assert alert == if(anchor == :leaf, do: :certificate_unknown, else: :unknown_ca)
      end
    end
  end

  defp assert_verify_events(anchor, scenario, reference) do
    if anchor == :intermediate and scenario != :origin_other do
      assert_receive {^reference, :verify, :valid_peer, 0}, 500
    end

    if scenario == :origin_other and anchor == :intermediate do
      assert_receive {^reference, :verify, {:bad_cert, :hostname_check_failed}, 0}, 500
    end

    refute_receive {^reference, :verify, _, _}, 0
  end
end

defmodule SSL.PartialChainBoundsIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for route <- [:direct, :prepared], count <- [15, 16, 17] do
    test "TLS13 #{route} certificate count #{count} bounds precede partial callback" do
      directory = RevocationFixtures.directory!()
      intermediate = File.read!(Path.join(directory, "intermediate.der"))
      leaf = File.read!(Path.join(directory, "leaf.der"))
      owner = self()
      ref = make_ref()

      partial = fn path ->
        send(owner, {ref, path})
        {:trusted_ca, intermediate}
      end

      options =
        RevocationFixtures.options(directory, :"tlsv1.3")
        |> Keyword.put(:cacerts, [])
        |> Keyword.put(:partial_chain, partial)

      peer =
        RevocationPeer.start_tls13(directory, placement: :absent, chain_length: unquote(count))

      {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

      try do
        result = connect(peer.port, options, unquote(route), {handle, lease})
        count = unquote(count)

        if count <= 16 do
          assert {:ok, socket} = result
          assert_receive {^ref, [^intermediate, ^leaf]}, 500
          assert :ok = SSL.send(socket, "R49 ping")
          assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
          assert :ok = SSL.close(socket)
        else
          assert {:error, {:tls_alert, _}} = result
        end

        refute_receive {^ref, _}, 0
        assert %{result: peer_result} = RevocationPeer.join_tls13(peer)

        if count <= 16,
          do: assert(peer_result == :authenticated),
          else: assert(match?({:rejected, _}, peer_result) or peer_result == :client_closed)

        settled(handle, unquote(route))
      after
        SSL.Lifecycle.cancel(lease, deadline(500))
        RevocationPeer.stop(peer)
      end
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"], route <- [:direct, :prepared], depth <- [0, 1, 2] do
    test "#{version} #{route} selected intermediate A depth=#{depth} still bounds subordinate CA B" do
      directory = RevocationFixtures.directory!()
      read = fn name -> File.read!(Path.join(directory, name <> ".der")) end
      root = read.("root")
      anchor = read.("branch-a-valid")
      subordinate = read.("branch-b")
      leaf = read.("leaf-branch")
      owner = self()
      ref = make_ref()

      partial = fn path ->
        send(owner, {ref, :path, path})
        {:trusted_ca, anchor}
      end

      verify = fn _, event, state ->
        case event do
          {:extension, _} ->
            {:unknown, state}

          {:bad_cert, reason} ->
            send(owner, {ref, :bad_cert, reason})
            {:fail, :rejected}

          _ ->
            {:valid, state}
        end
      end

      options =
        RevocationFixtures.options(directory, unquote(version)) ++
          [depth: unquote(depth), partial_chain: partial, verify_fun: {verify, nil}]

      peer =
        RevocationPeer.start(directory, unquote(version), [
          "-cert",
          "leaf-branch.pem",
          "-cert_chain",
          "partial-branch-valid.pem"
        ])

      {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

      try do
        result = connect(peer.port, options, unquote(route), {handle, lease})
        assert_receive {^ref, :path, [^root, ^anchor, ^subordinate, ^leaf]}, 500
        refute_receive {^ref, :path, _}, 0

        if unquote(depth) < 2 do
          assert {:error, {:tls_alert, _}} = result

          expected =
            if unquote(depth) == 0,
              do: :max_path_length_reached,
              else: {:policy_requirement_not_met, {{:explicit_policy, 0}, {:policy_set, []}}}

          # OTP28 public_key also reports this exact policy boundary for a
          # non-self-signed selected A; preserve its validator semantics.
          assert_receive {^ref, :bad_cert, ^expected}, 500
        else
          assert {:ok, socket} = result
          assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
          bytes = receive_body(socket, <<>>, byte_size(root))
          assert [header, ^root] = :binary.split(bytes, "\r\n\r\n")
          assert header =~ "HTTP/1.0 200"
          assert :ok = SSL.close(socket)
          refute_receive {^ref, :bad_cert, _}, 0
        end

        settled(handle, unquote(route))
      after
        SSL.Lifecycle.cancel(lease, deadline(500))
        RevocationPeer.stop(peer)
      end
    end
  end

  defp connect(port, options, :direct, lifecycle),
    do: SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: lifecycle]], 5_000)

  defp connect(port, options, :prepared, lifecycle) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000)
  end

  defp settled(handle, route) do
    mask = if route == :direct, do: 31, else: 30

    assert {:ok,
            %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
             SSL.Lifecycle.await(handle, deadline(2_000))
  end

  defp receive_body(socket, bytes, expected) do
    assert byte_size(bytes) <= expected + 8_192

    case :binary.split(bytes, "\r\n\r\n") do
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, part} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> part, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.PartialBelowAnchorIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      scenario <- [:valid, :name_constraint, :critical, :pathlen, :pathlen_valid] do
    test "#{version} #{route} #{scenario} constraints below selected exact A", %{
      directory: directory
    } do
      run_case(directory, unquote(version), unquote(route), unquote(scenario))
    end
  end

  defp run_case(directory, version, route, scenario) do
    read = fn name -> File.read!(Path.join(directory, name <> ".der")) end
    root = read.("root")
    anchor = read.("branch-a-valid")
    deep = scenario in [:pathlen, :pathlen_valid]
    leaf_name = if deep, do: "leaf-below-c", else: "leaf-branch"

    b_name = branch_name(scenario)

    expected_path =
      [root, anchor, read.(b_name)] ++
        if(deep, do: [read.("branch-c")], else: []) ++ [read.(leaf_name)]

    owner = self()
    ref = make_ref()

    partial = fn path ->
      send(owner, {ref, :path, path})
      {:trusted_ca, anchor}
    end

    verify = fn _, event, state ->
      case event do
        {:extension, {:Extension, {1, 2, 3, 4, 999}, true, <<5, 0>>}} ->
          send(owner, {ref, :critical_extension})
          {:unknown, state}

        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, reason} ->
          send(owner, {ref, :bad_cert, reason})
          {:fail, :rejected}

        _ ->
          {:valid, state}
      end
    end

    options =
      RevocationFixtures.options(directory, version) ++
        [partial_chain: partial, verify_fun: {verify, nil}]

    chain =
      "below-anchor-" <> (scenario |> Atom.to_string() |> String.replace("_", "-")) <> ".pem"

    peer =
      RevocationPeer.start(directory, version, [
        "-cert",
        leaf_name <> ".pem",
        "-cert_chain",
        chain
      ])

    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      result = connect(peer.port, options, route, {handle, lease})
      assert_receive {^ref, :path, ^expected_path}, 500
      refute_receive {^ref, :path, _}, 0

      if scenario in [:valid, :pathlen_valid] do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        bytes = receive_body(socket, <<>>, byte_size(root))
        assert [header, ^root] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
        refute_receive {^ref, :bad_cert, _}, 0
      else
        if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
        assert {:error, {:tls_alert, _}} = result

        if scenario == :critical do
          # public_key rejects an unhandled critical extension directly; it
          # does not synthesize a subsequent bad_cert callback for that event.
          assert_receive {^ref, :critical_extension}, 500
          refute_receive {^ref, :critical_extension}, 0
        else
          expected =
            if scenario == :name_constraint,
              do: :name_not_permitted,
              else: :max_path_length_reached

          assert_receive {^ref, :bad_cert, ^expected}, 500
        end

        refute_receive {^ref, :bad_cert, _}, 0
      end

      settled(handle, route)
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp connect(port, options, :direct, lifecycle),
    do: SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: lifecycle]], 5_000)

  defp connect(port, options, :prepared, lifecycle) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000)
  end

  defp settled(handle, route) do
    mask = if route == :direct, do: 31, else: 30

    assert {:ok,
            %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
             SSL.Lifecycle.await(handle, deadline(2_000))
  end

  defp receive_body(socket, bytes, expected) do
    assert byte_size(bytes) <= expected + 8_192

    case :binary.split(bytes, "\r\n\r\n") do
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, part} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> part, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp branch_name(scenario) do
    case scenario do
      :name_constraint -> "branch-b-name-constraint"
      :critical -> "branch-b-critical"
      :pathlen_valid -> "branch-b-depth1"
      _ -> "branch-b"
    end
  end
end

defmodule SSL.AdvancedPolicyTicketIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  def lookup(_, _, {{owner, ref, table}, []}) do
    send(owner, {ref, :lookup})
    [{:crl, crl}] = :ets.lookup(table, :crl)
    [crl]
  end

  def select(_, _), do: []
  def fresh_crl(_, current), do: current

  for route <- [:direct, :prepared], kind <- [:partial, :crl, :ocsp] do
    test "#{route} #{kind} two full policy handshakes ignore an available real TLS13 ticket" do
      run_case(unquote(route), unquote(kind))
    end
  end

  defp run_case(route, kind) do
    base = RevocationFixtures.directory!()
    read = fn name -> File.read!(Path.join(base, name <> ".der")) end
    options = RevocationFixtures.options(base, :"tlsv1.3") ++ [session_tickets: :auto]
    first = RevocationPeer.start_tls13(base, placement: :absent, ticket: true)
    port = first.port

    try do
      assert %{result: :authenticated, extension_ids: ids} =
               handshake(first, options, route, true)

      refute 41 in ids
    after
      RevocationPeer.stop(first)
    end

    host = if route == :direct, do: ~c"127.0.0.1", else: :upgrade
    {:ok, normalized} = SSL.Options.normalize(host, options)
    partition = SSL.ResumptionContext.partition(normalized, {{127, 0, 0, 1}, port})
    assert {:ok, ticket} = SSL.TicketCache.checkout(partition)
    assert :ok = SSL.SessionTicket.validate(ticket)
    assert byte_size(ticket.psk) == 32
    owner = self()
    ref = make_ref()
    table = :ets.new(:policy_ticket_state, [:public, :set])

    partial = fn path ->
      send(owner, {ref, :partial, path})
      [{:anchor, anchor}] = :ets.lookup(table, :anchor)
      {:trusted_ca, anchor}
    end

    policy = ticket_policy(kind, partial, owner, ref, table)

    options = options ++ policy
    {:ok, normalized_policy} = SSL.Options.normalize(host, options)
    assert normalized_policy.session_tickets == :auto
    policy_partition = SSL.ResumptionContext.partition(normalized_policy, {{127, 0, 0, 1}, port})

    prepared =
      if route == :prepared do
        {:ok, prepared} = SSL.prepare_upgrade(options)
        prepared
      end

    try do
      for attempt <- [1, 2] do
        anchor = if attempt == 1, do: read.("intermediate"), else: read.("leaf")
        :ets.insert(table, {:anchor, anchor})
        crl = if attempt == 1, do: "leaf-good.crl", else: "leaf-revoked.crl"
        :ets.insert(table, {:crl, read.(crl)})
        assert :ok = SSL.TicketCache.put(policy_partition, ticket)

        response =
          File.read!(
            Path.join(
              RevocationFixtures.ocsp_directory!(),
              if(attempt == 1, do: "good.ocsp", else: "revoked.ocsp")
            )
          )

        peer =
          RevocationPeer.start_tls13(base,
            port: port,
            placement: if(kind == :ocsp, do: :leaf, else: :absent),
            response: response
          )

        try do
          accepted = kind == :partial or attempt == 1
          observed = handshake(peer, options, route, accepted, prepared)
          refute 41 in observed.extension_ids
          assert observed.status_request_count == if(kind == :ocsp, do: 1, else: 0)
          assert {:ok, ^ticket} = SSL.TicketCache.checkout(policy_partition)

          if kind == :partial do
            assert_receive {^ref, :partial, [_root, _intermediate, _leaf]}, 500
            refute_receive {^ref, :partial, _}, 0
          end

          if kind == :crl do
            assert_receive {^ref, :lookup}, 500
            refute_receive {^ref, :lookup}, 0
          end
        after
          RevocationPeer.stop(peer)
        end
      end
    after
      :ets.delete(table)
      SSL.TicketCache.checkout(policy_partition)
    end
  end

  defp handshake(peer, options, route, accepted, prepared \\ nil) do
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              5_000
            )

          :prepared ->
            prepared =
              if prepared do
                prepared
              else
                {:ok, value} = SSL.prepare_upgrade(options)
                value
              end

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
        end

      if accepted do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "R49 ping")
        assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
        assert :ok = SSL.close(socket)
      else
        if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
        assert {:error, {:tls_alert, _}} = result
      end

      assert %{result: peer_result} = observed = RevocationPeer.join_tls13(peer)

      if accepted,
        do: assert(peer_result == :authenticated),
        else: assert(match?({:rejected, _}, peer_result))

      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      observed
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp ticket_policy(kind, partial, owner, ref, table) do
    case kind do
      :partial -> [partial_chain: partial]
      :crl -> [crl_check: :peer, crl_cache: {__MODULE__, {{owner, ref, table}, []}}]
      :ocsp -> [stapling: :staple]
    end
  end
end

defmodule SSL.PartialCertificateSizeIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      size <- [262_143, 262_144, 262_145] do
    test "#{version} #{route} signed certificate DER boundary #{size}" do
      run_case(unquote(version), unquote(route), unquote(size))
    end
  end

  defp run_case(version, route, size) do
    base = RevocationFixtures.directory!()
    leaf = File.read!(Path.join(base, "leaf.der"))
    issuer = File.read!(Path.join(base, "intermediate.der"))
    root = File.read!(Path.join(base, "root.der"))
    [entry] = :public_key.pem_decode(File.read!(Path.join(base, "intermediate-key.pem")))
    key = :public_key.pem_entry_decode(entry)
    tbs = :public_key.pkix_decode_cert(leaf, :otp) |> elem(1)

    der =
      Enum.reduce_while(0..3, 0, fn _, padding ->
        extensions =
          elem(tbs, 10) ++ [{:Extension, {1, 2, 3, 4, 998}, false, :binary.copy(<<42>>, padding)}]

        signed = :public_key.pkix_sign(put_elem(tbs, 10, extensions), key)

        if byte_size(signed) == size,
          do: {:halt, signed},
          else: {:cont, padding + size - byte_size(signed)}
      end)

    assert is_binary(der) and byte_size(der) == size
    issuer_decoded = :public_key.pkix_decode_cert(issuer, :otp)
    assert {:ok, _} = :public_key.pkix_path_validation(issuer_decoded, [der], [])
    path = Path.join(base, "padded-#{version}-#{route}-#{size}.pem")
    File.write!(path, :public_key.pem_encode([{:Certificate, der, :not_encrypted}]))
    on_exit(fn -> File.rm(path) end)
    owner = self()
    ref = make_ref()

    partial = fn chain ->
      send(owner, {ref, chain})
      {:trusted_ca, issuer}
    end

    options =
      RevocationFixtures.options(base, version)
      |> Keyword.put(:cacerts, [])
      |> Keyword.put(:partial_chain, partial)

    peer = RevocationPeer.start(base, version, ["-cert", path])
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              5_000
            )

          :prepared ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
        end

      if size <= 262_144 do
        assert {:ok, socket} = result
        assert_receive {^ref, [^issuer, ^der]}, 500
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        bytes = receive_body(socket, <<>>, byte_size(root))
        assert [header, ^root] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      else
        if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
        assert {:error, {:tls_alert, _}} = result
      end

      refute_receive {^ref, _}, 0
      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp receive_body(socket, bytes, expected) do
    case :binary.split(bytes, "\r\n\r\n") do
      [_header, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, next} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> next, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.PartialCandidateCapacityIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias SSL.PKIX.PartialChain

  alias ExSSL.TestSupport.RevocationFixtures

  setup_all do
    base = RevocationFixtures.directory!()
    root = File.read!(Path.join(base, "root.der"))
    issuer = File.read!(Path.join(base, "intermediate.der"))
    [entry] = :public_key.pem_decode(File.read!(Path.join(base, "root-key.pem")))
    key = :public_key.pem_entry_decode(entry)
    tbs = :public_key.pkix_decode_cert(root, :otp) |> elem(1)

    roots =
      for serial <- 1..4_096, do: :public_key.pkix_sign(put_elem(tbs, 2, 10_000 + serial), key)

    {:ok, decoded} = SSL.PKIX.decode_chain([issuer])

    anchors =
      Enum.map(roots, fn der ->
        certificate = :public_key.pkix_decode_cert(der, :otp)
        assert :public_key.pkix_is_self_signed(certificate)
        %{der: der, decoded: certificate}
      end)

    {:ok, chain: decoded, anchors: anchors}
  end

  for visits <- [4_095, 4_096, 4_097] do
    test "candidate expansion consumes exactly #{visits} signed certificate nodes", %{
      chain: chain,
      anchors: anchors
    } do
      count = unquote(visits)
      selected = Enum.take(anchors, count - 1)
      result = PartialChain.candidates(chain, selected)

      if count <= 4_096 do
        assert {:ok, paths} = result
        assert length(paths) == count - 1
        assert Enum.map(paths, fn {anchor, _} -> anchor.der end) == Enum.map(selected, & &1.der)
        assert Enum.all?(paths, fn {_, path} -> path == chain end)
      else
        assert {:error, :policy_capacity} = result
      end
    end
  end
end

defmodule SSL.PartialOriginRoutesIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      anchor <- [:leaf, :intermediate],
      scenario <- [:dns_sni_differs, :wrong_dns, :ip_positive, :wrong_ip] do
    test "#{version} #{route} selected #{anchor} pinned dial and #{scenario}" do
      run_case(unquote(version), unquote(route), unquote(anchor), unquote(scenario))
    end
  end

  defp run_case(version, route, anchor, scenario) do
    base = RevocationFixtures.directory!()
    variants = RevocationFixtures.leaf_variants!()
    ip? = scenario in [:ip_positive, :wrong_ip]

    leaf =
      File.read!(
        Path.join(if(ip?, do: variants, else: base), if(ip?, do: "ip-san.der", else: "leaf.der"))
      )

    issuer = File.read!(Path.join(base, "intermediate.der"))
    root = File.read!(Path.join(base, "root.der"))
    selected = if anchor == :leaf, do: leaf, else: issuer
    owner = self()
    ref = make_ref()

    partial = fn chain ->
      send(owner, {ref, :partial, chain})
      {:trusted_ca, selected}
    end

    verify = fn _, event, state ->
      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, _} ->
          send(owner, {ref, :verify, event, state})
          {:fail, :rejected}

        _ ->
          send(owner, {ref, :verify, event, state})
          {:valid, state + 1}
      end
    end

    identity = reference_identity(scenario)

    # The TCP destination remains pinned to127.0.0.1. SNI is intentionally
    # unrelated to the independently checked DNS/IP origin in every cell.
    options =
      RevocationFixtures.options(base, version)
      |> Keyword.put(:cacerts, [])
      |> Keyword.put(:server_name_indication, ~c"wire-only.example")
      |> Keyword.put(:partial_chain, partial)
      |> Keyword.put(:verify_fun, {verify, 0})
      |> Keyword.put(:ex_ssl, reference_identity: identity)

    peer =
      RevocationPeer.start(
        base,
        version,
        if(ip?, do: ["-cert", Path.join(variants, "ip-san.pem")], else: [])
      )

    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              Keyword.update!(options, :ex_ssl, &(&1 ++ [lifecycle: {handle, lease}])),
              5_000
            )

          :prepared ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
        end

      assert_receive {^ref, :partial, [^issuer, ^leaf]}, 500
      refute_receive {^ref, :partial, _}, 0
      positive = scenario in [:dns_sni_differs, :ip_positive]

      assert_exchange(positive, result, root)

      if anchor == :intermediate do
        if positive,
          do: assert_receive({^ref, :verify, :valid_peer, 0}, 500),
          else: assert_receive({^ref, :verify, {:bad_cert, :hostname_check_failed}, 0}, 500)
      end

      refute_receive {^ref, :verify, _, _}, 0
      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp receive_body(socket, bytes, expected) do
    case :binary.split(bytes, "\r\n\r\n") do
      [_header, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, next} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> next, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp reference_identity(scenario) do
    case scenario do
      :dns_sni_differs -> {:dns_id, "r49.example"}
      :wrong_dns -> {:dns_id, "wrong-origin.example"}
      :ip_positive -> {:ip, {127, 0, 0, 1}}
      :wrong_ip -> {:ip, {127, 0, 0, 2}}
    end
  end

  defp assert_exchange(positive, result, root) do
    if positive do
      assert {:ok, socket} = result
      assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
      bytes = receive_body(socket, <<>>, byte_size(root))
      assert [header, ^root] = :binary.split(bytes, "\r\n\r\n")
      assert header =~ "HTTP/1.0 200"
      assert :ok = SSL.close(socket)
    else
      if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
      assert {:error, {:tls_alert, _}} = result
    end
  end
end
