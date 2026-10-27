defmodule SSL.RevocationPolicyIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      managed <- [false, true] do
    test "#{version} #{route} managed=#{managed} good hash-directory CRLs authenticate and settle",
         %{directory: directory} do
      version = unquote(version)
      peer = RevocationPeer.start(directory, version)

      options =
        RevocationFixtures.options(directory, version) ++
          [
            crl_check: true,
            crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: Path.join(directory, "good")]}}
          ]

      lifecycle = lifecycle(unquote(managed))

      try do
        assert {:ok, socket} = connect(peer.port, options, unquote(route), lifecycle)
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        assert {:ok, response} = SSL.recv(socket, 0, 2_000)
        assert response =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
        check_settled(lifecycle, unquote(route))
      after
        RevocationPeer.stop(peer)
        cancel(lifecycle)
      end
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      mode <- [false, true, :peer, :best_effort],
      fixture <- ["good", "revoked", "intermediate-revoked", "missing"] do
    test "#{version} crl_check=#{mode} #{fixture} has the authenticated expected result", %{
      directory: directory
    } do
      check_variant(directory, unquote(version), unquote(mode), unquote(fixture))
    end
  end

  defp check_variant(directory, version, mode, fixture) do
    parent = self()
    reference = make_ref()

    verify = fn _, event, state ->
      send(parent, {reference, event})

      case event do
        {:bad_cert, _} -> {:fail, :policy_rejected}
        {:extension, _} -> {:unknown, state}
        _ -> {:valid, state}
      end
    end

    peer = RevocationPeer.start(directory, version)

    options =
      RevocationFixtures.options(directory, version) ++
        [
          verify_fun: {verify, nil},
          crl_check: mode,
          crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: Path.join(directory, fixture)]}}
        ]

    lifecycle = lifecycle(true)

    accepted =
      mode == false or fixture == "good" or
        (fixture == "intermediate-revoked" and mode == :peer) or
        (fixture == "missing" and mode == :best_effort)

    try do
      result = connect(peer.port, options, :direct, lifecycle)

      assert_exchange(accepted, result, fixture, reference, directory)

      {handle, _} = lifecycle
      assert {:ok, receipt} = SSL.Lifecycle.await(handle, deadline(2_000))
      assert receipt.cleanup == :confirmed
      assert receipt.roles == 31 and receipt.observed_down == 31 and receipt.losses == 0

      if mode == false do
        assert receipt.version == 1
        refute Map.has_key?(receipt, :auxiliary)
      else
        assert receipt.version == 2
        assert receipt.auxiliary == %{roles: 2, observed_down: 2, losses: 0}
      end
    after
      RevocationPeer.stop(peer)
      cancel(lifecycle)
    end
  end

  defp lifecycle(false), do: nil

  defp lifecycle(true) do
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
    {handle, lease}
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
  defp connect(port, options, :direct, nil), do: SSL.connect(~c"127.0.0.1", port, options, 5_000)

  defp connect(port, options, :direct, lifecycle),
    do: SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: lifecycle]], 5_000)

  defp connect(port, options, :prepared, lifecycle) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)

    if lifecycle,
      do: SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000),
      else: SSL.connect_prepared(tcp, prepared, 5_000)
  end

  defp check_settled(nil, _), do: :ok

  defp check_settled({handle, _}, route) do
    assert {:ok, receipt} = SSL.Lifecycle.await(handle, deadline(2_000))

    assert %{
             version: 2,
             cleanup: :confirmed,
             roles: mask,
             observed_down: mask,
             losses: 0,
             auxiliary: %{roles: 2, observed_down: 2, losses: 0}
           } = receipt

    assert mask == if(route == :direct, do: 31, else: 30)
  end

  defp cancel(nil), do: :ok
  defp cancel({_, lease}), do: SSL.Lifecycle.cancel(lease, deadline(500))

  defp assert_exchange(accepted, result, fixture, reference, directory) do
    if accepted do
      assert {:ok, socket} = result
      assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
      assert {:ok, response} = SSL.recv(socket, 0, 2_000)
      assert response =~ "HTTP/1.0 200"
      assert :ok = SSL.close(socket)
    else
      assert {:error, {:tls_alert, _}} = result

      if fixture == "missing" do
        assert_receive {^reference, {:bad_cert, :revocation_status_undetermined}}, 500
      else
        expected_reason =
          if fixture == "revoked", do: :keyCompromise, else: :cessationOfOperation

        assert_receive {^reference, {:bad_cert, {:revoked, ^expected_reason}}}, 500
      end

      refute inspect(result) =~ directory
    end
  end
end

defmodule SSL.RevocationHTTPIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      framing <- [:der, :pem, :chunked, :redirect, :disabled, :malformed, :oversize_header] do
    test "#{version} #{route} owned HTTP CRL #{framing}", %{directory: directory} do
      http_case(directory, unquote(version), unquote(route), unquote(framing))
    end
  end

  defp http_case(directory, version, route, framing) do
    root_crl = File.read!(Path.join(directory, "root-good.crl.der"))
    leaf_crl = File.read!(Path.join(directory, "leaf-good.crl.der"))
    leaf_pem = File.read!(Path.join(directory, "leaf-good.crl.pem"))
    assert :ok = SSL.CRLCache.insert({:der, [root_crl]})

    payloads = http_payloads(framing, leaf_crl, leaf_pem)

    {:ok, listener} =
      :gen_tcp.listen(18_749, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    server =
      Task.async(fn ->
        try do
          if payloads == [] do
            assert {:error, :timeout} = :gen_tcp.accept(listener, 300)
            []
          else
            for response <- payloads do
              assert {:ok, socket} = :gen_tcp.accept(listener, 2_000)

              try do
                assert {:ok, request} = :gen_tcp.recv(socket, 0, 2_000)
                assert request =~ "GET /"
                assert :ok = :gen_tcp.send(socket, response)
                request |> String.split("\r\n") |> hd()
              after
                :gen_tcp.close(socket)
              end
            end
          end
        after
          :gen_tcp.close(listener)
        end
      end)

    peer = RevocationPeer.start(directory, version)
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
    http_options = if framing == :disabled, do: [], else: [http: 1_000]

    options =
      RevocationFixtures.options(directory, version) ++
        [crl_check: true, crl_cache: {:ssl_crl_cache, {:internal, http_options}}]

    try do
      result = connect(peer.port, options, route, {handle, lease})

      if framing in [:der, :pem, :chunked, :redirect] do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        assert {:ok, response} = SSL.recv(socket, 0, 2_000)
        assert response =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
      end

      requests = Task.await(server, 3_000)
      assert length(requests) == length(payloads)

      if framing == :redirect,
        do: assert(requests == ["GET /leaf.crl HTTP/1.1", "GET /next.crl HTTP/1.1"])

      assert {:ok, receipt} = SSL.Lifecycle.await(handle, deadline(2_000))
      assert receipt.cleanup == :confirmed and receipt.losses == 0
      expected_primary = if route == :direct, do: 31, else: 30
      assert receipt.roles == expected_primary and receipt.observed_down == expected_primary

      if framing == :disabled do
        assert receipt.version == 1
      else
        assert receipt.version == 2
        assert receipt.auxiliary == %{roles: 1, observed_down: 1, losses: 0}
      end
    after
      if Process.alive?(server.pid), do: Task.shutdown(server, :brutal_kill)
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
      assert :ok = SSL.CRLCache.delete({:der, [root_crl]})
    end
  end

  defp fixed(bytes), do: "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(bytes)}\r\n\r\n" <> bytes
  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp connect(port, options, :direct, lifecycle),
    do: SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: lifecycle]], 5_000)

  defp connect(port, options, :prepared, lifecycle) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000)
  end

  defp http_payloads(framing, leaf_crl, leaf_pem) do
    case framing do
      :der ->
        [fixed(leaf_crl)]

      :pem ->
        [fixed(leaf_pem)]

      :chunked ->
        [
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" <>
            Integer.to_string(byte_size(leaf_crl), 16) <> "\r\n" <> leaf_crl <> "\r\n0\r\n\r\n"
        ]

      :redirect ->
        [
          "HTTP/1.1 302 Found\r\nLocation: /next.crl\r\nContent-Length: 0\r\n\r\n",
          fixed(leaf_crl)
        ]

      :disabled ->
        []

      :malformed ->
        [fixed("invalid policy material")]

      :oversize_header ->
        ["HTTP/1.1 200 OK\r\nPadding: " <> String.duplicate("x", 16_384) <> "\r\n\r\n"]
    end
  end
end

defmodule SSL.RevocationBufferedCloseIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      managed <- [false, true],
      policy <- [:none, :staple, :partial] do
    test "#{version} prepared lifecycle=#{managed} #{policy} drains authenticated data before terminal proof" do
      run_case(unquote(version), unquote(managed), unquote(policy))
    end
  end

  defp run_case(version, managed, policy) do
    directory = RevocationFixtures.directory!()

    extra =
      if policy == :staple,
        do: ["-status_file", Path.join(RevocationFixtures.ocsp_directory!(), "good.ocsp")],
        else: []

    peer = RevocationPeer.start(directory, version, extra)

    options =
      case policy do
        :none ->
          RevocationFixtures.options(directory, version)

        :staple ->
          RevocationFixtures.options(directory, version) ++ [stapling: :staple]

        :partial ->
          RevocationFixtures.options(directory, version) ++
            [partial_chain: fn _ -> :unknown_ca end]
      end

    lifecycle =
      if managed do
        {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
        {handle, lease}
      end

    try do
      {:ok, prepared} = SSL.prepare_upgrade(options)
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

      result =
        if lifecycle,
          do: SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000),
          else: SSL.connect_prepared(tcp, prepared, 5_000)

      assert {:ok, socket} = result

      try do
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        # The remote endpoint has actually exited and closed its TCP socket;
        # retaining plaintext cannot depend on keeping that peer endpoint open.
        assert :ok = RevocationPeer.await_exit(peer, 1_000)
        Process.sleep(20)

        if lifecycle do
          {handle, _} = lifecycle
          assert {:pending, %{observer: :alive}} = SSL.Lifecycle.await(handle, deadline(0))
        end

        expected = File.read!(Path.join(directory, "root.der"))
        bytes = receive_bytes(socket, <<>>, byte_size(expected))
        assert [_, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert :ok = SSL.close(socket)

        if lifecycle do
          {handle, _} = lifecycle

          assert {:ok,
                  %{
                    version: 1,
                    setup: :connected,
                    cleanup: :confirmed,
                    roles: 30,
                    observed_down: 30,
                    losses: 0
                  } = receipt} = SSL.Lifecycle.await(handle, deadline(2_000))

          refute Map.has_key?(receipt, :auxiliary)
        end
      after
        SSL.close(socket)
      end
    after
      RevocationPeer.stop(peer)

      if lifecycle do
        {_, lease} = lifecycle
        SSL.Lifecycle.cancel(lease, deadline(500))
      end
    end
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
      assert {:ok, more} = SSL.recv(socket, 0, 2_000)
      receive_bytes(socket, bytes <> more, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.CustomCRLCacheIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [
        :lookup3,
        :lookup2,
        :logger_pair,
        :logger_triple,
        :unavailable,
        :empty,
        :stale_refresh,
        :stale_unchanged,
        :future,
        :forged,
        :revoked,
        :intermediate_revoked,
        :raise,
        :improper,
        :invalid,
        :disabled,
        :best_effort_stale,
        :future_peer,
        :best_effort_future,
        :future_good,
        :future_revoked,
        :stale_future,
        :best_effort_stale_future,
        :general_good,
        :general_future,
        :malformed_time
      ] do
    test "#{version} #{route} custom CRL cache #{mode}" do
      run_case(unquote(version), unquote(route), unquote(mode))
    end
  end

  defp run_case(version, route, mode) do
    directory = RevocationFixtures.directory!()
    reference = make_ref()

    material =
      for name <- [
            "root-good",
            "leaf-good",
            "leaf-revoked",
            "root-revoked",
            "root-stale",
            "leaf-stale",
            "root-future",
            "leaf-future",
            "root-forged",
            "leaf-forged",
            "root-general-good",
            "leaf-general-good",
            "root-general-future",
            "leaf-general-future",
            "root-malformed-time",
            "leaf-malformed-time"
          ],
          into: %{},
          do: {name, File.read!(Path.join(directory, name <> ".crl.der"))}

    context = %{parent: self(), reference: reference, mode: mode, material: material}
    module = if mode == :lookup2, do: __MODULE__.OldCache, else: __MODULE__.Cache

    crl_check = crl_check(mode)

    verify = fn
      _, {:bad_cert, reason}, _state ->
        send(context.parent, {reference, :policy_bad_cert, reason})
        {:fail, reason}

      _, {:extension, _}, state ->
        {:unknown, state}

      _, _, state ->
        {:valid, state}
    end

    options =
      RevocationFixtures.options(directory, version) ++
        [crl_check: crl_check, crl_cache: {module, {context, []}}, verify_fun: {verify, nil}]

    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
    peer = RevocationPeer.start(directory, version)

    try do
      result = connect(peer.port, options, route, {handle, lease})

      accepted =
        mode in [
          :lookup3,
          :lookup2,
          :logger_pair,
          :logger_triple,
          :unavailable,
          :empty,
          :stale_refresh,
          :disabled,
          :best_effort_stale,
          :best_effort_future,
          :future_good,
          :best_effort_stale_future,
          :general_good
        ]

      if accepted do
        assert {:ok, socket} = result

        try do
          assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
          expected = File.read!(Path.join(directory, "root.der"))
          bytes = receive_bytes(socket, <<>>, byte_size(expected))
          assert [_, ^expected] = :binary.split(bytes, "\r\n\r\n")
        after
          SSL.close(socket)
        end
      else
        assert {:error, {:tls_alert, _}} = result
      end

      assert_cache_events(mode, reference)

      refute inspect(result) =~ "CACHE_PRIVATE"
      refute inspect(result) =~ directory
      expected_roles = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{
                version: 1,
                cleanup: :confirmed,
                roles: ^expected_roles,
                observed_down: ^expected_roles,
                losses: 0
              } = receipt} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      refute Map.has_key?(receipt, :auxiliary)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
  end

  defmodule Cache do
    def lookup(_point, _issuer, {context, []}), do: values(context, :lookup3)
    def select(_issuer, {context, []}), do: values(context, :select)

    def fresh_crl(_point, current) do
      context = Process.get({__MODULE__, :context})
      send(context.parent, {context.reference, :cache, :fresh})

      if context.mode in [:stale_refresh, :stale_future, :best_effort_stale_future] do
        der =
          case current do
            {der, _} -> der
            der -> der
          end

        prefix = if der == context.material["root-stale"], do: "root", else: "leaf"
        suffix = if context.mode == :stale_refresh, do: "-good", else: "-future"
        context.material[prefix <> suffix]
      else
        current
      end
    end

    def values(context, operation) do
      Process.put({__MODULE__, :context}, context)
      send(context.parent, {context.reference, :cache, operation})

      values = cached_values(context)

      case {context.mode, operation} do
        {:logger_pair, _} -> {{:logger, "CACHE_PRIVATE"}, values}
        {:logger_triple, _} -> {:logger, "CACHE_PRIVATE", values}
        {:unavailable, :lookup3} -> :not_available
        {:empty, :lookup3} -> []
        _ -> values
      end
    end

    defp cached_values(context) do
      case context.mode do
        mode
        when mode in [
               :stale_refresh,
               :stale_unchanged,
               :best_effort_stale,
               :stale_future,
               :best_effort_stale_future
             ] ->
          [context.material["root-stale"], context.material["leaf-stale"]]

        mode when mode in [:future, :future_peer, :best_effort_future] ->
          [context.material["root-future"], context.material["leaf-future"]]

        :future_good ->
          [
            context.material["root-future"],
            context.material["leaf-future"],
            context.material["root-good"],
            context.material["leaf-good"]
          ]

        :future_revoked ->
          [
            context.material["root-future"],
            context.material["leaf-future"],
            context.material["root-good"],
            context.material["leaf-revoked"]
          ]

        :general_good ->
          [context.material["root-general-good"], context.material["leaf-general-good"]]

        :general_future ->
          [context.material["root-general-future"], context.material["leaf-general-future"]]

        :malformed_time ->
          [context.material["root-malformed-time"], context.material["leaf-malformed-time"]]

        :forged ->
          [context.material["root-forged"], context.material["leaf-forged"]]

        :revoked ->
          [context.material["root-good"], context.material["leaf-revoked"]]

        :intermediate_revoked ->
          [context.material["root-revoked"], context.material["leaf-good"]]

        :raise ->
          raise "CACHE_PRIVATE"

        :improper ->
          [context.material["leaf-good"] | :improper]

        :invalid ->
          [:invalid]

        _ ->
          [context.material["root-good"], context.material["leaf-good"]]
      end
    end
  end

  defmodule OldCache do
    alias SSL.CustomCRLCacheIntegrationTest.Cache

    def lookup(_point, {context, []}),
      do: Cache.values(context, :lookup2)

    def select(issuer, reference),
      do: Cache.select(issuer, reference)

    def fresh_crl(point, current),
      do: Cache.fresh_crl(point, current)
  end

  defp connect(port, options, :direct, lifecycle),
    do: SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: lifecycle]], 5_000)

  defp connect(port, options, :prepared, lifecycle) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000)
  end

  defp receive_bytes(socket, bytes, expected) do
    assert byte_size(bytes) <= expected + 8_192

    complete =
      case :binary.split(bytes, "\r\n\r\n") do
        [_, body] -> byte_size(body) >= expected
        _ -> false
      end

    if complete,
      do: bytes,
      else:
        (case SSL.recv(socket, 0, 2_000) do
           {:ok, more} -> receive_bytes(socket, bytes <> more, expected)
           {:error, :closed} -> bytes
         end)
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp crl_check(mode) do
    case mode do
      :disabled ->
        false

      mode when mode in [:best_effort_stale, :best_effort_future, :best_effort_stale_future] ->
        :best_effort

      :future_peer ->
        :peer

      _ ->
        true
    end
  end

  defp assert_cache_events(mode, reference) do
    if mode == :disabled do
      refute_receive {^reference, :cache, _}, 0
    else
      assert_receive {^reference, :cache, :select}, 500
    end

    if mode == :lookup2, do: assert_receive({^reference, :cache, :lookup2}, 500)

    if mode in [:lookup3, :logger_pair, :logger_triple, :unavailable, :empty],
      do: assert_receive({^reference, :cache, :lookup3}, 500)

    if mode in [
         :stale_refresh,
         :stale_unchanged,
         :best_effort_stale,
         :stale_future,
         :best_effort_stale_future
       ],
       do: assert_receive({^reference, :cache, :fresh}, 500)

    if mode == :future_revoked do
      assert_receive {^reference, :policy_bad_cert, {:revoked, :keyCompromise}}, 500
    end

    if mode in [:future, :future_peer, :general_future, :stale_future] do
      assert_receive {^reference, :policy_bad_cert, :revocation_status_undetermined}, 500
    end

    if mode in [:stale_future, :best_effort_stale_future] do
      # One fresh callback was consumed above. The existing flow checks two
      # CRLs at I, then lookup+same-issuer at L only for best_effort.
      remaining = if mode == :stale_future, do: 1, else: 5
      for _ <- 1..remaining, do: assert_receive({^reference, :cache, :fresh}, 500)
      refute_receive {^reference, :cache, :fresh}, 0
    end
  end
end

defmodule SSL.CRLCacheMutationIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      key <- [:uri, :issuer] do
    test "#{version} #{route} #{key} mutable cache is revalidated on every handshake" do
      mutation_case(unquote(version), unquote(route), unquote(key))
    end
  end

  defp mutation_case(version, route, key) do
    directory = RevocationFixtures.directory!()
    root = File.read!(Path.join(directory, "root-good.crl.der"))
    good = File.read!(Path.join(directory, "leaf-good.crl.der"))
    revoked = File.read!(Path.join(directory, "leaf-revoked.crl.der"))
    forged = File.read!(Path.join(directory, "leaf-forged.crl.der"))
    all = [root, good, revoked, forged]
    uri = "http://127.0.0.1:18749/leaf.crl"

    insert = fn values ->
      if key == :uri,
        do: SSL.CRLCache.insert(uri, {:der, values}),
        else: SSL.CRLCache.insert({:der, values})
    end

    reference = make_ref()
    parent = self()

    verify = fn
      _, {:bad_cert, reason}, _ ->
        send(parent, {reference, reason})
        {:fail, reason}

      _, {:extension, _}, state ->
        {:unknown, state}

      _, _, state ->
        {:valid, state}
    end

    options =
      RevocationFixtures.options(directory, version) ++
        [crl_check: true, verify_fun: {verify, nil}]

    prepared =
      if route == :prepared do
        assert {:ok, prepared} = SSL.prepare_upgrade(options)
        prepared
      end

    handshake = fn expected ->
      peer = RevocationPeer.start(directory, version)
      {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

      try do
        result =
          if route == :direct do
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              5_000
            )
          else
            assert {:ok, tcp} =
                     :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
          end

        case expected do
          :valid ->
            assert {:ok, socket} = result

            try do
              assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
              assert {:ok, response} = SSL.recv(socket, 0, 2_000)
              assert response =~ "HTTP/1.0 200"
            after
              SSL.close(socket)
            end

          reason ->
            assert {:error, {:tls_alert, _}} = result
            assert_receive {^reference, ^reason}, 500
        end

        roles = if route == :direct, do: 31, else: 30

        assert {:ok,
                %{
                  version: 1,
                  cleanup: :confirmed,
                  roles: ^roles,
                  observed_down: ^roles,
                  losses: 0
                } = receipt} =
                 SSL.Lifecycle.await(handle, deadline(2_000))

        refute Map.has_key?(receipt, :auxiliary)
        refute inspect(result) =~ directory
      after
        RevocationPeer.stop(peer)
        SSL.Lifecycle.cancel(lease, deadline(500))
      end
    end

    try do
      assert :ok = SSL.CRLCache.delete(uri)
      assert :ok = SSL.CRLCache.delete({:der, all})
      assert :ok = insert.([root, good])
      handshake.(:valid)
      assert :ok = SSL.CRLCache.delete({:der, good})
      handshake.(:revocation_status_undetermined)
      assert :ok = insert.([revoked])
      handshake.({:revoked, :keyCompromise})
      assert :ok = SSL.CRLCache.delete({:der, revoked})
      assert :ok = insert.([forged])
      handshake.(:revocation_status_undetermined)
      assert :ok = SSL.CRLCache.delete({:der, forged})
      assert :ok = insert.([good])
      handshake.(:valid)

      if key == :uri do
        assert :ok = SSL.CRLCache.delete(uri)
      else
        assert :ok = SSL.CRLCache.delete({:der, all})
      end

      handshake.(:revocation_status_undetermined)
    after
      SSL.CRLCache.delete(uri)
      SSL.CRLCache.delete({:der, all})
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.IndirectRevocationIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {ders, []}), do: ders
  def select(_, {ders, []}), do: ders
  def fresh_crl(_, current), do: current

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      source <- [:peer, :trust] do
    test "#{version} #{route} indirect CRL signer from admitted #{source} pool", %{
      directory: base
    } do
      run_case(base, unquote(version), unquote(route), unquote(source), "good", true)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      variant <- [
        "no-crlsign",
        "expired",
        "critical",
        "bad-signature",
        "other-root",
        "same-name-root",
        "pathlen",
        "wrong-key"
      ] do
    test "#{version} #{route} indirect CRL rejects #{variant} signer at exact selected anchor", %{
      directory: base
    } do
      run_case(base, unquote(version), unquote(route), :trust, unquote(variant), false)
    end
  end

  test "CRL primitive preserves exact-anchor empty path for root and partial intermediate", %{
    directory: base
  } do
    for {certificate, anchor, crl_name} <- [
          {"intermediate", "root", "root-good.crl.der"},
          {"leaf", "intermediate", "leaf-good.crl.der"}
        ] do
      cert = decode(base, certificate)
      root = decode(base, anchor)
      der = File.read!(Path.join(base, crl_name))
      crl = :public_key.der_decode(:CertificateList, der)
      point = :public_key.pkix_dist_point(cert)
      assert :public_key.pkix_crl_verify(crl, root)

      assert :valid =
               :public_key.pkix_crls_validate(cert, [{point, {der, crl}}],
                 issuer_fun: {fn _, _, _, _ -> {:ok, root, []} end, nil},
                 undetermined_details: true
               )
    end
  end

  defp decode(base, name),
    do: :public_key.pkix_decode_cert(File.read!(Path.join(base, name <> ".der")), :otp)

  defp run_case(base, version, route, source, variant, accepted) do
    signer = if variant in ["good", "wrong-key"], do: "signer", else: "signer-" <> variant
    branch = if variant == "pathlen", do: ["branch-b", "branch-a"], else: []
    roots = if variant in ["other-root", "same-name-root"], do: [variant], else: []
    chain_file = if source == :peer, do: "extra-chain.pem", else: "intermediate.pem"

    peer =
      RevocationPeer.start(base, version, [
        "-cert",
        "indirect-leaf.pem",
        "-cert_chain",
        chain_file
      ])

    options = RevocationFixtures.options(base, version)
    additional = if source == :trust, do: [signer] ++ branch ++ roots, else: []

    options =
      Keyword.update!(
        options,
        :cacerts,
        &(&1 ++ Enum.map(additional, fn name -> File.read!(Path.join(base, name <> ".der")) end))
      )

    crl_name =
      if variant == "wrong-key", do: "indirect-crl-wrong-key.der", else: "indirect-crl.der"

    reference = make_ref()
    owner = self()
    leaf = File.read!(Path.join(base, "indirect-leaf.der"))
    intermediate = File.read!(Path.join(base, "intermediate.der"))

    verify = fn _, der, event, state ->
      role = certificate_role(der, leaf, intermediate)

      case event do
        {:bad_cert, reason} ->
          send(owner, {reference, role, {:bad_cert, reason}})
          {:fail, :rejected}

        {:extension, _} ->
          {:unknown, state}

        other ->
          send(owner, {reference, role, other})
          {:valid, state}
      end
    end

    options =
      options ++
        [
          verify_fun: {verify, nil},
          crl_check: :peer,
          crl_cache: {__MODULE__, {[File.read!(Path.join(base, crl_name))], []}}
        ]

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

      if accepted do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = File.read!(Path.join(base, "root.der"))
        response = receive_body(socket, <<>>, byte_size(expected))
        assert [header, ^expected] = :binary.split(response, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
        assert_receive {^reference, :leaf, :valid_peer}, 500
      else
        assert {:error, {:tls_alert, _}} = result
        assert_receive {^reference, :leaf, {:bad_cert, :revocation_status_undetermined}}, 500
      end

      assert_receive {^reference, :intermediate, :valid}, 500
      refute_receive {^reference, :unexpected_signer_event, _}, 0

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: mask, observed_down: mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      assert mask == if(route == :direct, do: 31, else: 30)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
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

  defp certificate_role(der, leaf, intermediate) do
    cond do
      der == leaf -> :leaf
      der == intermediate -> :intermediate
      true -> :unexpected_signer_event
    end
  end
end

defmodule SSL.RevocationDistributionPointIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}
  require Record

  Record.defrecordp(
    :dp,
    :DistributionPoint,
    Record.extract(:DistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(point, issuer, {{owner, ref, first, second, _selected, expected_issuer}, []}) do
    {:fullName, [{:uniformResourceIdentifier, uri}]} = dp(point, :distributionPoint)
    name = uri |> List.to_string() |> URI.parse() |> Map.fetch!(:path)

    send(
      owner,
      {ref, {:lookup, name, :public_key.pkix_normalize_name(issuer) == expected_issuer}}
    )

    case name do
      "/first" -> first
      "/second" -> second
    end
  end

  def select(issuer, {{owner, ref, _first, _second, selected, expected_issuer}, []}) do
    send(owner, {ref, {:select, :public_key.pkix_normalize_name(issuer) == expected_issuer}})
    selected
  end

  def fresh_crl(_, current), do: current

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      scenario <- [
        :unavailable_first,
        :empty_first,
        :empty_reject,
        :revoked_first,
        :forged_first,
        :stale_first,
        :no_dp,
        :first_good
      ] do
    test "#{route} #{version} #{scenario} distribution point order", %{directory: base} do
      run_case(base, unquote(version), unquote(route), unquote(scenario))
    end
  end

  defp run_case(base, version, route, scenario) do
    good = [File.read!(Path.join(base, "leaf-good.crl.der"))]
    revoked = [File.read!(Path.join(base, "leaf-revoked.crl.der"))]
    forged = [File.read!(Path.join(base, "leaf-forged.crl.der"))]
    stale = [File.read!(Path.join(base, "leaf-stale.crl.der"))]

    {first, second, selected, accepted, trace} =
      distribution_case(scenario, good, revoked, forged, stale)

    certificate = if scenario == :no_dp, do: "no-dp-leaf", else: "two-dp-leaf"
    leaf = :public_key.pkix_decode_cert(File.read!(Path.join(base, certificate <> ".der")), :otp)

    if scenario != :no_dp do
      points = :public_key.pkix_dist_points(leaf)

      names =
        Enum.map(points, fn point ->
          {:fullName, [{:uniformResourceIdentifier, uri}]} = dp(point, :distributionPoint)
          URI.parse(List.to_string(uri)).path
        end)

      assert names == ["/first", "/second"]
    end

    issuer = leaf |> elem(1) |> elem(4) |> :public_key.pkix_normalize_name()
    ref = make_ref()
    peer = RevocationPeer.start(base, version, ["-cert", certificate <> ".pem"])

    options =
      RevocationFixtures.options(base, version) ++
        [
          crl_check: :peer,
          crl_cache: {__MODULE__, {{self(), ref, first, second, selected, issuer}, []}}
        ]

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

      assert match?({:ok, _}, result) == accepted

      case result do
        {:ok, socket} ->
          assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
          assert {:ok, bytes} = SSL.recv(socket, 0, 2_000)
          assert bytes =~ "HTTP/1.0 200"
          assert :ok = SSL.close(socket)

        {:error, {:tls_alert, _}} ->
          :ok
      end

      actual = collect(ref, [])
      assert actual == trace

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: mask, observed_down: mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      assert mask == if(route == :direct, do: 31, else: 30)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp collect(ref, acc) do
    receive do
      {^ref, event} -> collect(ref, [event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp distribution_case(scenario, good, revoked, forged, stale) do
    case scenario do
      :unavailable_first ->
        {:not_available, good, [], true, [{:lookup, "/first", true}, {:lookup, "/second", true}]}

      :empty_first ->
        {[], revoked, good, false, [{:lookup, "/first", true}, {:lookup, "/second", true}]}

      :empty_reject ->
        {[], good, [], true, [{:lookup, "/first", true}, {:lookup, "/second", true}]}

      :revoked_first ->
        {revoked, good, good, false, [{:lookup, "/first", true}]}

      :forged_first ->
        {forged, revoked, good, true, [{:lookup, "/first", true}, {:select, true}]}

      :stale_first ->
        {stale, revoked, good, true, [{:lookup, "/first", true}, {:select, true}]}

      :no_dp ->
        {:not_available, revoked, good, true, [{:select, true}]}

      :first_good ->
        {good, revoked, revoked, true, [{:lookup, "/first", true}]}
    end
  end
end

defmodule SSL.RevokedSignerIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {context, []}) do
    Process.put({__MODULE__, :trace}, {context.owner, context.ref})
    send(context.owner, {context.ref, :lookup})
    context.lookup
  end

  def select(issuer, {context, []}) do
    Process.put({__MODULE__, :trace}, {context.owner, context.ref})

    if :public_key.pkix_normalize_name(issuer) == context.root do
      send(context.owner, {context.ref, :select_root})
      context.root_crls
    else
      send(context.owner, {context.ref, :select_leaf})
      context.selected
    end
  end

  def fresh_crl(_, current) do
    {owner, ref} = Process.get({__MODULE__, :trace})
    send(owner, {ref, :fresh})
    current
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer, :best_effort],
      scenario <- [
        :revoked,
        :default,
        :override,
        :missing,
        :good,
        :forged,
        :stale,
        :future,
        :wrong_issuer,
        :alternate_signer,
        :alternate_crl,
        :fallback,
        :all_invalid
      ] do
    test "#{version} #{route} #{mode} #{scenario} offpath signer status", %{directory: base} do
      run_case(base, unquote(version), unquote(route), unquote(mode), unquote(scenario))
    end
  end

  defp run_case(base, version, route, mode, scenario) do
    read = fn name -> File.read!(Path.join(base, name)) end
    indirect = read.("indirect-crl.der")
    revoked = read.("root-signer-revoked.der")
    root_good = read.("root-good.crl.der")

    {lookup, selected, additional, accepted, fallback} =
      signer_case(scenario, indirect, revoked, root_good, read)

    ref = make_ref()
    owner = self()
    leaf = read.("indirect-leaf.der")
    intermediate = read.("intermediate.der")

    verify = fn _, der, event, state ->
      role =
        cond do
          der == leaf -> :leaf
          der == intermediate -> :intermediate
          true -> :unexpected
        end

      case event do
        {:bad_cert, reason} ->
          send(owner, {ref, {:verify, role, {:bad_cert, reason}}})
          if scenario == :override, do: {:valid, state}, else: {:fail, :rejected}

        {:extension, _} ->
          {:unknown, state}

        other ->
          send(owner, {ref, {:verify, role, other}})
          {:valid, state}
      end
    end

    root =
      :public_key.pkix_decode_cert(read.("root.der"), :otp)
      |> elem(1)
      |> elem(6)
      |> :public_key.pkix_normalize_name()

    context = %{
      owner: owner,
      ref: ref,
      lookup: lookup,
      selected: selected,
      root: root,
      root_crls: [root_good]
    }

    options = RevocationFixtures.options(base, version)

    options =
      Keyword.update!(options, :cacerts, &(&1 ++ Enum.map(["signer.der" | additional], read))) ++
        [crl_check: mode, crl_cache: {__MODULE__, {context, []}}]

    options = if scenario == :default, do: options, else: options ++ [verify_fun: {verify, nil}]
    peer = RevocationPeer.start(base, version, ["-cert", "indirect-leaf.pem"])
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

      assert_exchange(accepted, result, read)

      events = collect(ref, [])
      trace = Enum.reject(events, &match?({:verify, _, _}, &1))

      expected_trace =
        if(mode == :peer, do: [], else: [:select_root]) ++
          [:lookup] ++
          if fallback, do: [:select_leaf], else: []

      # These unrelated signer-status inputs require no top-level refresh;
      # the nested signer-status primitive must never add a fresh_crl callback.
      assert trace == expected_trace

      IO.puts(
        JSON.encode!(%{
          signer_scenario: scenario,
          version: version,
          route: route,
          mode: mode,
          cache_trace: trace
        })
      )

      assert_signer_events(scenario, events)

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: mask, observed_down: mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      assert mask == if(route == :direct, do: 31, else: 30)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
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
      {^ref, event} -> collect(ref, [event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp signer_case(scenario, indirect, revoked, root_good, read) do
    case scenario do
      mode when mode in [:revoked, :default, :override] ->
        {[indirect, revoked], [indirect, revoked], [], mode == :override, true}

      :missing ->
        {[indirect], [indirect], [], true, false}

      :good ->
        {[indirect, root_good], [], [], true, false}

      mode when mode in [:forged, :stale, :future, :wrong_issuer] ->
        name = mode |> Atom.to_string() |> String.replace("_", "-")
        crls = [indirect, read.("root-signer-" <> name <> ".der")]
        {crls, crls, [], true, false}

      :alternate_signer ->
        {[indirect, revoked], [], ["signer-alternate.der"], true, false}

      :alternate_crl ->
        {[indirect, read.("indirect-crl-alternate.der"), revoked], [],
         ["signer-alternate-key.der"], true, false}

      :fallback ->
        {[indirect, revoked], [read.("leaf-good.crl.der")], [], true, true}

      :all_invalid ->
        {[indirect, revoked], [indirect, revoked],
         ["signer-expired.der", "signer-no-crlsign.der"], false, true}
    end
  end

  defp assert_signer_events(scenario, events) do
    if scenario != :default do
      assert Enum.count(events, &(&1 == {:verify, :intermediate, :valid})) == 1
      assert Enum.count(events, &(&1 == {:verify, :leaf, :valid_peer})) == 1
      bad = Enum.filter(events, &match?({:verify, _, {:bad_cert, _}}, &1))

      assert bad ==
               if(scenario in [:revoked, :override, :all_invalid],
                 do: [{:verify, :leaf, {:bad_cert, :revoked_crl_signer}}],
                 else: []
               )

      refute Enum.any?(events, &match?({:verify, :unexpected, _}, &1))
    end
  end

  defp assert_exchange(accepted, result, read) do
    if accepted do
      assert {:ok, socket} = result
      assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
      expected = read.("root.der")
      response = receive_body(socket, <<>>, byte_size(expected))
      assert [header, ^expected] = :binary.split(response, "\r\n\r\n")
      assert header =~ "HTTP/1.0 200"
      assert :ok = SSL.close(socket)
    else
      if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
      assert {:error, {:tls_alert, _}} = result
    end
  end
end

defmodule SSL.CRLMeaningIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {{_, crls}, []}), do: crls
  def select(_, {{root, crls}, []}), do: [root | crls]
  def fresh_crl(_, current), do: current

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer, :best_effort],
      {scenario, files, expected} <- [
        {:delta_good, ["base-good", "delta-good"], :valid},
        {:delta_revoked, ["base-good", "delta-revoked"], {:revoked, :keyCompromise}},
        {:delta_remove, ["base-hold", "delta-remove"], :valid},
        {:delta_wrong_base, ["base-hold", "delta-wrong-base"], {:revoked, :certificateHold}},
        {:partial_reasons, ["reason-key"], :revocation_status_undetermined},
        {:complete_reasons, ["reason-key", "reason-rest"], :valid},
        {:unknown_critical, ["unknown-critical"], :revocation_status_undetermined},
        # public_key/OTP compatibility: actual signature remains mandatory;
        # OpenSSL rejects this contradictory selector metadata.
        {:key_identifier_mismatch, ["wrong-aki"], :valid}
      ] do
    test "#{version} #{route} #{mode} #{scenario} authenticated CRL semantics", %{directory: base} do
      run_case(
        base,
        unquote(version),
        unquote(route),
        unquote(mode),
        unquote(files),
        unquote(Macro.escape(expected))
      )
    end
  end

  defp run_case(base, version, route, mode, files, expected) do
    accepted =
      expected == :valid or (expected == :revocation_status_undetermined and mode == :best_effort)

    crls = Enum.map(files, &File.read!(Path.join(base, &1 <> ".der")))
    root = File.read!(Path.join(base, "root-good.crl.der"))
    owner = self()
    ref = make_ref()

    verify = fn _, event, state ->
      case event do
        {:bad_cert, reason} ->
          send(owner, {ref, reason})
          {:fail, :rejected}

        {:extension, _} ->
          {:unknown, state}

        _ ->
          {:valid, state}
      end
    end

    options =
      RevocationFixtures.options(base, version) ++
        [crl_check: mode, crl_cache: {__MODULE__, {{root, crls}, []}}, verify_fun: {verify, nil}]

    peer = RevocationPeer.start(base, version)
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

      if accepted do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        body = File.read!(Path.join(base, "root.der"))
        response = receive_body(socket, <<>>, byte_size(body))
        assert [header, ^body] = :binary.split(response, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
        assert_receive {^ref, ^expected}, 500
      end

      refute_receive {^ref, _}, 0

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: mask, observed_down: mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      assert mask == if(route == :direct, do: 31, else: 30)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
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
end

defmodule SSL.CRLSignerBoundsIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.RevocationFixtures
  alias SSL.PKIX.{PartialChain, Revocation}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {{initial, _fallback}, []}), do: initial
  def select(_, {{_initial, fallback}, []}), do: fallback
  def fresh_crl(_, current), do: current

  test "signer path fuel N-1/N/N+1 is consumed before retaining nodes", %{directory: base} do
    [signer, root] = records(base, ["signer", "root"])

    for fuel <- [0, 1],
        do:
          assert(
            {:error, :policy_capacity} =
              PartialChain.signer_paths(signer, [root], root, fuel, :infinity)
          )

    for fuel <- [2, 3] do
      assert {:ok, [{^root, [^signer]}], remaining, 2} =
               PartialChain.signer_paths(signer, [root], root, fuel, :infinity)

      assert remaining == fuel - 2
    end
  end

  test "cycles and same-subject alternate roots never terminate at a different anchor", %{
    directory: base
  } do
    [signer, root, other] = records(base, ["signer", "root", "same-name-root"])

    assert {:ok, paths, remaining, visits} =
             PartialChain.signer_paths(signer, [signer, other, root], root, 20, :infinity)

    assert paths != []

    for {anchor, path} <- paths do
      assert anchor.der == root.der
      refute Enum.any?(path, &(&1.der == root.der))
      assert Enum.uniq_by(path, & &1.der) == path
    end

    assert remaining + visits == 20
    assert visits < 20
  end

  test "signer search original deadline expires without retaining a path", %{directory: base} do
    [signer, root] = records(base, ["signer", "root"])

    assert {:error, :deadline_exceeded} =
             PartialChain.signer_paths(
               signer,
               [root],
               root,
               4_096,
               System.monotonic_time(:millisecond) - 1
             )
  end

  test "nested signer status uses the shared remaining path fuel", %{directory: base} do
    data = data(base)
    Process.put({SSL.PolicyIO, :budget}, %{bytes: 0, nodes: 0, paths: 4_093})
    assert catch_throw(check(data, [data.indirect, data.revoked], [], :peer)) == :policy_capacity
    assert Process.get({SSL.PolicyIO, :failure}) == :policy_capacity
    assert SSL.PolicyIO.path_budget() == 0
    refute Process.get({Revocation, :revoked_signer})
  end

  test "independent checks cannot inherit known-revoked or successful-fallback state", %{
    directory: base
  } do
    data = data(base)

    for {initial, fallback, expected} <- [
          {[data.indirect, data.revoked], [data.indirect, data.revoked],
           {:bad_cert, :revoked_crl_signer}},
          {[data.indirect], [], :valid_peer},
          {[data.indirect, data.revoked], [data.leaf_good], :valid_peer},
          {[data.indirect, data.revoked], [], {:bad_cert, :revoked_crl_signer}},
          {[data.indirect], [], :valid_peer}
        ] do
      assert check(data, initial, fallback, :best_effort) == expected
      assert Process.get({Revocation, :revoked_signer}) == nil
    end
  end

  test "direct selected-path CRL issuer keeps its existing no-search route", %{directory: base} do
    data = data(base)
    Process.put({SSL.PolicyIO, :budget}, %{bytes: 0, nodes: 0, paths: 0})
    assert check(data, [], [data.leaf_good], :peer) == :valid_peer
    assert SSL.PolicyIO.path_budget() == 4_096
    assert Process.get({Revocation, :revoked_signer}) == nil
  end

  defp records(base, names) do
    {:ok, records} =
      SSL.PKIX.decode_chain(Enum.map(names, &File.read!(Path.join(base, &1 <> ".der"))))

    records
  end

  defp data(base) do
    [leaf, intermediate, root, signer] =
      records(base, ["indirect-leaf", "intermediate", "root", "signer"])

    %{
      leaf: leaf,
      selected: {root, [leaf, intermediate]},
      pool: [leaf, intermediate, root, signer],
      indirect: File.read!(Path.join(base, "indirect-crl.der")),
      revoked: File.read!(Path.join(base, "root-signer-revoked.der")),
      leaf_good: File.read!(Path.join(base, "leaf-good.crl.der"))
    }
  end

  defp check(data, initial, fallback, mode) do
    context = %SSL.PolicyIO.Context{deadline: System.monotonic_time(:millisecond) + 5_000}
    policy = %{crl_check: mode, crl_cache: {__MODULE__, {{initial, fallback}, []}}}

    Revocation.check(
      context,
      policy,
      data.leaf.decoded,
      data.leaf.der,
      :valid_peer,
      data.selected,
      data.pool,
      []
    )
  end
end

defmodule SSL.RevocationHashDirectoryBoundaryIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      scenario <- [
        :pem,
        :der,
        :r1_forged,
        :r1_wrong_issuer,
        :r1_stale,
        :gap,
        :stale_only,
        :revoked,
        :empty,
        :invalid,
        :directory,
        :size_below,
        :size_at,
        :size_above,
        :indices_254,
        :indices_255,
        :indices_256
      ] do
    test "#{version} #{route} hash directory #{scenario} keeps bounded owned file proof", %{
      directory: base
    } do
      run_case(base, unquote(version), unquote(route), unquote(scenario))
    end
  end

  defp run_case(base, version, route, scenario) do
    directory = Path.join(base, "hash-boundary-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    read = fn name -> File.read!(Path.join(base, name)) end
    good_pem = read.("leaf-good.crl.pem")
    good_der = read.("leaf-good.crl.der")

    filename =
      Path.wildcard(Path.join([base, "good", "*.r0"]))
      |> Enum.find(&(File.read!(&1) == good_pem))
      |> Path.basename()

    hash = String.trim_trailing(filename, ".r0")
    write = fn index, bytes -> File.write!(Path.join(directory, hash <> ".r#{index}"), bytes) end

    write_hash_fixture(scenario, write, good_pem, good_der, read, directory, filename)

    owner = self()
    reference = make_ref()

    verify = fn _, event, state ->
      case event do
        {:bad_cert, reason} ->
          send(owner, {reference, reason})
          {:fail, :policy_rejected}

        {:extension, _} ->
          {:unknown, state}

        _ ->
          {:valid, state}
      end
    end

    options =
      RevocationFixtures.options(base, version) ++
        [
          crl_check: :peer,
          verify_fun: {verify, nil},
          crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: directory]}}
        ]

    peer = RevocationPeer.start(base, version)
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(10_000))
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              10_000
            )

          :prepared ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 10_000)
        end

      accepted =
        scenario in [
          :pem,
          :der,
          :r1_forged,
          :r1_wrong_issuer,
          :r1_stale,
          :size_below,
          :size_at,
          :indices_254,
          :indices_255
        ]

      if accepted do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = read.("root.der")
        bytes = receive_body(socket, <<>>, byte_size(expected))
        assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
        refute_receive {^reference, _}, 0
      else
        assert {:error, {:tls_alert, _}} = result

        if scenario in [:gap, :stale_only, :empty],
          do: assert_receive({^reference, :revocation_status_undetermined}, 500)

        if scenario == :revoked, do: assert_receive({^reference, {:revoked, :keyCompromise}}, 500)
        refute inspect(result) =~ directory
      end

      if scenario == :directory do
        # A non-ENOENT native open error leaves resource state unknown. The
        # Observer stops after grace without sealing a terminal receipt.
        assert {:unconfirmed, :observer_unsealed} = SSL.Lifecycle.await(handle, deadline(3_000))
        assert {:unconfirmed, :observer_unsealed} = SSL.Lifecycle.status(handle)
      else
        assert {:ok, receipt} = SSL.Lifecycle.await(handle, deadline(3_000))
        mask = if route == :direct, do: 31, else: 30
        assert %{version: 2, roles: ^mask, observed_down: ^mask, losses: 0} = receipt
        assert receipt.cleanup == :confirmed
        assert receipt.auxiliary == %{roles: 2, observed_down: 2, losses: 0}
      end

      assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 500
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
      File.rm_rf!(directory)
    end
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

  defp write_hash_fixture(scenario, write, good_pem, good_der, read, directory, filename) do
    case scenario do
      :pem ->
        write.(0, good_pem)

      :der ->
        write.(0, good_der)

      :r1_forged ->
        write.(0, read.("leaf-forged.crl.der"))
        write.(1, good_der)

      :r1_wrong_issuer ->
        write.(0, read.("root-good.crl.der"))
        write.(1, good_der)

      :r1_stale ->
        write.(0, read.("leaf-stale.crl.der"))
        write.(1, good_der)

      :gap ->
        write.(0, read.("leaf-forged.crl.der"))
        write.(2, good_der)

      :stale_only ->
        write.(0, read.("leaf-stale.crl.der"))

      :revoked ->
        write.(0, read.("leaf-revoked.crl.der"))

      :empty ->
        :ok

      :invalid ->
        write.(0, "invalid CRL")

      :directory ->
        File.mkdir!(Path.join(directory, filename))

      value ->
        write_boundary_fixture(value, write, good_pem, good_der)
    end
  end

  defp write_boundary_fixture(scenario, write, good_pem, good_der) do
    case scenario do
      value when value in [:size_below, :size_at, :size_above] ->
        size =
          16_777_216 +
            case value do
              :size_below -> -1
              :size_at -> 0
              :size_above -> 1
            end

        write.(0, good_pem <> :binary.copy("\n", size - byte_size(good_pem)))

      value when value in [:indices_254, :indices_255, :indices_256] ->
        count =
          case value do
            :indices_254 -> 254
            :indices_255 -> 255
            :indices_256 -> 256
          end

        for index <- 0..(count - 1), do: write.(index, good_der)
    end
  end
end

defmodule SSL.RevocationHTTPBoundaryIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      scenario <- [
        :not_found,
        :server_error,
        :no_location,
        :https,
        :ftp,
        :file,
        :redirect_31,
        :redirect_32,
        :redirect_33,
        :header_below,
        :header_at,
        :header_above,
        :body_below,
        :body_at,
        :body_above,
        :chunks_below,
        :chunks_at,
        :chunks_above,
        :conflicting_framing,
        :truncated,
        :trailing,
        :until_close,
        :stall_headers,
        :stall_body,
        :refused
      ] do
    test "#{version} #{route} HTTP policy #{scenario} obeys original bounded attempt", %{
      directory: base
    } do
      run_case(base, unquote(version), unquote(route), unquote(scenario))
    end
  end

  defp run_case(base, version, route, scenario) do
    leaf = File.read!(Path.join(base, "leaf-good.crl.pem"))
    response = fixed(leaf)

    payloads = http_payloads(scenario, leaf, response)

    {:ok, listener} =
      :gen_tcp.listen(18_749, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    server =
      if scenario == :refused do
        :gen_tcp.close(listener)
        nil
      else
        Task.async(fn -> serve(listener, payloads, scenario) end)
      end

    peer = RevocationPeer.start(base, version)
    http_timeout = if scenario in [:stall_headers, :stall_body], do: 150, else: 5_000

    options =
      RevocationFixtures.options(base, version) ++
        [crl_check: :peer, crl_cache: {:ssl_crl_cache, {:internal, [http: http_timeout]}}]

    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(10_000))
    started = System.monotonic_time(:millisecond)

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              10_000
            )

          :prepared ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 10_000)
        end

      accepted =
        scenario in [
          :redirect_31,
          :redirect_32,
          :header_below,
          :header_at,
          :body_below,
          :body_at,
          :chunks_below,
          :chunks_at,
          :until_close
        ]

      if accepted do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = File.read!(Path.join(base, "root.der"))
        bytes = receive_body(socket, <<>>, byte_size(expected))
        assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
      end

      if scenario in [:stall_headers, :stall_body],
        do: assert(System.monotonic_time(:millisecond) - started < 2_000)

      if server do
        requests = Task.await(server, 5_000)
        assert length(requests) == length(payloads)
        assert hd(requests) == "GET /leaf.crl HTTP/1.1"

        if scenario in [:redirect_31, :redirect_32, :redirect_33],
          do: assert(Enum.all?(tl(requests), &(&1 == "GET /next.crl HTTP/1.1")))
      end

      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{
                version: 2,
                cleanup: :confirmed,
                roles: ^mask,
                observed_down: ^mask,
                losses: 0,
                auxiliary: %{roles: 1, observed_down: 1, losses: 0}
              }} = SSL.Lifecycle.await(handle, deadline(2_000))
    after
      RevocationPeer.stop(peer)
      if server && Process.alive?(server.pid), do: Task.shutdown(server, :brutal_kill)
      :gen_tcp.close(listener)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
  end

  defp serve(listener, payloads, scenario) do
    requests =
      for response <- payloads do
        assert {:ok, socket} = :gen_tcp.accept(listener, 6_000)

        try do
          assert {:ok, request} = :gen_tcp.recv(socket, 0, 2_000)

          case response do
            :stall ->
              assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)

            {:stall, bytes} ->
              assert :ok = :gen_tcp.send(socket, bytes)
              assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)

            bytes ->
              result = :gen_tcp.send(socket, bytes)

              if scenario in [:body_above, :chunks_above, :header_above],
                do: assert(result in [:ok, {:error, :closed}, {:error, :econnreset}]),
                else: assert(result == :ok)
          end

          request |> String.split("\r\n") |> hd()
        after
          :gen_tcp.close(socket)
        end
      end

    assert {:error, :timeout} = :gen_tcp.accept(listener, 50)
    requests
  after
    :gen_tcp.close(listener)
  end

  defp delta(value) when value in [:header_below, :body_below, :chunks_below], do: -1
  defp delta(value) when value in [:header_at, :body_at, :chunks_at], do: 0
  defp delta(_), do: 1
  defp fixed(bytes), do: "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(bytes)}\r\n\r\n" <> bytes

  defp redirect(location),
    do: "HTTP/1.1 302 Found\r\nLocation: #{location}\r\nContent-Length: 0\r\n\r\n"

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

  defp http_payloads(scenario, leaf, response) do
    case scenario do
      :not_found ->
        ["HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"]

      :server_error ->
        ["HTTP/1.1 500 Failed\r\nContent-Length: 0\r\n\r\n"]

      :no_location ->
        ["HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"]

      value when value in [:https, :ftp, :file] ->
        [redirect(Atom.to_string(value) <> "://127.0.0.1:18749/forbidden")]

      :conflicting_framing ->
        ["HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"]

      :truncated ->
        ["HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(leaf) + 1}\r\n\r\n" <> leaf]

      :trailing ->
        [fixed(leaf) <> "X"]

      :until_close ->
        ["HTTP/1.1 200 OK\r\n\r\n" <> leaf]

      :stall_headers ->
        [:stall]

      :stall_body ->
        [{:stall, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"}]

      :refused ->
        []

      value ->
        boundary_payloads(value, leaf, response)
    end
  end

  defp boundary_payloads(scenario, leaf, response) do
    case scenario do
      value when value in [:redirect_31, :redirect_32, :redirect_33] ->
        count =
          case value do
            :redirect_31 -> 31
            :redirect_32 -> 32
            :redirect_33 -> 33
          end

        if count <= 32,
          do: List.duplicate(redirect("/next.crl"), count - 1) ++ [response],
          else: List.duplicate(redirect("/next.crl"), 32)

      value when value in [:header_below, :header_at, :header_above] ->
        size = 16_384 + delta(value)
        prefix = "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(leaf)}\r\nPadding: "
        [prefix <> :binary.copy("x", size - byte_size(prefix) - 4) <> "\r\n\r\n" <> leaf]

      value when value in [:body_below, :body_at, :body_above] ->
        size = 16_777_216 + delta(value)
        [fixed(leaf <> :binary.copy("\n", size - byte_size(leaf)))]

      value when value in [:chunks_below, :chunks_at, :chunks_above] ->
        count = 65_535 + delta(value)

        [
          IO.iodata_to_binary([
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            Integer.to_string(byte_size(leaf), 16),
            "\r\n",
            leaf,
            "\r\n",
            List.duplicate("1\r\n\n\r\n", count - 1),
            "0\r\n\r\n"
          ])
        ]
    end
  end
end

defmodule SSL.RevocationHTTPCutoffIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      stage <- [:headers, :body],
      trigger <- [:cancel, :deadline, :connection_death, :caller_death] do
    test "#{version} #{route} HTTP #{stage} #{trigger} joins exact auxiliary and primary evidence",
         %{directory: base} do
      run_case(base, unquote(version), unquote(route), unquote(stage), unquote(trigger))
    end
  end

  defp run_case(base, version, route, stage, trigger) do
    owner = self()
    reference = make_ref()

    {:ok, listener} =
      :gen_tcp.listen(18_749, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    server =
      Task.async(fn ->
        try do
          assert {:ok, socket} = :gen_tcp.accept(listener, 2_000)

          try do
            assert {:ok, request} = :gen_tcp.recv(socket, 0, 2_000)
            assert request =~ "GET /leaf.crl HTTP/1.1"

            if stage == :body,
              do:
                assert(
                  :ok == :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                )

            send(owner, {reference, :http_waiting})
            assert {:error, :closed} = :gen_tcp.recv(socket, 0, 5_000)
            :closed
          after
            :gen_tcp.close(socket)
          end
        after
          :gen_tcp.close(listener)
        end
      end)

    verify = verification_callback(owner, reference)

    options =
      RevocationFixtures.options(base, version) ++
        [
          crl_check: :peer,
          verify_fun: {verify, nil},
          crl_cache: {:ssl_crl_cache, {:internal, [http: 8_000]}}
        ]

    peer = RevocationPeer.start(base, version)
    setup_deadline = if trigger == :deadline, do: deadline(2_000), else: :infinity
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: setup_deadline)
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)

    caller =
      Task.async(fn ->
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              :infinity
            )

          :prepared ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 1_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], :infinity)
        end
      end)

    try do
      assert_receive {^reference, :connection, connection}, 1_000
      connection_monitor = Process.monitor(connection)
      assert_receive {^reference, :http_waiting}, 1_000
      mask = if route == :direct, do: 31, else: 30

      assert {:pending, %{roles: ^mask, auxiliary: %{roles: 1, observed_down: 0, losses: 0}}} =
               SSL.Lifecycle.status(handle)

      assert Task.yield(caller, 0) == nil

      cutoff = trigger_cutoff(trigger, lease, setup_deadline, connection, caller)

      # The caller can be descheduled while native cleanup completes. Hold it
      # through the deadline case so its result cannot act as the cleanup oracle.
      hold_deadline_caller(trigger, caller)

      try do
        await_caller_before_cleanup(trigger, caller, cutoff)

        connection_timeout = cleanup_timeout(trigger, cutoff, 500)
        assert_receive {:DOWN, ^connection_monitor, :process, ^connection, _}, connection_timeout
        assert :closed = Task.await(server, cleanup_timeout(trigger, cutoff, 2_000))
        observer_timeout = cleanup_timeout(trigger, cutoff, 500)
        assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, observer_timeout

        assert {:ok,
                %{
                  version: 2,
                  logical: :closed,
                  cleanup: :confirmed,
                  roles: ^mask,
                  observed_down: ^mask,
                  losses: 0,
                  auxiliary: %{roles: 1, observed_down: 1, losses: 0}
                }} =
                 SSL.Lifecycle.await(handle, {:abs_ms, cutoff})

        if trigger == :deadline, do: assert(System.monotonic_time(:millisecond) <= cutoff)
      after
        if trigger == :deadline, do: :erlang.resume_process(caller.pid)
      end

      # Native cleanup has already met the original cutoff. Result delivery has
      # its own bounded watchdog after the caller is allowed to run again.
      if trigger == :deadline, do: assert({:error, :closed} = Task.await(caller, 1_000))

      refute_receive {^reference, :connection, _}, 0
      refute_receive {^reference, :bad_cert}, 0
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
      if Process.alive?(server.pid), do: Task.shutdown(server, :brutal_kill)
      :gen_tcp.close(listener)
      RevocationPeer.stop(peer)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp hold_deadline_caller(:deadline, caller), do: assert(:erlang.suspend_process(caller.pid))
  defp hold_deadline_caller(_trigger, _caller), do: :ok

  defp await_caller_before_cleanup(:deadline, _caller, _cutoff), do: :ok

  defp await_caller_before_cleanup(:caller_death, caller, _cutoff) do
    caller_pid = caller.pid
    caller_ref = caller.ref
    assert_receive {:DOWN, ^caller_ref, :process, ^caller_pid, :killed}, 1_000
  end

  defp await_caller_before_cleanup(_trigger, caller, cutoff) do
    assert {:error, :closed} =
             Task.await(caller, max(1, cutoff - System.monotonic_time(:millisecond)))
  end

  defp cleanup_timeout(:deadline, cutoff, _default),
    do: max(1, cutoff - System.monotonic_time(:millisecond))

  defp cleanup_timeout(_trigger, _cutoff, default), do: default

  defp trigger_cutoff(trigger, lease, setup_deadline, connection, caller) do
    case trigger do
      :cancel ->
        assert :ok = SSL.Lifecycle.cancel(lease, deadline(1_000))
        System.monotonic_time(:millisecond) + 1_000

      :deadline ->
        {:abs_ms, expiry} = setup_deadline
        assert System.monotonic_time(:millisecond) < expiry
        expiry + 1_000

      :connection_death ->
        Process.exit(connection, :kill)
        System.monotonic_time(:millisecond) + 1_000

      :caller_death ->
        Process.unlink(caller.pid)
        Process.exit(caller.pid, :kill)
        System.monotonic_time(:millisecond) + 1_000
    end
  end

  defp verification_callback(owner, reference) do
    fn _, event, state ->
      if event == :valid_peer, do: send(owner, {reference, :connection, self()})

      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, _} ->
          send(owner, {reference, :bad_cert})
          {:fail, :rejected}

        _ ->
          {:valid, state}
      end
    end
  end
end

defmodule SSL.RevocationConcurrentSurvivalIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {{owner, ref, stage, stale}, []}) do
    if stage == :lookup, do: blocked(owner, ref), else: [stale]
  end

  def select(_, {{owner, ref, _, _}, []}) do
    send(owner, {ref, :unexpected_select})
    []
  end

  def fresh_crl(_, current) do
    {owner, ref} = Process.get({__MODULE__, :callback})
    blocked(owner, ref)
    current
  end

  defp blocked(owner, ref) do
    send(owner, {ref, :entered, self()})

    receive do
      {^ref, :release} -> []
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      stage <- [:lookup, :fresh],
      trigger <- [:cancel, :deadline] do
    test "#{version} #{route} #{stage} #{trigger} preserves independent established TLS", %{
      directory: base
    } do
      run_case(base, unquote(version), unquote(route), unquote(stage), unquote(trigger))
    end
  end

  defp run_case(base, version, route, stage, trigger) do
    reference = make_ref()
    owner = self()
    healthy_peer = RevocationPeer.start(base, version)
    blocked_peer = RevocationPeer.start(base, version)

    {:ok, healthy_handle, healthy_lease} =
      SSL.Lifecycle.new(controller: self(), deadline: deadline(10_000))

    {:ok, healthy_socket} =
      connect(
        healthy_peer.port,
        RevocationFixtures.options(base, version),
        route,
        {healthy_handle, healthy_lease}
      )

    verify = fn _, event, state ->
      Process.put({__MODULE__, :callback}, {owner, reference})

      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, _} ->
          send(owner, {reference, :unexpected_bad_cert})
          {:fail, :rejected}

        _ ->
          {:valid, state}
      end
    end

    stale = File.read!(Path.join(base, "leaf-stale.crl.der"))

    options =
      RevocationFixtures.options(base, version) ++
        [
          crl_check: :peer,
          verify_fun: {verify, nil},
          crl_cache: {__MODULE__, {{owner, reference, stage, stale}, []}}
        ]

    setup_deadline = if trigger == :deadline, do: deadline(2_000), else: :infinity
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: setup_deadline)
    caller = Task.async(fn -> connect(blocked_peer.port, options, route, {handle, lease}) end)

    try do
      assert_receive {^reference, :entered, connection}, 1_000
      monitor = Process.monitor(connection)
      assert {:pending, %{setup: :connected}} = SSL.Lifecycle.status(healthy_handle)
      assert Task.yield(caller, 0) == nil

      cutoff =
        case trigger do
          :cancel ->
            assert :ok = SSL.Lifecycle.cancel(lease, deadline(1_000))
            System.monotonic_time(:millisecond) + 1_000

          :deadline ->
            {:abs_ms, expiry} = setup_deadline
            expiry + 1_000
        end

      assert {:error, :closed} =
               Task.await(caller, max(1, cutoff - System.monotonic_time(:millisecond)))

      assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 500
      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, {:abs_ms, cutoff})

      refute_receive {^reference, :entered, _}, 0
      refute_receive {^reference, :unexpected_select}, 0
      refute_receive {^reference, :unexpected_bad_cert}, 0
      assert :ok = SSL.send(healthy_socket, "GET /root.der HTTP/1.0\r\n\r\n")
      expected = File.read!(Path.join(base, "root.der"))
      bytes = receive_body(healthy_socket, <<>>, byte_size(expected))
      assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
      assert header =~ "HTTP/1.0 200"
      assert :ok = SSL.close(healthy_socket)

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(healthy_handle, deadline(2_000))
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      SSL.Lifecycle.cancel(healthy_lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
      SSL.close(healthy_socket)
      RevocationPeer.stop(blocked_peer)
      RevocationPeer.stop(healthy_peer)
    end
  end

  defp connect(port, options, :direct, lifecycle),
    do: SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: lifecycle]], :infinity)

  defp connect(port, options, :prepared, lifecycle) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], :infinity)
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

defmodule SSL.RevocationConcurrentCacheIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"], route <- [:direct, :prepared] do
    test "#{version} #{route} concurrent cache bytes never authorize another connection signer pool" do
      run_case(unquote(version), unquote(route))
    end
  end

  defp run_case(version, route) do
    base = RevocationFixtures.directory!()
    uri = "http://127.0.0.1/indirect.crl"
    crl = File.read!(Path.join(base, "indirect-crl.der"))
    signer = File.read!(Path.join(base, "signer.der"))
    assert :ok = SSL.CRLCache.insert(uri, {:der, [crl]})
    owner = self()
    reference = make_ref()
    peers = for _ <- 1..2, do: RevocationPeer.start(base, version, ["-cert", "indirect-leaf.pem"])

    handles =
      for _ <- 1..2 do
        {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(8_000))
        {handle, lease}
      end

    callers =
      for {{peer, lifecycle}, authorized} <- Enum.zip(Enum.zip(peers, handles), [true, false]) do
        Task.async(fn ->
          check_concurrent_connection(
            base,
            version,
            authorized,
            signer,
            owner,
            reference,
            route,
            {peer, lifecycle}
          )

          :checked
        end)
      end

    try do
      assert_receive {^reference, :ready, true, first}, 2_000
      assert_receive {^reference, :ready, false, second}, 2_000
      refute first == second
      send(first, {reference, :continue})
      send(second, {reference, :continue})
      assert Enum.map(callers, &Task.await(&1, 3_000)) == [:checked, :checked]
      assert_receive {^reference, :rejected, false, :revocation_status_undetermined}, 500
      refute_receive {^reference, :rejected, true, _}, 0
      refute_receive {^reference, :ready, _, _}, 0
      mask = if route == :direct, do: 31, else: 30

      for {handle, _} <- handles do
        assert {:ok,
                %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
                 SSL.Lifecycle.await(handle, deadline(2_000))
      end
    after
      for {_, lease} <- handles, do: SSL.Lifecycle.cancel(lease, deadline(500))
      for caller <- callers, Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
      Enum.each(peers, &RevocationPeer.stop/1)
      SSL.CRLCache.delete(uri)
    end
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

  defp check_concurrent_connection(
         base,
         version,
         authorized,
         signer,
         owner,
         reference,
         route,
         {peer, lifecycle}
       ) do
    options = RevocationFixtures.options(base, version)

    options =
      if authorized,
        do: Keyword.update!(options, :cacerts, &(&1 ++ [signer])),
        else: options

    verify = fn _, event, state ->
      case event do
        :valid_peer ->
          send(owner, {reference, :ready, authorized, self()})

          receive do
            {^reference, :continue} -> {:valid, state}
          end

        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, reason} ->
          send(owner, {reference, :rejected, authorized, reason})
          {:fail, :rejected}

        _ ->
          {:valid, state}
      end
    end

    options =
      options ++
        [
          verify_fun: {verify, nil},
          crl_check: :peer,
          crl_cache: {:ssl_crl_cache, {:internal, []}}
        ]

    result =
      case route do
        :direct ->
          SSL.connect(
            ~c"127.0.0.1",
            peer.port,
            options ++ [ex_ssl: [lifecycle: lifecycle]],
            5_000
          )

        :prepared ->
          {:ok, prepared} = SSL.prepare_upgrade(options)

          {:ok, tcp} =
            :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

          SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000)
      end

    if authorized do
      assert {:ok, socket} = result
      assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
      expected = File.read!(Path.join(base, "root.der"))
      bytes = receive_body(socket, <<>>, byte_size(expected))
      assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
      assert header =~ "HTTP/1.0 200"
      assert :ok = SSL.close(socket)
    else
      assert {:error, {:tls_alert, _}} = result
    end
  end
end

defmodule SSL.OffpathIntermediateRevocationIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias SSL.PKIX.Revocation

  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {{owner, ref, crls, _root, _good}, []}) do
    send(owner, {ref, :lookup})
    crls
  end

  def select(issuer, {{owner, ref, crls, root, good}, []}) do
    send(owner, {ref, :select})
    if :public_key.pkix_normalize_name(issuer) == root, do: [good], else: crls
  end

  def fresh_crl(_, current), do: current

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer, :best_effort],
      scenario <- [
        :good,
        :revoked,
        :forged,
        :stale,
        :future,
        :wrong_issuer,
        :alternate_j,
        :all_invalid,
        :override
      ] do
    test "#{version} #{route} #{mode} distinct offpath J #{scenario}", %{directory: base} do
      run_case(base, unquote(version), unquote(route), unquote(mode), unquote(scenario))
    end
  end

  defp run_case(base, version, route, mode, scenario) do
    read = fn name -> File.read!(Path.join(base, name)) end
    owner = self()
    ref = make_ref()
    leaf = read.("indirect-leaf.der")
    intermediate = read.("intermediate.der")

    verify = fn _, der, event, state ->
      role =
        cond do
          der == leaf -> :leaf
          der == intermediate -> :intermediate
          true -> :unexpected
        end

      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, reason} ->
          send(owner, {ref, role, {:bad_cert, reason}})
          if scenario == :override, do: {:valid, state}, else: {:fail, :rejected}

        other ->
          send(owner, {ref, role, other})
          {:valid, state}
      end
    end

    status = if scenario in [:alternate_j, :all_invalid, :override], do: :revoked, else: scenario
    status_name = Atom.to_string(status) |> String.replace("_", "-")

    alternatives = signer_alternatives(scenario)

    crls = Enum.map(["indirect-crl.der", "j-good.der", "root-j-" <> status_name <> ".der"], read)

    root =
      :public_key.pkix_decode_cert(read.("root.der"), :otp)
      |> elem(1)
      |> elem(6)
      |> :public_key.pkix_normalize_name()

    options = RevocationFixtures.options(base, version)

    options =
      Keyword.update!(
        options,
        :cacerts,
        &(&1 ++ Enum.map(["signer-via-j.der", "branch-a-valid.der"] ++ alternatives, read))
      ) ++
        [
          crl_check: mode,
          verify_fun: {verify, nil},
          crl_cache: {__MODULE__, {{self(), ref, crls, root, read.("root-good.crl.der")}, []}}
        ]

    peer = RevocationPeer.start(base, version, ["-cert", "indirect-leaf.pem"])
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

      if match?({:ok, _}, result) do
        socket = elem(result, 1)
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = read.("root.der")
        bytes = receive_body(socket, <<>>, byte_size(expected))
        assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      end

      IO.puts(
        JSON.encode!(%{
          offpath_j: scenario,
          version: version,
          route: route,
          mode: mode,
          accepted: match?({:ok, _}, result)
        })
      )

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: mask, observed_down: mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      assert mask == if(route == :direct, do: 31, else: 30)

      assert_policy_events(scenario, result, ref, mode)
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, deadline(500))
    end
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

  for remaining <- [5, 6, 7] do
    test "offpath J shared validation fuel #{remaining} keeps exact per-primitive boundary", %{
      directory: base
    } do
      data = bound_data(base)

      Process.put({SSL.PolicyIO, :budget}, %{
        bytes: 0,
        nodes: 0,
        paths: 4_096 - unquote(remaining)
      })

      try do
        if unquote(remaining) < 6 do
          assert catch_throw(bound_check(data, System.monotonic_time(:millisecond) + 5_000)) ==
                   :policy_capacity

          assert Process.get({SSL.PolicyIO, :failure}) == :policy_capacity
        else
          assert bound_check(data, System.monotonic_time(:millisecond) + 5_000) == :valid_peer
        end

        assert SSL.PolicyIO.path_budget() == max(unquote(remaining) - 6, 0)
        assert Process.get({SSL.PKIX.Revocation, :revoked_signer}) == nil
      after
        Process.delete({SSL.PolicyIO, :budget})
        Process.delete({SSL.PolicyIO, :failure})
      end
    end
  end

  test "offpath J expired original deadline cannot validate a signer path", %{directory: base} do
    data = bound_data(base)

    try do
      assert catch_throw(bound_check(data, System.monotonic_time(:millisecond) - 1)) ==
               :deadline_exceeded

      assert Process.get({SSL.PKIX.Revocation, :revoked_signer}) == nil
    after
      Process.delete({SSL.PolicyIO, :budget})
      Process.delete({SSL.PolicyIO, :failure})
    end
  end

  defp bound_data(base) do
    read = fn name -> File.read!(Path.join(base, name <> ".der")) end

    {:ok, [leaf, intermediate, root, signer, branch]} =
      SSL.PKIX.decode_chain(
        Enum.map(
          ["indirect-leaf", "intermediate", "root", "signer-via-j", "branch-a-valid"],
          read
        )
      )

    crls = Enum.map(["indirect-crl", "j-good", "root-j-good"], read)
    {leaf, {root, [leaf, intermediate]}, [leaf, intermediate, root, signer, branch], crls}
  end

  defp bound_check({leaf, selected, pool, crls}, cutoff) do
    context = %SSL.PolicyIO.Context{deadline: cutoff}

    policy = %{
      crl_check: :peer,
      crl_cache: {__MODULE__, {{self(), make_ref(), crls, nil, nil}, []}}
    }

    Revocation.check(
      context,
      policy,
      leaf.decoded,
      leaf.der,
      :valid_peer,
      selected,
      pool,
      []
    )
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp signer_alternatives(scenario) do
    case scenario do
      :alternate_j -> ["j-alternate.der"]
      :all_invalid -> ["j-expired.der", "j-bad-signature.der"]
      _ -> []
    end
  end

  defp assert_policy_events(scenario, result, ref, mode) do
    if scenario in [:revoked, :all_invalid] do
      assert {:error, {:tls_alert, _}} = result
      assert_receive {^ref, :leaf, {:bad_cert, :revoked_crl_signer}}, 500
    else
      assert {:ok, _} = result

      if scenario == :override do
        assert_receive {^ref, :leaf, {:bad_cert, :revoked_crl_signer}}, 500
      end
    end

    refute_receive {^ref, _, {:bad_cert, _}}, 0
    assert_receive {^ref, :intermediate, :valid}, 500
    assert_receive {^ref, :leaf, :valid_peer}, 500
    refute_receive {^ref, :intermediate, :valid}, 0
    refute_receive {^ref, :leaf, :valid_peer}, 0
    assert_receive {^ref, :lookup}, 500
    refute_receive {^ref, :lookup}, 0

    select_count =
      if(mode == :peer, do: 0, else: 1) +
        if scenario in [:revoked, :all_invalid, :override], do: 1, else: 0

    for _ <- List.duplicate(:select, select_count), do: assert_receive({^ref, :select}, 500)
    refute_receive {^ref, :select}, 0
    refute_receive {^ref, :unexpected, _}, 0
  end
end

defmodule SSL.CRLDistributionScopeIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}
  require Record

  Record.defrecordp(
    :dp,
    :DistributionPoint,
    Record.extract(:DistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :idp,
    :IssuingDistributionPoint,
    Record.extract(:IssuingDistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  setup_all do
    base = RevocationFixtures.directory!()
    read = fn name -> File.read!(Path.join(base, name)) end
    [entry] = :public_key.pem_decode(read.("intermediate-key.pem"))
    key = :public_key.pem_entry_decode(entry)
    leaf_tbs = :public_key.pkix_decode_cert(read.("leaf.der"), :otp) |> elem(1)

    for scope <- [:match, :mismatch] do
      point =
        dp(
          distributionPoint:
            {:fullName,
             [uniformResourceIdentifier: String.to_charlist("http://r49.invalid/#{scope}.crl")]}
        )

      extensions =
        Enum.reject(elem(leaf_tbs, 10), &(elem(&1, 1) == {2, 5, 29, 31})) ++
          [{:Extension, {2, 5, 29, 31}, false, [point]}]

      der = :public_key.pkix_sign(put_elem(leaf_tbs, 10, extensions), key)
      File.write!(Path.join(base, "point-#{scope}.der"), der)

      File.write!(
        Path.join(base, "point-#{scope}.pem"),
        :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
      )
    end

    {:CertificateList, tbs, algorithm, _} =
      :public_key.der_decode(:CertificateList, read.("leaf-good.crl.der"))

    scoped =
      :public_key.der_encode(
        :IssuingDistributionPoint,
        idp(
          distributionPoint:
            {:fullName, [uniformResourceIdentifier: ~c"http://r49.invalid/match.crl"]}
        )
      )

    tbs = put_elem(tbs, 7, elem(tbs, 7) ++ [{:Extension, {2, 5, 29, 28}, true, scoped}])
    signature = :public_key.sign(:public_key.der_encode(:TBSCertList, tbs), :sha256, key)
    der = :public_key.der_encode(:CertificateList, {:CertificateList, tbs, algorithm, signature})
    File.write!(Path.join(base, "point-scoped.crl.der"), der)

    File.write!(
      Path.join(base, "point-scoped.crl.pem"),
      :public_key.pem_encode([{:CertificateList, der, :not_encrypted}])
    )

    destination = Path.join(base, "public-dp-scope")
    File.mkdir!(destination)

    names =
      for(
        name <- ["root", "intermediate", "point-match", "point-mismatch"],
        suffix <- [".pem", ".der"],
        do: name <> suffix
      ) ++ ["point-scoped.crl.pem", "point-scoped.crl.der"]

    pins =
      for name <- names do
        bytes = read.(name)
        File.write!(Path.join(destination, name), bytes)

        %{
          path: name,
          bytes: byte_size(bytes),
          sha256: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
        }
      end

    File.write!(Path.join(destination, "manifest.json"), JSON.encode!(pins))
    {:ok, base: base}
  end

  def lookup(_, _, {data, []}), do: [data.scoped]

  def select(issuer, {data, []}) do
    if :public_key.pkix_normalize_name(issuer) == data.root_name,
      do: [data.root_crl],
      else: [data.scoped]
  end

  def fresh_crl(_, current), do: current

  test "characterize exact signed scope inputs before policy disposition", %{base: base} do
    read = fn name -> File.read!(Path.join(base, name)) end
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)
    issuer = :public_key.pkix_decode_cert(read.("intermediate.der"), :otp)
    der = read.("point-scoped.crl.der")
    {:CertificateList, tbs, _, _} = decoded = :public_key.der_decode(:CertificateList, der)

    {:Extension, {2, 5, 29, 28}, true, encoded_idp} =
      Enum.find(elem(tbs, 7), &(elem(&1, 1) == {2, 5, 29, 28}))

    idp = :public_key.der_decode(:IssuingDistributionPoint, encoded_idp)
    assert :public_key.pkix_crl_verify(der, issuer)
    {exe, prefix} = RevocationFixtures.openssl()

    for scope <- [:match, :mismatch] do
      leaf = :public_key.pkix_decode_cert(read.("point-#{scope}.der"), :otp)
      [point] = :public_key.pkix_dist_points(leaf)

      result =
        :public_key.pkix_crls_validate(leaf, [{point, {der, decoded}}],
          issuer_fun: {fn _, _, _, _ -> {:ok, root, [read.("intermediate.der")]} end, nil},
          undetermined_details: true
        )

      match_point = :public_key.pkix_match_dist_point(der, point)

      {out, code} =
        System.cmd(
          exe,
          prefix ++
            [
              "verify",
              "-CAfile",
              "root.pem",
              "-untrusted",
              "intermediate.pem",
              "-CRLfile",
              "point-scoped.crl.pem",
              "-crl_check",
              "-extended_crl",
              "point-#{scope}.pem"
            ],
          cd: base,
          stderr_to_stdout: true
        )

      IO.puts(
        JSON.encode!(%{
          scope_observation: scope,
          dp: inspect(point),
          idp: inspect(idp),
          public_key_valid: result == :valid,
          pkix_match_dist_point: match_point,
          openssl_exit: code,
          openssl_output: out
        })
      )

      assert {:ok, _} =
               :public_key.pkix_path_validation(
                 root,
                 [read.("intermediate.der"), read.("point-#{scope}.der")],
                 []
               )
    end
  end

  test "observed reference difference: OTP28 host-only URI and OpenSSL complete scope", %{
    base: base
  } do
    read = fn name -> File.read!(Path.join(base, name)) end
    issuer = :public_key.pkix_decode_cert(read.("intermediate.der"), :otp)
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)
    der = read.("point-scoped.crl.der")
    decoded = :public_key.der_decode(:CertificateList, der)
    assert :public_key.pkix_crl_verify(der, issuer)
    {exe, prefix} = RevocationFixtures.openssl()

    for scope <- [:match, :mismatch] do
      leaf = :public_key.pkix_decode_cert(read.("point-#{scope}.der"), :otp)

      assert {:ok, _} =
               :public_key.pkix_path_validation(
                 root,
                 [read.("intermediate.der"), read.("point-#{scope}.der")],
                 []
               )

      [point] = :public_key.pkix_dist_points(leaf)

      result =
        :public_key.pkix_crls_validate(leaf, [{point, {der, decoded}}],
          issuer_fun: {fn _, _, _, _ -> {:ok, root, [read.("intermediate.der")]} end, nil},
          undetermined_details: true
        )

      assert result == :valid
      assert :public_key.pkix_match_dist_point(der, point)

      args = [
        "verify",
        "-CAfile",
        "root.pem",
        "-untrusted",
        "intermediate.pem",
        "-CRLfile",
        "point-scoped.crl.pem",
        "-crl_check",
        "-extended_crl",
        "point-#{scope}.pem"
      ]

      {out, code} = System.cmd(exe, prefix ++ args, cd: base, stderr_to_stdout: true)

      IO.puts(
        JSON.encode!(%{
          dp_scope: scope,
          openssl_exit: code,
          output: out,
          primitive_valid: result == :valid
        })
      )

      assert code == if(scope == :match, do: 0, else: 2)
    end

    destination = Path.join(base, "public-dp-scope")
    File.mkdir_p!(destination)

    names =
      for name <- ["root", "intermediate", "point-match", "point-mismatch"],
          suffix <- [".pem", ".der"],
          do: name <> suffix

    names = names ++ ["point-scoped.crl.pem", "point-scoped.crl.der"]

    pins =
      for name <- names do
        bytes = read.(name)
        File.write!(Path.join(destination, name), bytes)

        %{
          path: name,
          bytes: byte_size(bytes),
          sha256: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
        }
      end

    File.write!(Path.join(destination, "manifest.json"), JSON.encode!(pins))
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer, :best_effort],
      scope <- [:match, :mismatch] do
    test "#{version} #{route} #{mode} authenticated DP/IDP #{scope}", %{base: base} do
      run_case(base, unquote(version), unquote(route), unquote(mode), unquote(scope), :candidate)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"], scope <- [:match, :mismatch] do
    test "observed reference difference: OTP28 #{version} accepts DP/IDP #{scope}", %{base: base} do
      {:ok, _} = Application.ensure_all_started(:ssl)
      run_case(base, unquote(version), :direct, true, unquote(scope), :otp)
    end
  end

  defp run_case(base, version, route, mode, scope, provider) do
    read = fn name -> File.read!(Path.join(base, name)) end
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)

    data = %{
      root_name: :public_key.pkix_normalize_name(root |> elem(1) |> elem(6)),
      root_crl: read.("root-good.crl.der"),
      scoped: read.("point-scoped.crl.der")
    }

    options =
      RevocationFixtures.options(base, version) ++
        [crl_check: mode, crl_cache: {__MODULE__, {data, []}}]

    peer = RevocationPeer.start(base, version, ["-cert", "point-#{scope}.pem"])

    lifecycle =
      if provider == :candidate do
        {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
        {handle, lease}
      end

    try do
      result =
        case {provider, route} do
          {:otp, :direct} ->
            :ssl.connect(~c"127.0.0.1", peer.port, options, 5_000)

          {:candidate, :direct} ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: lifecycle]],
              5_000
            )

          {:candidate, :prepared} ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000)
        end

      accepted = provider == :otp or scope == :match or mode == :best_effort

      if accepted do
        assert {:ok, socket} = result
        module = if provider == :otp, do: :ssl, else: SSL
        assert :ok = module.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = read.("root.der")
        bytes = receive_body(module, socket, <<>>, byte_size(expected))
        assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = module.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
      end

      if lifecycle do
        {handle, _} = lifecycle
        mask = if route == :direct, do: 31, else: 30

        assert {:ok,
                %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
                 SSL.Lifecycle.await(handle, deadline(2_000))
      end
    after
      if lifecycle, do: SSL.Lifecycle.cancel(elem(lifecycle, 1), deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp receive_body(module, socket, bytes, expected) do
    case :binary.split(bytes, "\r\n\r\n") do
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, next} = module.recv(socket, 0, 2_000)
        receive_body(module, socket, bytes <> next, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.CRLUnreadableFileIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      denied <- [false, true] do
    test "#{version} #{route} new public regular CRL permission denied=#{denied}" do
      base = RevocationFixtures.directory!()
      {uid_output, 0} = System.cmd("/usr/bin/id", ["-u"])
      {uid, ""} = Integer.parse(String.trim(uid_output))
      assert uid > 0
      bytes = File.read!(Path.join(base, "leaf-good.crl.pem"))
      issuer = :public_key.pkix_decode_cert(File.read!(Path.join(base, "intermediate.der")), :otp)

      hash =
        issuer
        |> elem(1)
        |> elem(6)
        |> :public_key.pkix_normalize_name()
        |> :public_key.short_name_hash()
        |> List.to_string()

      directory = Path.join(base, "new-public-permission-#{System.unique_integer([:positive])}")
      File.mkdir!(directory)
      path = Path.join(directory, hash <> ".r0")
      File.write!(path, bytes)
      original_mode = Bitwise.band(File.stat!(path).mode, 0o777)
      peer = RevocationPeer.start(base, unquote(version))
      {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(10_000))
      observer = handle.receipt.observer
      monitor = Process.monitor(observer)

      try do
        if unquote(denied) do
          File.chmod!(path, 0)
          assert {:error, :eacces} = :file.open(String.to_charlist(path), [:raw, :binary, :read])
        else
          assert File.read!(path) == bytes
        end

        options =
          RevocationFixtures.options(base, unquote(version)) ++
            [crl_check: :peer, crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: directory]}}]

        result =
          case unquote(route) do
            :direct ->
              SSL.connect(
                ~c"127.0.0.1",
                peer.port,
                options ++ [ex_ssl: [lifecycle: {handle, lease}]],
                10_000
              )

            :prepared ->
              {:ok, prepared} = SSL.prepare_upgrade(options)

              {:ok, tcp} =
                :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

              SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 10_000)
          end

        if unquote(denied) do
          assert {:error, {:tls_alert, _}} = result
          assert {:unconfirmed, :observer_unsealed} = SSL.Lifecycle.await(handle, deadline(3_000))
          assert {:unconfirmed, :observer_unsealed} = SSL.Lifecycle.status(handle)
        else
          assert {:ok, socket} = result
          assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
          expected = File.read!(Path.join(base, "root.der"))
          response = receive_body(socket, <<>>, byte_size(expected))
          assert [_, ^expected] = :binary.split(response, "\r\n\r\n")
          assert :ok = SSL.close(socket)
          mask = if unquote(route) == :direct, do: 31, else: 30

          assert {:ok,
                  %{
                    version: 2,
                    cleanup: :confirmed,
                    roles: ^mask,
                    observed_down: ^mask,
                    losses: 0,
                    auxiliary: %{roles: 2, observed_down: 2, losses: 0}
                  }} = SSL.Lifecycle.await(handle, deadline(3_000))
        end

        assert_receive {:DOWN, ^monitor, :process, ^observer, :normal}, 500
      after
        File.chmod!(path, original_mode)
        assert Bitwise.band(File.stat!(path).mode, 0o777) == original_mode
        assert File.read!(path) == bytes
        RevocationPeer.stop(peer)
        SSL.Lifecycle.cancel(lease, deadline(500))
        File.rm!(path)
        File.rmdir!(directory)
      end
    end
  end

  defp receive_body(socket, bytes, expected) do
    case :binary.split(bytes, "\r\n\r\n") do
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, next} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> next, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.CRLExactScopeRoutesIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}
  require Record

  Record.defrecordp(
    :dp,
    :DistributionPoint,
    Record.extract(:DistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :idp,
    :IssuingDistributionPoint,
    Record.extract(:IssuingDistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  setup_all do
    base = RevocationFixtures.directory!()
    read = fn name -> File.read!(Path.join(base, name)) end
    [entry] = :public_key.pem_decode(read.("intermediate-key.pem"))
    key = :public_key.pem_entry_decode(entry)
    original = :public_key.pkix_decode_cert(read.("leaf.der"), :otp) |> elem(1)

    uri = fn path ->
      {:uniformResourceIdentifier, String.to_charlist("http://r49.invalid/" <> path)}
    end

    full = fn names -> {:fullName, names} end
    first = full.([uri.("first")])
    second = full.([uri.("second")])

    relative = fn text ->
      {:nameRelativeToCRLIssuer, [{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, text}}]}
    end

    for {name, points} <- [
          {"match", [first]},
          {"path", [full.([uri.("different")])]},
          {"host", [full.(uniformResourceIdentifier: ~c"http://other.invalid/first")]},
          {"query", [full.([uri.("first?query=1")])]},
          {"aliases", [full.([uri.("different"), uri.("first")])]},
          {"aliases_bad", [full.([uri.("different"), uri.("third")])]},
          {"two", [second, first]},
          {"none", []},
          {"relative", [relative.("scope")]},
          {"relative_bad", [relative.("other")]}
        ] do
      extensions = Enum.reject(elem(original, 10), &(elem(&1, 1) == {2, 5, 29, 31}))

      extensions =
        if points == [],
          do: extensions,
          else:
            extensions ++
              [{:Extension, {2, 5, 29, 31}, false, Enum.map(points, &dp(distributionPoint: &1))}]

      der = :public_key.pkix_sign(put_elem(original, 10, extensions), key)
      File.write!(Path.join(base, "exact-#{name}.der"), der)

      File.write!(
        Path.join(base, "exact-#{name}.pem"),
        :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
      )
    end

    for {name, source, scope} <- [
          {"first", "leaf-good.crl.der", first},
          {"second", "leaf-good.crl.der", second},
          {"wrong", "leaf-good.crl.der", full.([uri.("wrong")])},
          {"aliases", "leaf-good.crl.der", full.([uri.("wrong"), uri.("first")])},
          {"stale", "leaf-stale.crl.der", first},
          {"relative", "leaf-good.crl.der", relative.("scope")}
        ] do
      {:CertificateList, tbs, algorithm, _} =
        :public_key.der_decode(:CertificateList, read.(source))

      extensions = if elem(tbs, 7) == :asn1_NOVALUE, do: [], else: elem(tbs, 7)
      extensions = Enum.reject(extensions, &(elem(&1, 1) == {2, 5, 29, 28}))
      encoded = :public_key.der_encode(:IssuingDistributionPoint, idp(distributionPoint: scope))
      tbs = put_elem(tbs, 7, extensions ++ [{:Extension, {2, 5, 29, 28}, true, encoded}])
      signature = :public_key.sign(:public_key.der_encode(:TBSCertList, tbs), :sha256, key)

      der =
        :public_key.der_encode(:CertificateList, {:CertificateList, tbs, algorithm, signature})

      File.write!(Path.join(base, "exact-#{name}.crl.der"), der)

      File.write!(
        Path.join(base, "exact-#{name}.crl.pem"),
        :public_key.pem_encode([{:CertificateList, der, :not_encrypted}])
      )
    end

    {:ok, base: base}
  end

  def lookup(point, _, {data, []}) do
    Process.put({__MODULE__, :current}, data)
    name = dp(point, :distributionPoint)
    send(data.owner, {data.ref, {:lookup, name}})

    if data.scenario == :first_empty,
      do: if(name == data.first, do: [], else: [data.second_crl]),
      else:
        if(data.scenario == :first_wrong,
          do: if(name == data.first, do: [data.wrong], else: [data.second_crl]),
          else: data.looked_up
        )
  end

  def select(issuer, {data, []}) do
    Process.put({__MODULE__, :current}, data)

    if :public_key.pkix_normalize_name(issuer) == data.root_name do
      [data.root_crl]
    else
      send(data.owner, {data.ref, :select})
      data.selected
    end
  end

  def fresh_crl(point, current) do
    data = Process.get({__MODULE__, :current})

    if data.refresh do
      send(data.owner, {data.ref, {:refresh, dp(point, :distributionPoint)}})
      data.refresh
    else
      current
    end
  end

  @scenarios [
    :match,
    :path,
    :host,
    :query,
    :aliases,
    :aliases_bad,
    :crl_aliases,
    :alternatives,
    :alternatives_bad,
    :fallback_good,
    :fallback_bad,
    :no_dp_scoped,
    :no_dp_unscoped,
    :refresh_good,
    :refresh_wrong,
    :relative,
    :relative_bad,
    :first_wrong,
    :first_empty,
    :first_good,
    :first_other_dp
  ]
  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer, :best_effort],
      scenario <- @scenarios do
    test "#{version} #{route} #{mode} exact scope #{scenario}", %{base: base} do
      run_case(base, unquote(version), unquote(route), unquote(mode), unquote(scenario), false)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer],
      scenario <- [:path, :no_dp_scoped, :refresh_wrong, :relative_bad] do
    test "#{version} #{route} #{mode} explicit scope override #{scenario}", %{base: base} do
      run_case(base, unquote(version), unquote(route), unquote(mode), unquote(scenario), true)
    end
  end

  test "signed scope fixture path/signature and relative-name independent controls", %{base: base} do
    read = fn name -> File.read!(Path.join(base, name)) end
    issuer = :public_key.pkix_decode_cert(read.("intermediate.der"), :otp)
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)

    for name <- [
          "match",
          "path",
          "host",
          "query",
          "aliases",
          "aliases_bad",
          "two",
          "none",
          "relative",
          "relative_bad"
        ] do
      assert {:ok, _} =
               :public_key.pkix_path_validation(
                 root,
                 [read.("intermediate.der"), read.("exact-#{name}.der")],
                 []
               )
    end

    for name <- ["first", "second", "wrong", "aliases", "stale", "relative"] do
      assert :public_key.pkix_crl_verify(read.("exact-#{name}.crl.der"), issuer)
    end

    {exe, prefix} = RevocationFixtures.openssl()

    for name <- ["relative", "relative_bad"] do
      der = read.("exact-relative.crl.der")
      decoded = :public_key.der_decode(:CertificateList, der)
      leaf = :public_key.pkix_decode_cert(read.("exact-#{name}.der"), :otp)
      [point] = :public_key.pkix_dist_points(leaf)

      result =
        :public_key.pkix_crls_validate(leaf, [{point, {der, decoded}}],
          issuer_fun: {fn _, _, _, _ -> {:ok, root, [read.("intermediate.der")]} end, nil},
          undetermined_details: true
        )

      assert result == :valid == (name == "relative")

      {output, code} =
        System.cmd(
          exe,
          prefix ++
            [
              "verify",
              "-CAfile",
              "root.pem",
              "-untrusted",
              "intermediate.pem",
              "-CRLfile",
              "exact-relative.crl.pem",
              "-crl_check",
              "-extended_crl",
              "exact-#{name}.pem"
            ],
          cd: base,
          stderr_to_stdout: true
        )

      IO.puts(
        JSON.encode!(%{
          relative_scope: name,
          openssl_exit: code,
          output: output,
          primitive: inspect(result)
        })
      )

      assert code == if(name == "relative", do: 0, else: 2)
    end
  end

  defp run_case(base, version, route, mode, scenario, override) do
    read = fn name -> File.read!(Path.join(base, name)) end
    first = {:fullName, [uniformResourceIdentifier: ~c"http://r49.invalid/first"]}
    second = {:fullName, [uniformResourceIdentifier: ~c"http://r49.invalid/second"]}
    good = read.("exact-first.crl.der")
    wrong = read.("exact-wrong.crl.der")

    {leaf_name, looked_up, selected, refresh, good_status, trace} =
      scope_case(scenario, read, first, second, good, wrong)

    owner = self()
    ref = make_ref()
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)
    leaf = :public_key.pkix_decode_cert(read.("exact-#{leaf_name}.der"), :otp)

    data = %{
      owner: owner,
      ref: ref,
      scenario: scenario,
      first: first,
      root_name: :public_key.pkix_normalize_name(root |> elem(1) |> elem(6)),
      root_crl: read.("root-good.crl.der"),
      wrong: wrong,
      second_crl: read.("exact-second.crl.der"),
      looked_up: looked_up,
      selected: selected,
      refresh: refresh
    }

    verify = fn certificate, event, state ->
      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, reason} ->
          send(owner, {ref, {:verify, certificate == leaf, {:bad_cert, reason}, state}})
          if override, do: {:valid, state + 1}, else: {:fail, :explicit_rejection}

        _ ->
          send(owner, {ref, {:verify, certificate == leaf, event, state}})
          {:valid, state + 1}
      end
    end

    options =
      RevocationFixtures.options(base, version) ++
        [crl_check: mode, crl_cache: {__MODULE__, {data, []}}, verify_fun: {verify, 0}]

    peer = RevocationPeer.start(base, version, ["-cert", "exact-#{leaf_name}.pem"])
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

      accepted = good_status or mode == :best_effort or override

      if accepted do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = read.("root.der")
        bytes = receive_body(socket, <<>>, byte_size(expected))
        assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
      end

      events = collect(ref, [])
      actual = Enum.reject(events, &match?({:verify, _, _, _}, &1))
      assert actual == trace
      leaf_events = for {:verify, true, event, _} <- events, do: event
      assert Enum.count(leaf_events, &(&1 == :valid_peer)) == 1
      bad = Enum.filter(leaf_events, &match?({:bad_cert, _}, &1))

      assert bad ==
               if(good_status or mode == :best_effort,
                 do: [],
                 else: [{:bad_cert, :revocation_status_undetermined}]
               )

      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp collect(ref, acc) do
    receive do
      {^ref, event} -> collect(ref, [event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp receive_body(socket, bytes, expected) do
    case :binary.split(bytes, "\r\n\r\n") do
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, next} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> next, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp scope_case(scenario, read, first, second, good, wrong) do
    case scenario do
      :match ->
        {"match", [good], [], nil, true, [{:lookup, first}]}

      :crl_aliases ->
        {"match", [read.("exact-aliases.crl.der")], [], nil, true, [{:lookup, first}]}

      :alternatives ->
        {"match", [wrong, good], [], nil, true, [{:lookup, first}]}

      :alternatives_bad ->
        {"match", [wrong, read.("exact-second.crl.der")], [], nil, false,
         [{:lookup, first}, :select]}

      :fallback_good ->
        {"match", [], [good], nil, true, [{:lookup, first}, :select]}

      :fallback_bad ->
        {"match", [], [wrong], nil, false, [{:lookup, first}, :select]}

      :no_dp_scoped ->
        {"none", [], [good], nil, false, [:select]}

      :no_dp_unscoped ->
        {"none", [], [read.("leaf-good.crl.der")], nil, true, [:select]}

      :refresh_good ->
        {"match", [read.("exact-stale.crl.der")], [], good, true,
         [{:lookup, first}, {:refresh, first}]}

      :refresh_wrong ->
        {"match", [read.("exact-stale.crl.der")], [], wrong, false,
         [{:lookup, first}, {:refresh, first}, :select]}

      name when name in [:first_wrong, :first_empty] ->
        {"two", [], [], nil, true, [{:lookup, first}, {:lookup, second}]}

      :first_good ->
        {"two", [good], [], nil, true, [{:lookup, first}]}

      :first_other_dp ->
        {"two", [read.("exact-second.crl.der")], [], nil, true, [{:lookup, first}]}

      name ->
        named_scope_case(name, read, good)
    end
  end

  defp named_scope_case(scenario, read, good) do
    case scenario do
      name when name in [:path, :host, :query, :aliases, :aliases_bad] ->
        leaf = :public_key.pkix_decode_cert(read.("exact-#{name}.der"), :otp)
        [point] = :public_key.pkix_dist_points(leaf)
        yes = name == :aliases

        {to_string(name), [good], [good], nil, yes,
         [{:lookup, dp(point, :distributionPoint)}] ++ if(yes, do: [], else: [:select])}

      name when name in [:relative, :relative_bad] ->
        leaf = :public_key.pkix_decode_cert(read.("exact-#{name}.der"), :otp)
        [point] = :public_key.pkix_dist_points(leaf)
        yes = name == :relative

        {to_string(name), [read.("exact-relative.crl.der")], [], nil, yes,
         [{:lookup, dp(point, :distributionPoint)}] ++ if(yes, do: [], else: [:select])}
    end
  end
end

defmodule SSL.CRLGeneralNamesBoundsIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}
  require Record

  Record.defrecordp(
    :dp,
    :DistributionPoint,
    Record.extract(:DistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :idp,
    :IssuingDistributionPoint,
    Record.extract(:IssuingDistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  setup_all do
    base = RevocationFixtures.directory!()
    read = fn name -> File.read!(Path.join(base, name)) end
    [entry] = :public_key.pem_decode(read.("intermediate-key.pem"))
    key = :public_key.pem_entry_decode(entry)
    original = :public_key.pkix_decode_cert(read.("leaf.der"), :otp) |> elem(1)

    {:CertificateList, crl_tbs, algorithm, _} =
      :public_key.der_decode(:CertificateList, read.("leaf-good.crl.der"))

    match_name = {:uniformResourceIdentifier, ~c"http://r49.invalid/exact-last"}

    for count <- [1, 127, 128, 129] do
      names =
        if count == 1,
          do: [match_name],
          else:
            for(
              n <- 1..(count - 1),
              do:
                {:uniformResourceIdentifier,
                 String.to_charlist("http://r49.invalid/different-#{n}")}
            ) ++ [match_name]

      assert length(names) == count and List.last(names) == match_name
      point = dp(distributionPoint: {:fullName, names})

      exts =
        Enum.reject(elem(original, 10), &(elem(&1, 1) == {2, 5, 29, 31})) ++
          [{:Extension, {2, 5, 29, 31}, false, [point]}]

      der = :public_key.pkix_sign(put_elem(original, 10, exts), key)
      File.write!(Path.join(base, "names-#{count}.der"), der)

      File.write!(
        Path.join(base, "names-#{count}.pem"),
        :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
      )

      encoded =
        :public_key.der_encode(
          :IssuingDistributionPoint,
          idp(distributionPoint: {:fullName, names})
        )

      tbs =
        put_elem(crl_tbs, 7, elem(crl_tbs, 7) ++ [{:Extension, {2, 5, 29, 28}, true, encoded}])

      signature = :public_key.sign(:public_key.der_encode(:TBSCertList, tbs), :sha256, key)

      der =
        :public_key.der_encode(:CertificateList, {:CertificateList, tbs, algorithm, signature})

      File.write!(Path.join(base, "names-#{count}.crl.der"), der)
    end

    {:ok, base: base}
  end

  def lookup(_, _, {data, []}), do: [data.crl]

  def select(issuer, {data, []}) do
    if :public_key.pkix_normalize_name(issuer) == data.root_name,
      do: [data.root_crl],
      else: [data.crl]
  end

  def fresh_crl(_, current), do: current

  test "all signed GeneralNames boundary fixtures are cryptographically valid with final matching name",
       %{base: base} do
    read = fn name -> File.read!(Path.join(base, name)) end
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)
    issuer = :public_key.pkix_decode_cert(read.("intermediate.der"), :otp)

    for source <- [:dp, :idp], count <- [127, 128, 129] do
      leaf_count = if source == :dp, do: count, else: 1
      crl_count = if source == :idp, do: count, else: 1
      der = read.("names-#{crl_count}.crl.der")
      decoded = :public_key.der_decode(:CertificateList, der)
      leaf = :public_key.pkix_decode_cert(read.("names-#{leaf_count}.der"), :otp)
      [point] = :public_key.pkix_dist_points(leaf)
      assert :public_key.pkix_crl_verify(der, issuer)

      assert {:ok, _} =
               :public_key.pkix_path_validation(
                 root,
                 [read.("intermediate.der"), read.("names-#{leaf_count}.der")],
                 []
               )

      assert :valid =
               :public_key.pkix_crls_validate(leaf, [{point, {der, decoded}}],
                 issuer_fun: {fn _, _, _, _ -> {:ok, root, [read.("intermediate.der")]} end, nil},
                 undetermined_details: true
               )

      {:fullName, dp_names} = dp(point, :distributionPoint)

      {:Extension, {2, 5, 29, 28}, true, bytes} =
        Enum.find(elem(elem(decoded, 1), 7), &(elem(&1, 1) == {2, 5, 29, 28}))

      {:fullName, idp_names} =
        :public_key.der_decode(:IssuingDistributionPoint, bytes) |> idp(:distributionPoint)

      assert length(dp_names) == leaf_count
      assert length(idp_names) == crl_count
      assert List.last(dp_names) == List.last(idp_names)
      assert Enum.count(dp_names, fn name -> name in idp_names end) == 1
    end
  end

  @tag :capacity_verifier
  test "actual policy verifier preserves sanitized bound outcome before TLS alert mapping", %{
    base: base
  } do
    read = fn name -> File.read!(Path.join(base, name)) end
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)

    for source <- [:dp, :idp],
        count <- [127, 128, 129],
        mode <- [true, :peer, :best_effort],
        protocol <- [:tls12, :tls13] do
      leaf_count = if source == :dp, do: count, else: 1
      crl_count = if source == :idp, do: count, else: 1

      data = %{
        root_name: :public_key.pkix_normalize_name(root |> elem(1) |> elem(6)),
        root_crl: read.("root-good.crl.der"),
        crl: read.("names-#{crl_count}.crl.der")
      }

      opts = [cacerts: [read.("root.der")], crl_check: mode, crl_cache: {__MODULE__, {data, []}}]
      {:ok, normalized} = SSL.Options.normalize(~c"r49.example", opts)

      {:ok, context, verify} =
        SSL.PolicyIO.prepare(normalized, nil, self(), System.monotonic_time(:millisecond) + 5_000)

      try do
        result =
          verify.(
            [read.("names-#{leaf_count}.der"), read.("intermediate.der")],
            normalized.trust_source,
            {:dns_id, ~c"r49.example"},
            :verify_peer,
            [],
            protocol
          )

        IO.puts(
          JSON.encode!(%{
            capacity_verifier: true,
            source: source,
            count: count,
            mode: mode,
            protocol: protocol,
            result: if(match?({:ok, _}, result), do: "ok", else: inspect(result)),
            sentinel: inspect(Process.get({SSL.PolicyIO, :failure}))
          })
        )

        if count <= 128 do
          assert {:ok, _} = result
          assert Process.get({SSL.PolicyIO, :failure}) == nil
        else
          assert {:error, :policy_capacity} = result
          assert Process.get({SSL.PolicyIO, :failure}) == :policy_capacity
        end
      after
        assert :ok = SSL.PolicyIO.finish(context)
      end
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer, :best_effort],
      source <- [:dp, :idp],
      count <- [127, 128, 129] do
    test "#{version} #{route} #{mode} #{source} GeneralNames #{count}", %{base: base} do
      run_case(
        base,
        unquote(version),
        unquote(route),
        unquote(mode),
        unquote(source),
        unquote(count)
      )
    end
  end

  defp run_case(base, version, route, mode, source, count) do
    read = fn name -> File.read!(Path.join(base, name)) end
    leaf_count = if source == :dp, do: count, else: 1
    crl_count = if source == :idp, do: count, else: 1
    root = :public_key.pkix_decode_cert(read.("root.der"), :otp)

    data = %{
      root_name: :public_key.pkix_normalize_name(root |> elem(1) |> elem(6)),
      root_crl: read.("root-good.crl.der"),
      crl: read.("names-#{crl_count}.crl.der")
    }

    options =
      RevocationFixtures.options(base, version) ++
        [crl_check: mode, crl_cache: {__MODULE__, {data, []}}]

    peer = RevocationPeer.start(base, version, ["-cert", "names-#{leaf_count}.pem"])
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

      if count <= 128 do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
        expected = read.("root.der")
        bytes = receive_body(socket, <<>>, byte_size(expected))
        assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
        assert header =~ "HTTP/1.0 200"
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, {:bad_certificate, ~c"TLS protocol error"}}} = result
      end

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
      [_, body] when byte_size(body) >= expected ->
        bytes

      _ ->
        assert {:ok, next} = SSL.recv(socket, 0, 2_000)
        receive_body(socket, bytes <> next, expected)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end
