defmodule SSL.OCSPPolicyIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok,
     directory: RevocationFixtures.directory!(),
     ocsp: RevocationFixtures.ocsp_directory!(),
     extended: RevocationFixtures.ocsp_extended!(),
     mutated: RevocationFixtures.ocsp_mutated!()}
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      managed <- [false, true],
      fixture <- [
        :good,
        :revoked,
        :unknown,
        :wrong_target,
        :malformed,
        :missing,
        :nonce_missing,
        :nonce_mismatch,
        :nonce_disabled_present,
        :trusted_root,
        :delegated,
        :expired_delegated,
        :no_eku,
        :unrelated,
        :future_produced,
        :future_this_update,
        :expired_next_update,
        :missing_next_update,
        :wrong_serial,
        :wrong_name_hash,
        :wrong_key_hash,
        :bad_signature,
        :unsupported_response,
        :unsuccessful_response
      ] do
    test "#{version} #{route} lifecycle=#{managed} OCSP #{fixture}", context do
      policy_case(context, unquote(version), unquote(route), unquote(managed), unquote(fixture))
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"], staple <- [:good, :revoked, :missing] do
    test "#{version} configured staple #{staple} has OTP precedence over opposite CRL", context do
      combined_case(context, unquote(version), unquote(staple))
    end
  end

  defp policy_case(
         %{directory: directory, ocsp: ocsp, extended: extended, mutated: mutated},
         version,
         route,
         managed,
         fixture
       ) do
    file = fixture_file(fixture)

    fixture_directory = fixture_directory(fixture, ocsp, extended, mutated)

    extra = if file, do: ["-status_file", Path.join(fixture_directory, file <> ".ocsp")], else: []
    peer = RevocationPeer.start(directory, version, extra)
    reference = make_ref()
    parent = self()

    verify = fn _, der, event, state ->
      send(parent, {reference, der, event, state})

      case event do
        {:bad_cert, _} -> {:fail, :policy_rejected}
        {:extension, _} -> {:unknown, state + 1}
        _ -> {:valid, state + 1}
      end
    end

    options =
      RevocationFixtures.options(directory, version) ++
        [
          stapling: %{ocsp_nonce: fixture in [:nonce_missing, :nonce_mismatch]},
          verify_fun: {verify, 0}
        ]

    lifecycle = lifecycle(managed)

    try do
      result = connect(peer.port, options, route, lifecycle)

      if fixture in [
           :good,
           :nonce_missing,
           :nonce_disabled_present,
           :trusted_root,
           :delegated,
           :missing_next_update
         ] do
        assert {:ok, socket} = result
        authenticated_payload(socket, directory)
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
      end

      events = drain(reference, [])

      if fixture not in [
           :good,
           :nonce_missing,
           :nonce_disabled_present,
           :trusted_root,
           :delegated,
           :missing_next_update,
           :malformed
         ] do
        leaf = File.read!(Path.join(directory, "leaf.der"))

        relevant =
          for {^leaf, event, state} <- events,
              event == :valid_peer or match?({:bad_cert, _}, event),
              do: {event, state}

        # OCSP is part of common certificate validation before the custom
        # leaf :valid_peer event; CRL cert_status_check has the opposite order.
        assert [{{:bad_cert, reason}, _state}] = relevant

        case fixture do
          :revoked -> assert reason == {:revoked, :keyCompromise}
          :missing -> assert reason == :missing_ocsp_staple
          _ -> assert is_atom(reason)
        end
      end

      assert_settled(lifecycle, route)
      refute inspect(result) =~ directory
    after
      RevocationPeer.stop(peer)
      cancel(lifecycle)
    end
  end

  defp combined_case(%{directory: directory, ocsp: ocsp}, version, staple) do
    file =
      if staple == :missing, do: nil, else: Path.join(ocsp, Atom.to_string(staple) <> ".ocsp")

    extra = if file, do: ["-status_file", file], else: []
    peer = RevocationPeer.start(directory, version, extra)
    # An owned HTTP policy would produce a v2 receipt if CRL fallback occurred.
    # Installed OTP source gives configured OCSP precedence; this callback must
    # also remain untouched with both policies configured.
    parent = self()
    reference = make_ref()

    callback = fn _, _, state ->
      send(parent, {reference, :crl_called})
      {:not_available, state}
    end

    cache = {__MODULE__.ForbiddenCRL, {{reference, callback}, []}}

    options =
      RevocationFixtures.options(directory, version) ++
        [stapling: :staple, crl_check: true, crl_cache: cache]

    lifecycle = lifecycle(true)

    try do
      result = connect(peer.port, options, :direct, lifecycle)

      if staple == :good do
        assert {:ok, socket} = result
        authenticated_payload(socket, directory)
        assert :ok = SSL.close(socket)
      else
        assert {:error, {:tls_alert, _}} = result
      end

      refute_receive {^reference, :crl_called}, 0
      assert_settled(lifecycle, :direct)
    after
      RevocationPeer.stop(peer)
      cancel(lifecycle)
    end
  end

  defmodule ForbiddenCRL do
    def lookup(point, issuer, {{_reference, callback}, []}), do: callback.(point, issuer, :unused)
    def select(issuer, {{_reference, callback}, []}), do: callback.(issuer, :select, :unused)
    def fresh_crl(point, crl), do: raise("unexpected CRL refresh #{inspect({point, crl})}")
  end

  defp authenticated_payload(socket, directory) do
    assert :ok = SSL.send(socket, "GET /root.der HTTP/1.0\r\n\r\n")
    expected = File.read!(Path.join(directory, "root.der"))
    bytes = receive_bytes(socket, <<>>, byte_size(expected) + 8_192)
    assert [header, ^expected] = :binary.split(bytes, "\r\n\r\n")
    assert header =~ "HTTP/1.0 200"
  end

  defp receive_bytes(socket, bytes, maximum) do
    assert byte_size(bytes) <= maximum

    case SSL.recv(socket, 0, 2_000) do
      {:ok, more} -> receive_bytes(socket, bytes <> more, maximum)
      {:error, :closed} -> bytes
    end
  end

  defp drain(reference, acc) do
    receive do
      {^reference, der, event, state} -> drain(reference, [{der, event, state} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp lifecycle(false), do: nil

  defp lifecycle(true) do
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
    {handle, lease}
  end

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

  defp assert_settled(nil, _), do: :ok

  defp assert_settled({handle, _}, route) do
    assert {:ok, receipt} = SSL.Lifecycle.await(handle, deadline(2_000))
    expected = if route == :direct, do: 31, else: 30
    assert receipt.version == 1 and receipt.cleanup == :confirmed
    assert receipt.roles == expected and receipt.observed_down == expected and receipt.losses == 0
    refute Map.has_key?(receipt, :auxiliary)
  end

  defp cancel(nil), do: :ok
  defp cancel({_, lease}), do: SSL.Lifecycle.cancel(lease, deadline(500))
  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp fixture_file(fixture) do
    case fixture do
      :missing -> nil
      :nonce_missing -> "good"
      :nonce_mismatch -> "nonce"
      :nonce_disabled_present -> "nonce"
      :wrong_target -> "wrong-target"
      :trusted_root -> "trusted-root"
      :no_eku -> "no-eku"
      value -> value |> Atom.to_string() |> String.replace("_", "-")
    end
  end

  defp fixture_directory(fixture, ocsp, extended, mutated) do
    cond do
      fixture in [:trusted_root, :delegated, :expired_delegated, :no_eku, :unrelated] ->
        extended

      fixture in [
        :future_produced,
        :future_this_update,
        :expired_next_update,
        :missing_next_update,
        :wrong_serial,
        :wrong_name_hash,
        :wrong_key_hash,
        :bad_signature,
        :unsupported_response,
        :unsuccessful_response
      ] ->
        mutated

      true ->
        ocsp
    end
  end
end

defmodule SSL.OCSPConstructedPeerIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for route <- [:direct, :prepared],
      managed <- [false, true],
      check <- [
        :both,
        :intermediate_only,
        :swapped,
        :nonce_match,
        :nonce_hrr,
        :fragmented,
        :cv,
        :finished,
        :aead,
        :duplicate,
        :malformed,
        :unsupported,
        :trailing,
        :unsolicited,
        :absent,
        :partial
      ] do
    test "TLS13 #{route} lifecycle=#{managed} constructed #{check}" do
      run_case(unquote(route), unquote(managed), unquote(check))
    end
  end

  defp run_case(route, managed, check) do
    directory = RevocationFixtures.directory!()

    configuration = peer_configuration(check)

    peer = RevocationPeer.start_tls13(directory, configuration)
    reference = make_ref()
    parent = self()

    verify = fn _, der, event, state ->
      send(parent, {reference, der, event})

      case event do
        {:bad_cert, _} -> {:fail, :rejected}
        {:extension, _} -> {:unknown, state + 1}
        _ -> {:valid, state + 1}
      end
    end

    options = RevocationFixtures.options(directory, :"tlsv1.3") ++ [verify_fun: {verify, 0}]

    options =
      if check == :unsolicited,
        do: options,
        else: options ++ [stapling: %{ocsp_nonce: check in [:nonce_match, :nonce_hrr]}]

    options =
      if check == :nonce_hrr,
        do: options ++ [supported_groups: [:x25519, :secp384r1]],
        else: options

    options =
      if check == :partial do
        issuer = File.read!(Path.join(directory, "intermediate.der"))

        options
        |> Keyword.put(:cacerts, [])
        |> Keyword.put(:partial_chain, fn _ -> {:trusted_ca, issuer} end)
      else
        options
      end

    lifecycle =
      if managed do
        {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
        {handle, lease}
      end

    try do
      result = connect(peer.port, options, route, lifecycle)

      assert_exchange(check, result)

      assert %{
               result: peer_result,
               status_request_count: count,
               nonce_present: present?,
               retry_nonce_unchanged: true
             } =
               RevocationPeer.join_tls13(peer)

      assert count == if(check == :unsolicited, do: 0, else: 1)
      assert present? == check in [:nonce_match, :nonce_hrr]

      if check in [:both, :nonce_match, :nonce_hrr, :fragmented, :partial],
        do: assert(peer_result == :authenticated),
        else: assert(match?({:rejected, _}, peer_result) or peer_result == :client_closed)

      assert_certificate_events(directory, check, reference)

      assert_lifecycle(lifecycle, route)
    after
      RevocationPeer.stop(peer)

      if lifecycle do
        {_, lease} = lifecycle
        SSL.Lifecycle.cancel(lease, deadline(500))
      end
    end
  end

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

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp peer_configuration(check) do
    case check do
      :nonce_match -> [echo_nonce: true]
      :nonce_hrr -> [echo_nonce: true, hrr: true]
      :fragmented -> [fragment: true]
      :partial -> [placement: :both]
      value when value in [:cv, :finished, :aead] -> [corrupt: value]
      value when value in [:unsolicited] -> []
      value -> [placement: value]
    end
  end

  defp assert_certificate_events(directory, check, reference) do
    leaf = File.read!(Path.join(directory, "leaf.der"))

    case check do
      value when value in [:intermediate_only, :absent] ->
        assert_receive {^reference, ^leaf, {:bad_cert, :missing_ocsp_staple}}, 500
        refute_receive {^reference, ^leaf, :valid_peer}, 0

      value when value in [:cv, :finished, :aead] ->
        assert_receive {^reference, ^leaf, :valid_peer}, 500
        refute_receive {^reference, ^leaf, {:bad_cert, _}}, 0

      :swapped ->
        # Validation visits I before L, so the response for L attached to I
        # must fail at I and cannot be reassigned by subject or list position.
        intermediate = File.read!(Path.join(directory, "intermediate.der"))

        assert_receive {^reference, ^intermediate, {:bad_cert, :revocation_status_undetermined}},
                       500

        refute_receive {^reference, ^leaf, :valid_peer}, 0

      _ ->
        :ok
    end
  end

  defp assert_lifecycle(lifecycle, route) do
    if lifecycle do
      {handle, _} = lifecycle
      expected = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{
                version: 1,
                cleanup: :confirmed,
                roles: ^expected,
                observed_down: ^expected,
                losses: 0
              } = receipt} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      refute Map.has_key?(receipt, :auxiliary)
    end
  end

  defp assert_exchange(check, result) do
    if check in [:both, :nonce_match, :nonce_hrr, :fragmented, :partial] do
      assert {:ok, socket} = result

      try do
        assert :ok = SSL.send(socket, "R49 ping")
        assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
      after
        SSL.close(socket)
      end
    else
      assert {:error, {:tls_alert, {alert, _}}} = result
      if check in [:cv, :finished], do: assert(alert == :decrypt_error)
      if check == :aead, do: assert(alert == :bad_record_mac)
    end
  end
end

defmodule SSL.OCSPNonceReuseIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for route <- [:direct, :prepared], nonce <- [false, true], hrr <- [false, true] do
    test "TLS13 #{route} nonce=#{nonce} HRR=#{hrr} regenerates per handshake with one prepared snapshot" do
      run_case(unquote(route), unquote(nonce), unquote(hrr))
    end
  end

  defp run_case(route, nonce, hrr) do
    directory = RevocationFixtures.directory!()

    options =
      RevocationFixtures.options(directory, :"tlsv1.3") ++ [stapling: %{ocsp_nonce: nonce}]

    options = if hrr, do: options ++ [supported_groups: [:x25519, :secp384r1]], else: options

    prepared =
      if route == :prepared do
        {:ok, prepared} = SSL.prepare_upgrade(options)
        prepared
      end

    observations =
      for _ <- 1..2 do
        peer = RevocationPeer.start_tls13(directory, echo_nonce: nonce, hrr: hrr)
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
                {:ok, tcp} =
                  :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

                SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
            end

          assert {:ok, socket} = result
          assert :ok = SSL.send(socket, "R49 ping")
          assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
          assert :ok = SSL.close(socket)
          observation = RevocationPeer.join_tls13(peer)

          assert %{
                   result: :authenticated,
                   status_request_count: 1,
                   nonce_present: ^nonce,
                   retry_nonce_unchanged: true
                 } = observation

          mask = if route == :direct, do: 31, else: 30

          assert {:ok,
                  %{
                    version: 1,
                    cleanup: :confirmed,
                    roles: ^mask,
                    observed_down: ^mask,
                    losses: 0
                  }} = SSL.Lifecycle.await(handle, deadline(2_000))

          observation
        after
          RevocationPeer.stop(peer)
          SSL.Lifecycle.cancel(lease, deadline(500))
        end
      end

    [first, second] = observations
    assert first.extension_ids == second.extension_ids
    assert byte_size(first.key_share_digest) == 32
    assert byte_size(second.key_share_digest) == 32
    refute first.key_share_digest == second.key_share_digest

    if nonce do
      assert byte_size(first.nonce_digest) == 32
      assert byte_size(second.nonce_digest) == 32
      refute first.nonce_digest == second.nonce_digest
    else
      assert first.nonce_digest == nil and second.nonce_digest == nil
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.OCSPTLS12WireIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for route <- [:direct, :prepared],
      status <- [
        :good,
        :fragmented,
        :not_negotiated,
        :omitted,
        :unsupported,
        :zero,
        :truncated,
        :trailing,
        :before_certificate,
        :after_ske,
        :duplicate,
        :unsolicited
      ] do
    test "TLS12 #{route} status #{status} actual authenticated wire" do
      run_case(unquote(route), :root, unquote(status), nil)
    end
  end

  for route <- [:direct, :prepared],
      anchor <- [:intermediate, :leaf],
      corrupt <- [nil, :ske, :finished, :aead] do
    test "TLS12 #{route} partial #{anchor} mutation=#{corrupt} keeps authentication" do
      run_case(unquote(route), unquote(anchor), :good, unquote(corrupt))
    end
  end

  for route <- [:direct, :prepared], corrupt <- [:ske, :finished, :aead] do
    test "TLS12 #{route} good OCSP does not bypass #{corrupt}" do
      run_case(unquote(route), :root, :good, unquote(corrupt))
    end
  end

  defp run_case(route, anchor, status, corrupt) do
    directory = RevocationFixtures.directory!()
    intermediate = File.read!(Path.join(directory, "intermediate.der"))
    leaf = File.read!(Path.join(directory, "leaf.der"))
    owner = self()
    reference = make_ref()

    verify = fn _, der, event, state ->
      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, _} ->
          send(owner, {reference, der, event})
          {:fail, :rejected}

        _ ->
          send(owner, {reference, der, event})
          {:valid, state}
      end
    end

    options = RevocationFixtures.options(directory, :"tlsv1.2") ++ [verify_fun: {verify, 0}]
    requested = anchor != :leaf and status != :unsolicited
    options = if requested, do: options ++ [stapling: :staple], else: options

    options = anchor_options(anchor, options, intermediate, leaf, owner, reference)

    peer_status = peer_status(anchor, status)

    peer =
      RevocationPeer.start_tls12(directory,
        status: peer_status,
        fragment: status == :fragmented,
        corrupt: corrupt
      )

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

      accepted = status in [:good, :fragmented] and corrupt == nil

      assert_exchange(accepted, result, corrupt)

      assert %{
               result: peer_result,
               status_request_count: count,
               negotiated: negotiated,
               extended_master_secret: true,
               transcript_includes_status: transcript_status
             } = RevocationPeer.join_tls13(peer)

      assert count == if(requested, do: 1, else: 0)
      assert negotiated == (peer_status != :not_negotiated)
      assert transcript_status == peer_status not in [:not_negotiated, :omitted]

      if accepted,
        do: assert(peer_result == :authenticated),
        else: assert(match?({:rejected, _}, peer_result) or peer_result == :client_closed)

      assert_certificate_events(anchor, status, accepted, corrupt, reference, intermediate, leaf)

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

  defp peer_status(anchor, status) do
    cond do
      anchor == :leaf -> :not_negotiated
      status == :fragmented -> :good
      status == :unsolicited -> :good
      true -> status
    end
  end

  defp assert_exchange(accepted, result, corrupt) do
    if accepted do
      assert {:ok, socket} = result
      assert :ok = SSL.send(socket, "R49 ping")
      assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
      assert :ok = SSL.close(socket)
    else
      assert {:error, {:tls_alert, {alert, _}}} = result
      if corrupt in [:ske, :finished], do: assert(alert == :decrypt_error)
      if corrupt == :aead, do: assert(alert == :bad_record_mac)
    end
  end

  defp assert_certificate_events(anchor, status, accepted, corrupt, reference, intermediate, leaf) do
    if anchor != :root do
      assert_receive {^reference, :partial, [^intermediate, ^leaf]}, 500
      refute_receive {^reference, :partial, _}, 0
    end

    if status in [:not_negotiated, :omitted] do
      assert_receive {^reference, ^leaf, {:bad_cert, :missing_ocsp_staple}}, 500
      refute_receive {^reference, ^leaf, :valid_peer}, 0
    end

    if (accepted or corrupt != nil) and anchor != :leaf do
      assert_receive {^reference, ^leaf, :valid_peer}, 500
      refute_receive {^reference, ^leaf, {:bad_cert, _}}, 0
    end
  end

  defp anchor_options(anchor, options, intermediate, leaf, owner, reference) do
    if anchor == :root do
      options
    else
      selected = if anchor == :intermediate, do: intermediate, else: leaf

      partial = fn path ->
        send(owner, {reference, :partial, path})
        {:trusted_ca, selected}
      end

      options |> Keyword.put(:cacerts, []) |> Keyword.put(:partial_chain, partial)
    end
  end
end

defmodule SSL.PolicyTemporalIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias SSL.PKIX.OCSP
  alias SSL.PKIX.Revocation

  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  def lookup(_, _, {ders, []}), do: ders
  def select(_, {ders, []}), do: ders
  def fresh_crl(_, current), do: current

  defp aligned_second do
    milliseconds = System.system_time(:millisecond)
    Process.sleep(1_020 - rem(milliseconds, 1_000))
    System.system_time(:second)
  end

  defp stamp(second),
    do:
      second
      |> DateTime.from_unix!()
      |> Calendar.strftime("%Y%m%d%H%M%SZ")
      |> String.to_charlist()

  defp utc(second),
    do:
      {:utcTime,
       second
       |> DateTime.from_unix!()
       |> Calendar.strftime("%y%m%d%H%M%SZ")
       |> String.to_charlist()}

  defp key(base) do
    [entry] = :public_key.pem_decode(File.read!(Path.join(base, "intermediate-key.pem")))
    :public_key.pem_entry_decode(entry)
  end

  test "OCSP exact live second boundary characterization", %{directory: base} do
    response = File.read!(Path.join(RevocationFixtures.ocsp_directory!(), "good.ocsp"))

    {:OCSPResponse, :successful, {:ResponseBytes, oid, bytes}} =
      :public_key.der_decode(:OCSPResponse, response)

    {:BasicOCSPResponse, data, algorithm, _, certs} =
      :public_key.der_decode(:BasicOCSPResponse, bytes)

    [single] = elem(data, 4)
    signing_key = key(base)

    {:ok, [leaf, issuer, root]} =
      SSL.PKIX.decode_chain(
        Enum.map(["leaf", "intermediate", "root"], &File.read!(Path.join(base, &1 <> ".der")))
      )

    selected = {root, [leaf, issuer]}
    now = aligned_second()

    for {field, offset} <-
          for(field <- [:produced, :this, :next], offset <- [-1, 0, 1], do: {field, offset}) ++
            [{:missing_next, 0}] do
      changed = single |> put_elem(3, stamp(now - 60)) |> put_elem(4, stamp(now + 60))

      changed =
        case field do
          :this -> put_elem(changed, 3, stamp(now + offset))
          :next -> put_elem(changed, 4, stamp(now + offset))
          :missing_next -> put_elem(changed, 4, :asn1_NOVALUE)
          _ -> changed
        end

      changed_data =
        data
        |> put_elem(3, stamp(if(field == :produced, do: now + offset, else: now - 60)))
        |> put_elem(4, [changed])

      signature =
        :public_key.sign(
          :public_key.der_encode(:ResponseData, changed_data),
          :sha256,
          signing_key
        )

      encoded =
        :public_key.der_encode(
          :BasicOCSPResponse,
          {:BasicOCSPResponse, changed_data, algorithm, signature, certs}
        )

      encoded =
        :public_key.der_encode(
          :OCSPResponse,
          {:OCSPResponse, :successful, {:ResponseBytes, oid, encoded}}
        )

      before = System.system_time(:second)

      oracle =
        :public_key.pkix_ocsp_validate(leaf.decoded, issuer.decoded, encoded, :undefined, [])

      actual =
        OCSP.check(
          leaf.decoded,
          leaf.der,
          :valid_peer,
          selected,
          [root],
          [{leaf.der, encoded}],
          :undefined
        )

      after_time = System.system_time(:second)

      IO.puts(
        JSON.encode!(%{
          temporal: :ocsp,
          field: field,
          offset: offset,
          before: before,
          after: after_time,
          fixture_clock: now,
          oracle: inspect(oracle),
          actual: inspect(actual)
        })
      )

      assert before == now and after_time == now

      expected_valid =
        not ((field in [:produced, :this] and offset == 1) or (field == :next and offset == -1))

      assert actual == :valid_peer == expected_valid
    end
  end

  test "CRL exact live second and missing-next characterization", %{directory: base} do
    {:CertificateList, tbs, algorithm, _} =
      :public_key.der_decode(:CertificateList, File.read!(Path.join(base, "leaf-good.crl.der")))

    signing_key = key(base)

    {:ok, [leaf, issuer, root]} =
      SSL.PKIX.decode_chain(
        Enum.map(["leaf", "intermediate", "root"], &File.read!(Path.join(base, &1 <> ".der")))
      )

    selected = {root, [leaf, issuer]}
    now = aligned_second()

    for {field, offset} <-
          for(field <- [:this, :next], offset <- [-1, 0, 1], do: {field, offset}) ++
            [{:missing_next, 0}] do
      changed = tbs |> put_elem(4, utc(now - 60)) |> put_elem(5, utc(now + 60))

      changed =
        case field do
          :this -> put_elem(changed, 4, utc(now + offset))
          :next -> put_elem(changed, 5, utc(now + offset))
          :missing_next -> put_elem(changed, 5, :asn1_NOVALUE)
        end

      signature =
        :public_key.sign(:public_key.der_encode(:TBSCertList, changed), :sha256, signing_key)

      encoded =
        :public_key.der_encode(
          :CertificateList,
          {:CertificateList, changed, algorithm, signature}
        )

      policy = %{crl_check: :peer, crl_cache: {__MODULE__, {[encoded], []}}}
      context = %SSL.PolicyIO.Context{deadline: System.monotonic_time(:millisecond) + 5000}
      before = System.system_time(:second)

      actual =
        try do
          Revocation.check(
            context,
            policy,
            leaf.decoded,
            leaf.der,
            :valid_peer,
            selected,
            [leaf, issuer, root],
            []
          )
        rescue
          FunctionClauseError -> :primitive_missing_next_clause
        end

      after_time = System.system_time(:second)

      IO.puts(
        JSON.encode!(%{
          temporal: :crl,
          field: field,
          offset: offset,
          before: before,
          after: after_time,
          fixture_clock: now,
          actual: inspect(actual)
        })
      )

      assert before == now and after_time == now

      expected =
        cond do
          field == :missing_next -> :primitive_missing_next_clause
          field == :this and offset == 1 -> {:bad_cert, :revocation_status_undetermined}
          field == :next and offset <= 0 -> {:bad_cert, :revocation_status_undetermined}
          true -> :valid_peer
        end

      assert actual == expected
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      mode <- [true, :peer, :best_effort] do
    test "#{version} #{route} #{mode} absent CRL nextUpdate fails closed with sanitized policy error",
         %{directory: base} do
      missing_next(base, unquote(version), unquote(route), unquote(mode), :candidate)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "OTP28 #{version} missing CRL nextUpdate reference", %{directory: base} do
      {:ok, _} = Application.ensure_all_started(:ssl)
      missing_next(base, unquote(version), :direct, :peer, :otp)
    end
  end

  defp missing_next(base, version, route, mode, provider) do
    {:CertificateList, tbs, algorithm, _} =
      :public_key.der_decode(:CertificateList, File.read!(Path.join(base, "leaf-good.crl.der")))

    tbs = put_elem(tbs, 5, :asn1_NOVALUE)
    signature = :public_key.sign(:public_key.der_encode(:TBSCertList, tbs), :sha256, key(base))

    encoded =
      :public_key.der_encode(:CertificateList, {:CertificateList, tbs, algorithm, signature})

    root_good = File.read!(Path.join(base, "root-good.crl.der"))

    options =
      RevocationFixtures.options(base, version) ++
        [crl_check: mode, crl_cache: {__MODULE__, {[encoded, root_good], []}}]

    peer = RevocationPeer.start(base, version)

    {:ok, handle, lease} =
      SSL.Lifecycle.new(
        controller: self(),
        deadline: {:abs_ms, System.monotonic_time(:millisecond) + 5_000}
      )

    try do
      result =
        case {provider, route} do
          {:otp, :direct} ->
            :ssl.connect(~c"127.0.0.1", peer.port, options, 5_000)

          {:candidate, :direct} ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              options ++ [ex_ssl: [lifecycle: {handle, lease}]],
              5_000
            )

          {:candidate, :prepared} ->
            {:ok, prepared} = SSL.prepare_upgrade(options)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
        end

      if match?({:ok, _}, result) do
        if provider == :otp, do: :ssl.close(elem(result, 1)), else: SSL.close(elem(result, 1))
      end

      assert {:error, {:tls_alert, _}} = result

      if provider == :candidate do
        refute inspect(result) =~ "FunctionClauseError"
        refute inspect(result) =~ "time_str_2_gregorian_sec"
        mask = if route == :direct, do: 31, else: 30

        assert {:ok,
                %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
                 SSL.Lifecycle.await(
                   handle,
                   {:abs_ms, System.monotonic_time(:millisecond) + 2_000}
                 )
      end
    after
      RevocationPeer.stop(peer)
      SSL.Lifecycle.cancel(lease, {:abs_ms, System.monotonic_time(:millisecond) + 500})
    end
  end
end

defmodule SSL.OCSPCrossIssuerIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for route <- [:direct, :prepared], fixture <- [:selected_cross, :same_subject_original] do
    test "TLS13 #{route} #{fixture} OCSP binds exact cross-signed selected issuer" do
      run_case(unquote(route), unquote(fixture))
    end
  end

  defp run_case(route, fixture) do
    base = RevocationFixtures.directory!()
    read = fn name -> File.read!(Path.join(base, name <> ".der")) end
    root = read.("other-root")
    cross = read.("intermediate-cross")
    leaf = read.("leaf")
    ref = make_ref()
    owner = self()

    partial = fn path ->
      send(owner, {ref, :path, path})
      {:trusted_ca, root}
    end

    verify = fn _, der, event, state ->
      role =
        cond do
          der == cross -> :cross
          der == leaf -> :leaf
          true -> :unexpected
        end

      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, reason} ->
          send(owner, {ref, role, {:bad_cert, reason}})
          {:fail, :rejected}

        other ->
          send(owner, {ref, role, other})
          {:valid, state}
      end
    end

    options =
      RevocationFixtures.options(base, :"tlsv1.3") |> Keyword.update!(:cacerts, &(&1 ++ [root]))

    options = options ++ [partial_chain: partial, verify_fun: {verify, nil}, stapling: :staple]

    response = fixture_response(fixture)

    peer =
      RevocationPeer.start_tls13(base,
        placement: :both,
        intermediate: "intermediate-cross",
        issuer_response: response
      )

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

      assert_receive {^ref, :path, [^root, ^cross, ^leaf]}, 500
      refute_receive {^ref, :path, _}, 0

      if fixture == :selected_cross do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "R49 ping")
        assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
        assert :ok = SSL.close(socket)
        assert_receive {^ref, :cross, :valid}, 500
        assert_receive {^ref, :leaf, :valid_peer}, 500
        refute_receive {^ref, _, {:bad_cert, _}}, 0
      else
        if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
        assert {:error, {:tls_alert, _}} = result
        assert_receive {^ref, :cross, {:bad_cert, :revocation_status_undetermined}}, 500
        refute_receive {^ref, :cross, :valid}, 0
        refute_receive {^ref, :leaf, _}, 0
      end

      refute_receive {^ref, :unexpected, _}, 0
      assert %{result: observed} = RevocationPeer.join_tls13(peer)

      if fixture == :selected_cross,
        do: assert(observed == :authenticated),
        else: assert(match?({:rejected, _}, observed))

      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp fixture_response(fixture) do
    case fixture do
      :selected_cross ->
        File.read!(Path.join(RevocationFixtures.ocsp_extended!(), "cross-intermediate.ocsp"))

      :same_subject_original ->
        File.read!(Path.join(RevocationFixtures.ocsp_directory!(), "wrong-target.ocsp"))
    end
  end
end

defmodule SSL.OCSPWireSizeIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"], route <- [:direct, :prepared], delta <- [-1, 0, 1] do
    test "#{version} #{route} signed OCSP wire size boundary #{delta}" do
      run_case(unquote(version), unquote(route), unquote(delta))
    end
  end

  defp run_case(version, route, delta) do
    base = RevocationFixtures.directory!()

    {:ok, [leaf, issuer, root]} =
      SSL.PKIX.decode_chain(
        Enum.map(["leaf", "intermediate", "root"], &File.read!(Path.join(base, &1 <> ".der")))
      )

    peer_options =
      if version == :"tlsv1.2" do
        # OTP 28 caps OCSP DER at 100 KiB; OTP 29 accepts the signed N+1 input.
        # The provider retains its own 100 KiB boundary on both runtimes.
        response = RevocationFixtures.padded_ocsp!(base, :leaf, 102_400 + delta)
        assert_signed(response, issuer)

        oracle =
          :public_key.pkix_ocsp_validate(leaf.decoded, issuer.decoded, response, :undefined, [])

        cond do
          delta <= 0 ->
            assert {:ok, _} = oracle

          :erlang.system_info(:otp_release) == ~c"29" ->
            assert {:ok, []} = oracle

          true ->
            assert {:error,
                    {:bad_cert,
                     {:revocation_status_undetermined, {:ocsp_response_too_large, 102_401}}}} =
                     oracle
        end

        [status: :good, response: response]
      else
        # Each entry is legal independently; their combined extension bytes
        # cross 65535 only at N+1 (eight framing bytes per response).
        response = RevocationFixtures.padded_ocsp!(base, :leaf, 32_760 + delta)
        issuer_response = RevocationFixtures.padded_ocsp!(base, :issuer, 32_759)

        assert {:ok, _} =
                 :public_key.pkix_ocsp_validate(
                   leaf.decoded,
                   issuer.decoded,
                   response,
                   :undefined,
                   []
                 )

        assert {:ok, _} =
                 :public_key.pkix_ocsp_validate(
                   issuer.decoded,
                   root.decoded,
                   issuer_response,
                   :undefined,
                   []
                 )

        assert byte_size(response) + byte_size(issuer_response) + 16 == 65_535 + delta
        [placement: :both, response: response, issuer_response: issuer_response]
      end

    peer =
      if version == :"tlsv1.2",
        do: RevocationPeer.start_tls12(base, peer_options),
        else: RevocationPeer.start_tls13(base, peer_options)

    options = RevocationFixtures.options(base, version) ++ [stapling: :staple]
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

      if delta <= 0 do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "R49 ping")
        assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
        assert :ok = SSL.close(socket)
      else
        if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
        assert {:error, {:tls_alert, _}} = result
      end

      assert %{result: observed} = RevocationPeer.join_tls13(peer)

      if delta <= 0,
        do: assert(observed == :authenticated),
        else: assert(match?({:rejected, _}, observed))

      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp assert_signed(response, issuer) do
    {:OCSPResponse, :successful, {:ResponseBytes, _, basic}} =
      :public_key.der_decode(:OCSPResponse, response)

    {:BasicOCSPResponse, data, _, signature, _} =
      :public_key.der_decode(:BasicOCSPResponse, basic)

    public = issuer.decoded |> elem(1) |> elem(7) |> elem(2)

    assert :public_key.verify(
             :public_key.der_encode(:ResponseData, data),
             :sha256,
             signature,
             public
           )
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.OCSPListBoundsIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias SSL.PolicyIO.Bounded

  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      kind <- [:responses, :responders],
      delta <- [-1, 0, 1] do
    test "#{version} #{route} signed OCSP #{kind} boundary #{delta}" do
      run_case(unquote(version), unquote(route), unquote(kind), unquote(delta))
    end
  end

  defp run_case(version, route, kind, delta) do
    base = RevocationFixtures.directory!()

    {:ok, [leaf, issuer]} =
      SSL.PKIX.decode_chain(
        Enum.map(["leaf", "intermediate"], &File.read!(Path.join(base, &1 <> ".der")))
      )

    original = File.read!(Path.join(RevocationFixtures.ocsp_directory!(), "good.ocsp"))

    {:OCSPResponse, :successful, {:ResponseBytes, oid, basic}} =
      :public_key.der_decode(:OCSPResponse, original)

    {:BasicOCSPResponse, data, algorithm, _, certs} =
      :public_key.der_decode(:BasicOCSPResponse, basic)

    [entry] = :public_key.pem_decode(File.read!(Path.join(base, "intermediate-key.pem")))
    key = :public_key.pem_entry_decode(entry)

    {data, certs} =
      case kind do
        :responses -> {put_elem(data, 4, List.duplicate(hd(elem(data, 4)), 128 + delta)), certs}
        :responders -> {data, List.duplicate(hd(certs), 32 + delta)}
      end

    signature = :public_key.sign(:public_key.der_encode(:ResponseData, data), :sha256, key)

    response =
      :public_key.der_encode(
        :OCSPResponse,
        {:OCSPResponse, :successful,
         {:ResponseBytes, oid,
          :public_key.der_encode(
            :BasicOCSPResponse,
            {:BasicOCSPResponse, data, algorithm, signature, certs}
          )}}
      )

    assert_signed(response, issuer)
    # The underlying primitive accepts every signed fixture. The candidate's
    # independent bounded admission rejects only N+1 before policy decoding.
    assert {:ok, _} =
             :public_key.pkix_ocsp_validate(
               leaf.decoded,
               issuer.decoded,
               response,
               :undefined,
               []
             )

    material = Bounded.der(response, :ocsp)

    if delta <= 0,
      do: assert(match?({:ok, _}, material)),
      else: assert(material == {:error, :policy_capacity})

    peer_options =
      if version == :"tlsv1.2",
        do: [status: :good, response: response],
        else: [placement: :leaf, response: response]

    peer =
      if version == :"tlsv1.2",
        do: RevocationPeer.start_tls12(base, peer_options),
        else: RevocationPeer.start_tls13(base, peer_options)

    options = RevocationFixtures.options(base, version) ++ [stapling: :staple]
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

      if delta <= 0 do
        assert {:ok, socket} = result
        assert :ok = SSL.send(socket, "R49 ping")
        assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
        assert :ok = SSL.close(socket)
      else
        if match?({:ok, _}, result), do: SSL.close(elem(result, 1))
        assert {:error, {:tls_alert, _}} = result
      end

      assert %{result: observed} = RevocationPeer.join_tls13(peer)

      if delta <= 0,
        do: assert(observed == :authenticated),
        else: assert(match?({:rejected, _}, observed))

      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp assert_signed(response, issuer) do
    {:OCSPResponse, :successful, {:ResponseBytes, _, basic}} =
      :public_key.der_decode(:OCSPResponse, response)

    {:BasicOCSPResponse, data, _, signature, _} =
      :public_key.der_decode(:BasicOCSPResponse, basic)

    public = issuer.decoded |> elem(1) |> elem(7) |> elem(2)

    assert :public_key.verify(
             :public_key.der_encode(:ResponseData, data),
             :sha256,
             signature,
             public
           )
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.OCSPRequiredWireIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      setting <- [:absent, :no_staple, :staple, :empty_map, :false_map, :true_map] do
    test "#{version} #{route} #{setting} exact default status-request wire" do
      wire_case(unquote(version), unquote(route), unquote(setting), :default)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      nonce <- [false, true],
      position <- [:first, :middle, :last] do
    test "#{version} #{route} nonce=#{nonce} explicit status-request profile position #{position}" do
      wire_case(
        unquote(version),
        unquote(route),
        if(unquote(nonce), do: :true_map, else: :false_map),
        unquote(position)
      )
    end
  end

  for route <- [:direct, :prepared], nonce <- [false, true] do
    test "TLS12 #{route} nonce=#{nonce} fresh two-handshake signed echo" do
      base = RevocationFixtures.directory!()

      options =
        RevocationFixtures.options(base, :"tlsv1.2") ++ [stapling: %{ocsp_nonce: unquote(nonce)}]

      prepared =
        if unquote(route) == :prepared do
          {:ok, value} = SSL.prepare_upgrade(options)
          value
        end

      observations =
        for _ <- 1..2 do
          peer = RevocationPeer.start_tls12(base, status: :good, echo_nonce: unquote(nonce))
          exchange(peer, options, unquote(route), prepared)
        end

      [first, second] = observations
      assert first.status_request_count == 1 and second.status_request_count == 1
      assert first.nonce_present == unquote(nonce) and second.nonce_present == unquote(nonce)
      refute first.client_random_digest == second.client_random_digest

      if unquote(nonce) do
        assert byte_size(first.nonce_digest) == 32 and byte_size(second.nonce_digest) == 32
        refute first.nonce_digest == second.nonce_digest
      else
        assert first.nonce_digest == nil and second.nonce_digest == nil
      end
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      conflict <- [:missing, :nonce_mismatch, :raw, :disabled] do
    test "#{version} explicit #{conflict} profile conflicts before dial" do
      base = RevocationFixtures.directory!()
      options = RevocationFixtures.options(base, unquote(version))
      {:ok, normalized} = SSL.Options.normalize(~c"127.0.0.1", options)

      extra =
        case unquote(conflict) do
          :missing -> []
          :nonce_mismatch -> [{:status_request, true}]
          :raw -> [{:raw, 5, <<1, 0::16, 0::16>>}]
          :disabled -> [{:status_request, false}]
        end

      profile = %{normalized.profile | extensions: normalized.profile.extensions ++ extra}

      options =
        options ++
          [
            stapling: if(unquote(conflict) == :disabled, do: :no_staple, else: :staple),
            ex_ssl: [profile: profile]
          ]

      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, {_, port}} = :inet.sockname(listener)

      try do
        assert {:error, {:options, {:stapling, :profile_conflict}}} =
                 SSL.connect(~c"127.0.0.1", port, options, 500)

        assert {:error, {:options, {:stapling, :profile_conflict}}} = SSL.prepare_upgrade(options)
        assert {:error, :timeout} = :gen_tcp.accept(listener, 50)
      after
        :gen_tcp.close(listener)
      end
    end
  end

  defp wire_case(version, route, setting, position) do
    base = RevocationFixtures.directory!()
    options = RevocationFixtures.options(base, version)
    {:ok, baseline} = SSL.Options.normalize(~c"127.0.0.1", options)
    enabled = setting not in [:absent, :no_staple]
    nonce = setting == :true_map

    settings = stapling_settings(setting)

    slot =
      case position do
        :first -> 0
        :middle -> 2
        _ -> length(baseline.profile.extensions)
      end

    options =
      if position == :default do
        options ++ settings
      else
        extensions = List.insert_at(baseline.profile.extensions, slot, {:status_request, nonce})
        options ++ settings ++ [ex_ssl: [profile: %{baseline.profile | extensions: extensions}]]
      end

    peer =
      if version == :"tlsv1.2",
        do:
          RevocationPeer.start_tls12(base,
            status: if(enabled, do: :good, else: :not_negotiated),
            echo_nonce: nonce
          ),
        else:
          RevocationPeer.start_tls13(base,
            placement: if(enabled, do: :leaf, else: :absent),
            echo_nonce: nonce
          )

    observed = exchange(peer, options, route, nil)
    assert observed.status_request_count == if(enabled, do: 1, else: 0)
    assert observed.nonce_present == nonce
    expected = Enum.map(baseline.profile.extensions, &extension_id/1)
    expected = if enabled, do: List.insert_at(expected, slot, 5), else: expected
    assert observed.extension_ids == expected
  end

  defp exchange(peer, options, route, prepared) do
    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))

    try do
      result =
        case route do
          :direct ->
            SSL.connect(
              ~c"127.0.0.1",
              peer.port,
              Keyword.update(
                options,
                :ex_ssl,
                [lifecycle: {handle, lease}],
                &(&1 ++ [lifecycle: {handle, lease}])
              ),
              5_000
            )

          :prepared ->
            prepared =
              if prepared,
                do: prepared,
                else:
                  (case SSL.prepare_upgrade(options) do
                     {:ok, value} -> value
                   end)

            {:ok, tcp} =
              :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

            SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: {handle, lease}]], 5_000)
        end

      assert {:ok, socket} = result
      assert :ok = SSL.send(socket, "R49 ping")
      assert {:ok, "R49 pong"} = SSL.recv(socket, 8, 2_000)
      assert :ok = SSL.close(socket)
      assert %{result: :authenticated} = observed = RevocationPeer.join_tls13(peer)
      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))

      observed
    after
      SSL.Lifecycle.cancel(lease, deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp extension_id({name, _}),
    do:
      %{
        server_name: 0,
        supported_versions: 43,
        supported_groups: 10,
        signature_algorithms: 13,
        key_share: 51,
        ec_point_formats: 11,
        extended_master_secret: 23,
        renegotiation_info: 65_281,
        signature_algorithms_cert: 50,
        alpn: 16
      }[name]

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp stapling_settings(setting) do
    case setting do
      :absent -> []
      :no_staple -> [stapling: :no_staple]
      :staple -> [stapling: :staple]
      :empty_map -> [stapling: %{}]
      :false_map -> [stapling: %{ocsp_nonce: false}]
      :true_map -> [stapling: %{ocsp_nonce: true}]
    end
  end
end

defmodule SSL.OCSPPrecedenceRoutesIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}

  def lookup(_, _, {data, []}) do
    send(data.owner, {data.ref, :crl_called})
    [data.leaf_crl, data.root_crl]
  end

  def select(_, {data, []}) do
    send(data.owner, {data.ref, :crl_called})
    [data.leaf_crl, data.root_crl]
  end

  def fresh_crl(_, current), do: current

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      staple <- [:good, :revoked, :missing],
      override <- [false, true] do
    test "#{version} #{route} #{staple} OCSP opposite CRL and explicit override=#{override}" do
      run_case(
        unquote(version),
        unquote(route),
        unquote(staple),
        unquote(override),
        :candidate,
        false
      )
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      staple <- [:good, :revoked, :missing],
      override <- [false, true] do
    test "observed reference difference: OTP28 #{version} #{staple} explicit override=#{override}" do
      {:ok, _} = Application.ensure_all_started(:ssl)
      run_case(unquote(version), :direct, unquote(staple), unquote(override), :otp, false)
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :prepared],
      crl <- [:good, :revoked] do
    test "#{version} #{route} disabled OCSP exposes actual #{crl} CRL control" do
      run_case(unquote(version), unquote(route), unquote(crl), false, :candidate, true)
    end
  end

  defp run_case(version, route, staple, override, provider, disabled) do
    base = RevocationFixtures.directory!()
    ocsp = RevocationFixtures.ocsp_directory!()
    read = fn name -> File.read!(Path.join(base, name)) end
    leaf = :public_key.pkix_decode_cert(read.("leaf.der"), :otp)
    ref = make_ref()
    owner = self()
    crl_status = if disabled, do: staple, else: if(staple == :good, do: :revoked, else: :good)

    data = %{
      owner: owner,
      ref: ref,
      leaf_crl: read.("leaf-#{crl_status}.crl.der"),
      root_crl: read.("root-good.crl.der")
    }

    verify = verification_callback(owner, ref, leaf, override)

    options =
      RevocationFixtures.options(base, version) ++
        [
          stapling: if(disabled, do: :no_staple, else: :staple),
          crl_check: true,
          crl_cache: {__MODULE__, {data, []}},
          verify_fun: {verify, 0}
        ]

    extra =
      if not disabled and staple != :missing,
        do: ["-status_file", Path.join(ocsp, "#{staple}.ocsp")],
        else: []

    peer = RevocationPeer.start(base, version, extra)

    lifecycle =
      if provider == :candidate do
        {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: deadline(5_000))
        {handle, lease}
      end

    try do
      result = connect_provider(provider, route, peer, options, lifecycle)

      observed_events = collect(ref, [])

      report_otp_precedence(provider, version, staple, override, result, observed_events)

      accepted =
        if provider == :otp,
          do: override,
          else: if(disabled, do: staple == :good, else: staple == :good or override)

      assert_exchange(accepted, result, provider, read)

      if disabled do
        assert_receive {^ref, :crl_called}, 500
      else
        refute_receive {^ref, :crl_called}, 0
      end

      events = observed_events

      relevant =
        for {true, event, state} <- events,
            event == :valid_peer or match?({:bad_cert, _}, event),
            do: {event, state}

      assert_precedence(provider, staple, override, events, disabled, relevant)

      assert_lifecycle(lifecycle, route)
    after
      if lifecycle, do: SSL.Lifecycle.cancel(elem(lifecycle, 1), deadline(500))
      RevocationPeer.stop(peer)
    end
  end

  defp collect(ref, acc) do
    receive do
      {^ref, :verify, leaf, event, state} -> collect(ref, [{leaf, event, state} | acc])
    after
      0 -> Enum.reverse(acc)
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

  defp assert_exchange(accepted, result, provider, read) do
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
  end

  defp assert_precedence(provider, staple, override, events, disabled, relevant) do
    if provider == :otp do
      expected =
        case {staple, override} do
          {:missing, false} ->
            [{false, :valid, 0}, {false, {:bad_cert, :missing_ocsp_staple}, 1}]

          {:missing, true} ->
            [
              {false, :valid, 0},
              {false, {:bad_cert, :missing_ocsp_staple}, 1},
              {true, :valid_peer, 2},
              {true, {:bad_cert, :missing_ocsp_staple}, 3}
            ]

          _ ->
            [
              {false, :valid, 0},
              {true,
               {:bad_cert, {:revocation_status_undetermined, :ocsp_responder_cert_not_found}}, 1}
            ]
        end

      assert events == expected
    end

    if not disabled and provider == :candidate do
      if staple == :good do
        assert Enum.any?(relevant, fn {event, _} -> event == :valid_peer end)
        refute Enum.any?(relevant, fn {event, _} -> match?({:bad_cert, _}, event) end)
      else
        bad = Enum.filter(relevant, fn {event, _} -> match?({:bad_cert, _}, event) end)
        assert length(bad) == 1
        [{{:bad_cert, reason}, _}] = bad

        if staple == :missing,
          do: assert(reason == :missing_ocsp_staple),
          else: assert(match?({:revoked, _}, reason))

        if provider == :candidate, do: assert(length(relevant) == 1)
      end
    end
  end

  defp assert_lifecycle(lifecycle, route) do
    if lifecycle do
      {handle, _} = lifecycle
      mask = if route == :direct, do: 31, else: 30

      assert {:ok,
              %{version: 1, cleanup: :confirmed, roles: ^mask, observed_down: ^mask, losses: 0}} =
               SSL.Lifecycle.await(handle, deadline(2_000))
    end
  end

  defp connect_provider(provider, route, peer, options, lifecycle) do
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
  end

  defp report_otp_precedence(provider, version, staple, override, result, observed_events) do
    if provider == :otp,
      do:
        IO.puts(
          JSON.encode!(%{
            otp_precedence: true,
            version: version,
            staple: staple,
            override: override,
            accepted: match?({:ok, _}, result),
            events:
              Enum.map(observed_events, fn {leaf, event, state} ->
                %{leaf: leaf, event: inspect(event), state: state}
              end)
          })
        )
  end

  defp verification_callback(owner, ref, leaf, override) do
    fn certificate, event, state ->
      case event do
        {:extension, _} ->
          {:unknown, state}

        {:bad_cert, reason} ->
          send(owner, {ref, :verify, certificate == leaf, {:bad_cert, reason}, state})
          if override, do: {:valid, state + 1}, else: {:fail, :explicit_rejection}

        _ ->
          send(owner, {ref, :verify, certificate == leaf, event, state})
          {:valid, state + 1}
      end
    end
  end
end

defmodule SSL.OCSPBudgetPrecedenceIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.RevocationFixtures
  alias SSL.PKIX.OCSP
  alias SSL.PolicyIO

  setup_all do
    base = RevocationFixtures.directory!()
    response = RevocationFixtures.padded_ocsp!(base, :leaf, 102_401)
    {:ok, response: response}
  end

  defp check(response) do
    {:return, OCSP.check(nil, :leaf, :valid_peer, nil, [], [{:leaf, response}], nil)}
  catch
    :throw, reason -> {:throw, reason}
  end

  test "hard material size takes precedence over callback-visible OCSP rejection" do
    with_clean_policy_state(fn ->
      result = check(:binary.copy(<<0>>, 16_777_217))
      assert result == {:throw, :policy_capacity}
      assert Process.get({PolicyIO, :failure}) == :policy_capacity
    end)
  end

  test "prior admitted bytes retain their cumulative bound", %{response: response} do
    with_clean_policy_state(fn ->
      assert :ok = PolicyIO.charge(:bytes, 33_554_432 - byte_size(response) + 1, 33_554_432)
      assert check(response) == {:throw, :policy_capacity}
      assert Process.get({PolicyIO, :failure}) == :policy_capacity
    end)
  end

  test "prior admitted nodes retain their cumulative bound", %{response: response} do
    with_clean_policy_state(fn ->
      assert :ok = PolicyIO.charge(:nodes, 65_536, 65_536)
      assert check(response) == {:throw, :policy_capacity}
      assert Process.get({PolicyIO, :failure}) == :policy_capacity
    end)
  end

  test "callback-visible size rejection still charges admitted DER", %{response: response} do
    with_clean_policy_state(fn ->
      assert check(response) == {:return, {:bad_cert, :revocation_status_undetermined}}
      budget = Process.get({PolicyIO, :budget}, %{bytes: 0, nodes: 0})
      assert budget.bytes == byte_size(response)
      assert budget.nodes > 0
    end)
  end

  defp with_clean_policy_state(fun) do
    Process.delete({PolicyIO, :budget})
    Process.delete({PolicyIO, :failure})

    try do
      fun.()
    after
      Process.delete({PolicyIO, :budget})
      Process.delete({PolicyIO, :failure})
    end
  end
end
