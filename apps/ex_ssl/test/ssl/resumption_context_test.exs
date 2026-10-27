defmodule SSL.ResumptionContextTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias SSL.{Options, ResumptionContext, SessionTicket, TicketCache}
  alias ExSSL.TestSupport.ClientAuthFixtures
  @host {127, 0, 0, 1}

  setup_all do
    dir = Path.join(System.tmp_dir!(), "ticket-policy-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(dir) end)
    %{fixtures: ClientAuthFixtures.create(dir), dir: dir}
  end

  test "automatic tickets reject public none-mode options", %{fixtures: f} do
    options = Keyword.merge(base(f), verify: :verify_none)

    assert {:error, {:options, {:session_tickets, :verify_peer_required}}} =
             Options.normalize(@host, options)
  end

  test "injected internal none-mode cache entries cannot satisfy peer validation", %{
    fixtures: f
  } do
    peer = normalized(f, server_name_indication: ~c"wrong.example.test")
    # Public normalization rejects none-mode auto tickets. Inject only the internal
    # verification mode to exercise defensive handling of legacy or misplaced state.
    none = %{peer | verify: :verify_none}
    endpoint = {@host, 443}
    none_key = ResumptionContext.partition(none, endpoint)
    peer_key = ResumptionContext.partition(peer, endpoint)
    refute none_key == peer_key
    cached = ticket([f.server.der])
    assert :ok = TicketCache.put(none_key, cached)
    assert {:ok, _, selected, ^none_key} = ResumptionContext.prepare(none, endpoint)
    assert selected.peer.leaf_der == f.server.der
    assert {:ok, _, nil, ^peer_key} = ResumptionContext.prepare(peer, endpoint)

    # Even a deliberately misplaced cache entry still faces the current peer policy.
    assert :ok = TicketCache.put(peer_key, cached)
    assert {:ok, _, nil, ^peer_key} = ResumptionContext.prepare(peer, endpoint)
    assert :ok = TicketCache.put(none_key, ticket([<<1, 2, 3>>]))
    assert {:ok, _, nil, ^none_key} = ResumptionContext.prepare(none, endpoint)

    [entry] = :public_key.pem_decode(File.read!(f.ca.key))
    issuer_key = :public_key.pem_entry_decode(entry)
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(f.ca.der, :otp)

    legacy_root =
      :public_key.pkix_sign(tbs |> put_elem(1, :v1) |> put_elem(10, :asn1_NOVALUE), issuer_key)

    assert :ok = TicketCache.put(none_key, ticket([f.server.der, legacy_root]))
    assert {:ok, _, nil, ^none_key} = ResumptionContext.prepare(none, endpoint)
  end

  test "every authentication context participates in partition identity", %{fixtures: f} do
    options = normalized(f)
    endpoint = {@host, 443}
    base = ResumptionContext.partition(options, endpoint)

    variants = [
      %{options | endpoint: ~c"other.test"},
      %{options | identity: {:dns_id, ~c"other.test"}},
      %{options | trust_source: [f.wrong.der]},
      %{options | depth: options.depth + 1},
      %{options | hostname_check: [match_fun: fn _, _ -> false end]},
      %{
        options
        | profile: %{options.profile | cipher_suites: Enum.reverse(options.profile.cipher_suites)}
      },
      normalized(f, alpn_advertised_protocols: ["h2"]),
      normalized(f, supported_groups: [:secp384r1]),
      normalized(f, signature_algs: [:rsa_pss_rsae_sha256])
    ]

    for changed <- variants, do: refute(ResumptionContext.partition(changed, endpoint) == base)
    refute ResumptionContext.partition(options, {@host, 444}) == base
    refute ResumptionContext.partition(options, {{127, 0, 0, 2}, 443}) == base
  end

  test "replacing a trust file at the same path changes the partition", %{fixtures: f, dir: dir} do
    path = Path.join(dir, "mutable-trust.pem")
    File.cp!(f.ca.certificate, path)
    opts = [cacertfile: path, session_tickets: :auto]
    assert {:ok, before} = Options.normalize(@host, opts)
    File.cp!(f.wrong.certificate, path)
    assert {:ok, after_change} = Options.normalize(@host, opts)

    refute ResumptionContext.partition(before, {@host, 443}) ==
             ResumptionContext.partition(after_change, {@host, 443})
  end

  test "explicit reference identity and independent SNI both partition tickets", %{fixtures: f} do
    options =
      normalized(f,
        server_name_indication: ~c"routing.test",
        ex_ssl: [reference_identity: {:ip, "127.0.0.1"}]
      )

    partition = ResumptionContext.partition(options, {@host, 443})
    assert :ok = TicketCache.put(partition, ticket([f.server.der]))

    for changed <- [
          normalized(f,
            server_name_indication: ~c"other-routing.test",
            ex_ssl: [reference_identity: {:ip, "127.0.0.1"}]
          ),
          normalized(f,
            server_name_indication: :disable,
            ex_ssl: [reference_identity: {:ip, "127.0.0.1"}]
          ),
          normalized(f,
            server_name_indication: ~c"routing.test",
            ex_ssl: [reference_identity: {:ip, "::1"}]
          )
        ] do
      changed_partition = ResumptionContext.partition(changed, {@host, 443})
      refute changed_partition == partition
      assert {:ok, _, nil, ^changed_partition} = ResumptionContext.prepare(changed, {@host, 443})
    end

    assert {:ok, _, selected, ^partition} = ResumptionContext.prepare(options, {@host, 443})
    assert selected.peer.leaf_der == f.server.der

    wrong = normalized(f, ex_ssl: [reference_identity: {:ip, "127.0.0.2"}])
    wrong_partition = ResumptionContext.partition(wrong, {@host, 443})
    assert :ok = TicketCache.put(wrong_partition, ticket([f.server.der]))
    assert {:ok, _, nil, ^wrong_partition} = ResumptionContext.prepare(wrong, {@host, 443})
  end

  test "cached chain is reverified and invalid or expired chains cannot supply PSK", %{
    fixtures: f
  } do
    opts = normalized(f)
    endpoint = {@host, 1443}
    key = ResumptionContext.partition(opts, endpoint)

    for chain <- [[f.wrong.der], [f.expired.der], [<<1, 2, 3>>]] do
      assert :ok = TicketCache.put(key, ticket(chain))
      assert {:ok, prepared, nil, ^key} = ResumptionContext.prepare(opts, endpoint)
      refute List.keymember?(prepared.profile.extensions, :pre_shared_key, 0)
    end

    assert :ok = TicketCache.put(key, ticket([f.server.der]))
    assert {:ok, prepared, selected, ^key} = ResumptionContext.prepare(opts, endpoint)
    assert selected.peer.leaf_der == f.server.der
    assert selected.peer.chain == [f.server.der]
    assert is_binary(prepared.context.pre_shared_key)
    assert :miss = TicketCache.checkout(key)
  end

  test "expired ticket, incompatible ALPN and hash are misses even in same partition", %{
    fixtures: f
  } do
    opts = normalized(f)
    endpoint = {@host, 2443}
    key = ResumptionContext.partition(opts, endpoint)

    for changed <- [
          %{ticket([f.server.der]) | alpn: "h2"},
          %{ticket([f.server.der]) | hash: :sha384, psk: :binary.copy(<<1>>, 48)}
        ] do
      # Pin AES128 so SHA384 cannot be resumed under this policy.
      {:ok, narrow} =
        Options.normalize(@host, Keyword.put(base(f), :ciphers, ["TLS_AES_128_GCM_SHA256"]))

      narrow_key = ResumptionContext.partition(narrow, endpoint)
      assert :ok = TicketCache.put(narrow_key, changed)
      assert {:ok, _, nil, ^narrow_key} = ResumptionContext.prepare(narrow, endpoint)
    end

    now = System.monotonic_time(:millisecond)

    assert {:error, :expired} =
             TicketCache.put(key, %{
               ticket([f.server.der])
               | issued_at: now - 10,
                 expires_at: now - 1
             })

    assert {:ok, _, nil, ^key} = ResumptionContext.prepare(opts, endpoint)
  end

  test "auto is explicit TLS13-only without credentials and manual early-data options reject", %{
    fixtures: f
  } do
    assert {:ok, %{session_tickets: :disabled}} = Options.normalize(@host, cacerts: [f.ca.der])

    for extra <- [
          [session_tickets: :manual],
          [use_ticket: []],
          [early_data: "secret"],
          [versions: [:"tlsv1.2"]],
          [versions: [:"tlsv1.3", :"tlsv1.2"]],
          [certfile: f.rsa.certificate, keyfile: f.rsa.key]
        ] do
      assert {:error, {:options, _}} = Options.normalize(@host, Keyword.merge(base(f), extra))
    end
  end

  test "explicit profiles reserve last deferred PSK slot and preserve other ordering", %{
    fixtures: f
  } do
    options = normalized(f)
    assert List.last(options.profile.extensions) == {:pre_shared_key, :deferred}

    assert {:ok, explicit} =
             Options.normalize(@host, base(f) ++ [ex_ssl: [profile: options.profile]])

    assert explicit.profile == options.profile
    bad = %{options.profile | extensions: Enum.reverse(options.profile.extensions)}
    assert {:error, {:options, _}} = Options.normalize(@host, base(f) ++ [ex_ssl: [profile: bad]])

    assert {:error, {:options, _}} =
             Options.normalize(@host, cacerts: [f.ca.der], ex_ssl: [profile: options.profile])
  end

  defp base(f),
    do: [
      cacerts: [f.ca.der],
      server_name_indication: ~c"exssl.test",
      session_tickets: :auto,
      alpn_advertised_protocols: ["http/1.1"]
    ]

  defp normalized(f, extra \\ []) do
    {:ok, opts} = Options.normalize(@host, Keyword.merge(base(f), extra))
    opts
  end

  defp ticket(chain) do
    now = System.monotonic_time(:millisecond)

    %SessionTicket{
      ticket: "context-ticket",
      psk: :binary.copy(<<1>>, 32),
      hash: :sha256,
      age_add: 1,
      issued_at: now,
      expires_at: now + 60_000,
      peer: %{chain: chain},
      alpn: "http/1.1"
    }
  end
end
