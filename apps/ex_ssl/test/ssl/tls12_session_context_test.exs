defmodule SSL.TLS12SessionContextTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias SSL.{Options, SessionCache, TLS12ResumptionContext, TLS12Session}
  @host {127, 0, 0, 1}
  @endpoint {@host, 443}

  setup_all do
    dir =
      Path.join(System.tmp_dir!(), "tls12-session-context-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(dir) end)
    %{fixtures: ClientAuthFixtures.create(dir)}
  end

  test "origin, endpoint, trust, reference identity, SNI, profile, ALPN and client identities partition sessions",
       %{fixtures: f} do
    options = normalized(f)
    base = TLS12ResumptionContext.partition(options, @endpoint)

    variants = [
      %{options | endpoint: ~c"other.test"},
      %{options | identity: {:ip, "127.0.0.2"}},
      %{options | context: Map.put(options.context, :server_name, "other-routing.test")},
      %{options | trust_source: [f.wrong.der]},
      %{options | depth: options.depth + 1},
      %{options | hostname_check: [match_fun: fn _, _ -> false end]},
      %{options | verify: :verify_none},
      normalized(f, alpn_advertised_protocols: ["h2"]),
      normalized(f, supported_groups: [:secp384r1]),
      normalized(f, certfile: f.rsa.certificate, keyfile: f.rsa.key),
      normalized(f, certfile: f.ec.certificate, keyfile: f.ec.key)
    ]

    for changed <- variants,
        do: refute(TLS12ResumptionContext.partition(changed, @endpoint) == base)

    refute TLS12ResumptionContext.partition(options, {@host, 444}) == base
    refute TLS12ResumptionContext.partition(options, {{127, 0, 0, 2}, 443}) == base
    assert TLS12ResumptionContext.partition(%{options | reuse_sessions: :save}, @endpoint) == base
  end

  test "cached credentials are reverified rather than trusting retained decoded material", %{
    fixtures: f
  } do
    options = normalized(f)
    key = TLS12ResumptionContext.partition(options, @endpoint)
    candidate = session([f.server.der])
    assert :ok = SessionCache.put(key, candidate)

    assert {:ok, prepared, selected, {^key, true}} =
             TLS12ResumptionContext.prepare(options, @endpoint)

    assert selected.peer.leaf_der == f.server.der
    assert prepared.profile.session_id == {:fixed, candidate.id}

    for chain <- [[f.expired.der], [f.wrong.der], [<<1, 2, 3>>]] do
      assert :ok = SessionCache.put(key, %{candidate | peer: %{chain: chain}})
      assert {:ok, _, nil, {^key, true}} = TLS12ResumptionContext.prepare(options, @endpoint)
    end

    wrong = normalized(f, server_name_indication: ~c"wrong.exssl.test")
    wrong_key = TLS12ResumptionContext.partition(wrong, @endpoint)
    assert :ok = SessionCache.put(wrong_key, candidate)
    assert {:ok, _, nil, {^wrong_key, true}} = TLS12ResumptionContext.prepare(wrong, @endpoint)
  end

  test "cache expiry and exact saved ALPN/suite policy are checked before offering IDs", %{
    fixtures: f
  } do
    options = normalized(f)
    key = TLS12ResumptionContext.partition(options, @endpoint)
    candidate = session([f.server.der])

    for change <- [%{alpn: "h2"}, %{suite: 0xC030}] do
      assert :ok = SessionCache.put(key, struct!(candidate, change))
      restricted = %{options | profile: %{options.profile | cipher_suites: [0xC02F]}}
      # Inject under the current partition to exercise validation beyond key isolation.
      restricted_key = TLS12ResumptionContext.partition(restricted, @endpoint)
      assert :ok = SessionCache.put(restricted_key, struct!(candidate, change))

      assert {:ok, _, nil, {^restricted_key, true}} =
               TLS12ResumptionContext.prepare(restricted, @endpoint)
    end

    assert :ok = SessionCache.put(key, candidate)

    :sys.replace_state(SessionCache, fn state ->
      entries =
        Map.update!(state.entries, {key, candidate.id}, fn {entry, size, order} ->
          {%{entry | expires_at: System.monotonic_time(:millisecond) - 1}, size, order}
        end)

      %{state | entries: entries}
    end)

    assert {:ok, _, nil, {^key, true}} = TLS12ResumptionContext.prepare(options, @endpoint)
  end

  test "verify_fun and advanced certificate policy bypass both lookup and saving", %{fixtures: f} do
    base = normalized(f)

    for changed <- [
          normalized(f, verify_fun: {fn _, _, state -> {:valid, state} end, 0}),
          normalized(f, partial_chain: fn _ -> :unknown_ca end),
          normalized(f, stapling: :staple),
          normalized(f, crl_check: :peer)
        ] do
      key = TLS12ResumptionContext.partition(changed, @endpoint)
      assert :ok = SessionCache.put(key, session([f.server.der]))
      assert {:ok, ^changed, nil, nil} = TLS12ResumptionContext.prepare(changed, @endpoint)
      assert {:ok, _} = SessionCache.lookup(key, :auto)
    end

    disabled = %{base | reuse_sessions: false}

    assert {:ok, ^disabled, nil, {_key, false}} =
             TLS12ResumptionContext.prepare(disabled, @endpoint)
  end

  test "fixed profile IDs are honored, while explicit saved IDs work in save mode", %{fixtures: f} do
    base = normalized(f)
    fixed = %{base | profile: %{base.profile | session_id: {:fixed, <<1>>}}}
    key = TLS12ResumptionContext.partition(fixed, @endpoint)
    assert :ok = SessionCache.put(key, session([f.server.der]))
    assert {:ok, ^fixed, nil, {^key, true}} = TLS12ResumptionContext.prepare(fixed, @endpoint)
    saved = %{base | reuse_sessions: :save}
    saved_key = TLS12ResumptionContext.partition(saved, @endpoint)
    candidate = %{session([f.server.der]) | auto: false}
    assert :ok = SessionCache.put(saved_key, candidate)

    assert {:ok, ^saved, nil, {^saved_key, :save}} =
             TLS12ResumptionContext.prepare(saved, @endpoint)

    selected = %{saved | reuse_session: candidate.id}

    assert {:ok, _, %TLS12Session{}, {^saved_key, :save}} =
             TLS12ResumptionContext.prepare(selected, @endpoint)
  end

  defp normalized(f, extra \\ []) do
    {:ok, options} =
      Options.normalize(
        @host,
        Keyword.merge(
          [
            verify: :verify_peer,
            cacerts: [f.ca.der],
            server_name_indication: ~c"exssl.test",
            versions: [:"tlsv1.2"],
            reuse_sessions: true,
            alpn_advertised_protocols: ["http/1.1"]
          ],
          extra
        )
      )

    options
  end

  defp session(chain) do
    now = System.monotonic_time(:millisecond)

    %TLS12Session{
      id: <<9>>,
      master_secret: :binary.copy(<<83>>, 48),
      suite: 0xC02F,
      peer: %{chain: chain},
      alpn: "http/1.1",
      issued_at: now,
      expires_at: now + 60_000,
      auto: true
    }
  end
end
