defmodule SSL.MultiClientIdentityOptionsTest do
  use ExUnit.Case, async: true

  test "explicit empty modern identities override all malformed legacy sources" do
    for entries <- [[], [%{}]] do
      assert {:ok, nil} =
               SSL.ClientIdentity.load(
                 certs_keys: entries,
                 cert: :ignored,
                 certfile: :ignored,
                 key: :ignored,
                 keyfile: :ignored,
                 password: :ignored
               )

      assert {:ok, %{client_identity: nil}} =
               SSL.Options.normalize(~c"localhost",
                 verify: :verify_none,
                 certs_keys: entries,
                 cert: :ignored,
                 password: :ignored
               )
    end
  end

  test "outer count includes empty maps and rejects improper or unknown entries" do
    assert {:ok, nil} = SSL.ClientIdentity.load(certs_keys: List.duplicate(%{}, 16))

    assert {:error, {:options, :identity_count_limit}} =
             SSL.ClientIdentity.load(certs_keys: List.duplicate(%{}, 17))

    for entries <- [[%{} | :improper], [[cert: <<>>]], [%{unknown: true}], :invalid] do
      assert {:error, {:options, _}} = SSL.ClientIdentity.load(certs_keys: entries)
    end

    assert {:error, {:options, _}} = SSL.ClientIdentity.load(certs_keys: [], certs_keys: [])
  end

  test "empty override never invokes ignored password and permits automatic tickets" do
    callback = fn -> flunk("ignored legacy password invoked") end
    assert {:ok, nil} = SSL.ClientIdentity.load(certs_keys: [], password: callback)

    assert {:ok, %{client_identity: nil, session_tickets: :auto}} =
             SSL.Options.normalize(~c"localhost",
               verify: :verify_none,
               certs_keys: [],
               session_tickets: :auto,
               password: callback
             )
  end

  test "aggregate credential encoding has an exact eight-MiB boundary" do
    alias SSL.ClientIdentity.Candidates
    key = :synthetic_decoded_key
    bytes = :erlang.external_size(key)
    # Pure accounting inputs; cryptographic admission is separately tested through load/1.
    identity = %SSL.ClientIdentity{
      chain: [:binary.copy(<<0>>, 262_144), :binary.copy(<<0>>, 262_144 - bytes)],
      private_key: key,
      public_key: nil,
      signature_schemes: []
    }

    assert {:ok, %{count: 16}} = Candidates.new(List.duplicate(identity, 16))
    [first, last] = identity.chain
    larger = %{identity | chain: [first, last <> <<0>>]}
    assert {:error, {:options, _}} = Candidates.new([larger | List.duplicate(identity, 15)])
  end
end

defmodule SSL.MultiClientIdentityLoadingTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F
  alias SSL.ClientIdentity

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-multi-loading-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  test "modern DER and key source precedence, paths and combined PEM", %{fixtures: m} do
    der = F.identity(m, "rsa2048-a", :der)
    files = F.identity(m, "rsa2048-a")

    for entry <- [
          der,
          %{der | cert: [der.cert]},
          files,
          Map.new(files, fn {k, v} -> {k, String.to_charlist(v)} end),
          F.identity(m, "rsa2048-a", :combined),
          Map.merge(der, %{certfile: "/ignored-private-cert", keyfile: "/ignored-private-key"}),
          %{certfile: m["identities"]["rsa2048-a"]["combined"], key: der.key}
        ] do
      assert {:ok, %ClientIdentity.Candidates{identities: [identity]}} =
               ClientIdentity.load(certs_keys: [entry], cert: :ignored, password: :ignored)

      assert identity.chain == [F.der(m, "rsa2048-a")]
    end
  end

  test "every later identity validates and malformed options fail before dial", %{fixtures: m} do
    first = F.identity(m, "rsa2048-a")
    second = F.identity(m, "p256-a")
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    for bad <- [
          %{cert: <<1>>, keyfile: second.keyfile},
          Map.delete(second, :keyfile),
          %{second | keyfile: m["identities"]["p256-b"]["key"]},
          Map.put(second, :unsupported, true)
        ] do
      assert {:error, {:options, _}} =
               SSL.connect(
                 {127, 0, 0, 1},
                 port,
                 Keyword.put(F.options(m, []), :certs_keys, [first, bad]),
                 1_000
               )

      assert {:error, :timeout} = :gen_tcp.accept(listener, 10)
    end
  end

  test "per-map encrypted callbacks are transient and top-level password is ignored", %{
    fixtures: m
  } do
    counts = :atomics.new(3, [])

    entries =
      for {name, index} <- [{"rsa2048-a", 1}, {"p256-a", 2}] do
        item = m["identities"][name]
        password = File.read!(item["password_file"])

        %{
          certfile: item["cert"],
          keyfile: item["encrypted_key"],
          password: fn ->
            :atomics.add_get(counts, index, 1)
            password
          end
        }
      end

    assert {:ok, loaded} =
             ClientIdentity.load(
               certs_keys: entries,
               password: fn ->
                 :atomics.add_get(counts, 3, 1)
                 :invalid
               end
             )

    assert [1, 1, 0] == Enum.map(1..3, &:atomics.get(counts, &1))
    retained = :erlang.term_to_binary(loaded)

    for name <- ["rsa2048-a", "p256-a"] do
      item = m["identities"][name]
      refute retained =~ File.read!(item["password_file"])
      refute retained =~ item["key"]
      refute inspect(loaded) =~ item["cert"]
    end

    refute inspect(loaded) =~ "private_key"

    assert {:error, {:options, _}} =
             ClientIdentity.load(
               certs_keys: [Map.delete(hd(entries), :password)],
               password: "ignored"
             )

    assert {:error, {:options, _}} =
             ClientIdentity.load(
               certs_keys: [hd(entries), %{List.last(entries) | password: "wrong"}]
             )
  end

  test "nonempty identities retain ticket exclusion while verify_none nil trust remains usable",
       %{fixtures: m} do
    assert {:error, {:options, {:session_tickets, :client_identity_unsupported}}} =
             SSL.Options.normalize(
               ~c"localhost",
               [session_tickets: :auto] ++ F.options(m, ["rsa2048-a"])
             )

    assert {:ok, %{trust_source: nil, client_identity: %ClientIdentity.Candidates{count: 2}}} =
             SSL.Options.normalize(~c"localhost",
               verify: :verify_none,
               certs_keys: [F.identity(m, "rsa2048-a"), F.identity(m, "p256-a")]
             )
  end
end
