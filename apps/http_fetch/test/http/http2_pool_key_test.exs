defmodule HTTP.HTTP2PoolKeyTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.PoolKey
  alias HTTP.HTTP2.WireProfile
  alias HTTP.Request

  defp request(options \\ []) do
    %Request{url: URI.parse("https://Example.COM:443/path"), transport_options: options}
  end

  test "same origin, profile, and options have the same key" do
    assert {:ok, left} = PoolKey.build(request(), WireProfile.native_v1(), :h2)
    assert {:ok, right} = PoolKey.build(request(), WireProfile.native_v1(), "h2")
    assert left == right
    assert left.host == "example.com"
    assert left.port == 443
  end

  test "ordered settings and profile contents participate in the key" do
    first = %{id: "ordered", settings: [{1, 4096}, {4, 65_535}]}
    second = %{id: "ordered", settings: [{4, 65_535}, {1, 4096}]}
    assert {:ok, left} = PoolKey.build(request(), first, :h2)
    assert {:ok, right} = PoolKey.build(request(), second, :h2)
    refute left == right
  end

  test "scope, backend, verification, SNI, and ALPN isolate identities" do
    base = [http2_scope: "tenant-a", tls_backend: :ssl, ssl: [verify: :verify_peer]]
    assert {:ok, first} = PoolKey.build(request(base), WireProfile.native_v1(), :h2)

    for change <- [
          [http2_scope: "tenant-b", tls_backend: :ssl, ssl: [verify: :verify_peer]],
          [http2_scope: "tenant-a", tls_backend: :ex_ssl, ssl: [verify: :verify_peer]],
          [http2_scope: "tenant-a", tls_backend: :ssl, ssl: [verify: :verify_none]],
          [
            http2_scope: "tenant-a",
            tls_backend: :ssl,
            ssl: [verify: :verify_peer, server_name_indication: ~c"other.example"]
          ],
          [
            http2_scope: "tenant-a",
            tls_backend: :ssl,
            ssl: [verify: :verify_peer, alpn_advertised_protocols: ["h2"]]
          ]
        ] do
      assert {:ok, other} = PoolKey.build(request(change), WireProfile.native_v1(), :h2)
      refute first == other
    end
  end

  test "certificate and key content changes alter identity" do
    first = [ssl: [cert: <<1, 2>>, key: <<3, 4>>, cacerts: [<<5>>]]]
    second = [ssl: [cert: <<1, 2>>, key: <<3, 5>>, cacerts: [<<5>>]]]
    assert {:ok, left} = PoolKey.build(request(first), WireProfile.native_v1(), :h2)
    assert {:ok, right} = PoolKey.build(request(second), WireProfile.native_v1(), :h2)
    refute left == right
  end

  test "file-backed TLS identity includes file contents" do
    path = Path.join(System.tmp_dir!(), "http2-pool-key-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm(path) end)
    File.write!(path, "certificate-a")
    options = [ssl: [cacertfile: path]]
    assert {:ok, first} = PoolKey.build(request(options), WireProfile.native_v1(), :h2)
    File.write!(path, "certificate-b")
    assert {:ok, second} = PoolKey.build(request(options), WireProfile.native_v1(), :h2)
    refute first == second
  end

  test "callbacks are never marked reusable" do
    callback = fn _, _ -> :valid end

    assert {:ok, :non_reusable, key} =
             PoolKey.build(
               request(ssl: [verify_fun: {callback, []}]),
               WireProfile.native_v1(),
               :h2
             )

    refute inspect(key) =~ "valid"
    refute inspect(key) =~ "fn"
  end

  test "private values do not appear in the key" do
    secret = "private-key-token"
    assert {:ok, key} = PoolKey.build(request(ssl: [key: secret]), WireProfile.native_v1(), :h2)
    refute inspect(key) =~ secret
    refute :erlang.term_to_binary(key) =~ secret
  end

  test "http2_reuse false gets a unique isolated marker" do
    options = [http2_reuse: false]

    assert {:ok, :non_reusable, first} =
             PoolKey.build(request(options), WireProfile.native_v1(), :h2)

    assert {:ok, :non_reusable, second} =
             PoolKey.build(request(options), WireProfile.native_v1(), :h2)

    refute first == second
    refute first.reuse == :shared
  end

  test "h2c and unsupported proxy routes are explicit" do
    assert {:ok, h2c} =
             PoolKey.build(
               %{request() | url: URI.parse("http://example.com")},
               WireProfile.native_v1(),
               :h2c
             )

    assert h2c.protocol == :h2c

    assert {:error, {:unsupported_route, :proxy}} =
             PoolKey.build(request(proxy: "http://proxy"), WireProfile.native_v1(), :h2)
  end
end
