defmodule SSL.OSTrustStoreWarmTest do
  # Restarts the :ex_ssl application and clears the process-global OS trust
  # store cache, so it must not run concurrently with other tests.
  use ExUnit.Case, async: false

  # A cold `:public_key.cacerts_get/0` cannot be made reliably slower than a
  # request deadline, so these tests pin the ordering instead (#165): the OS
  # trust store is loaded while :ex_ssl starts, before any request can arm a
  # deadline. `:public_key` caches the loaded store under this persistent_term
  # key; the first test pins that probe against the public API.
  @cache_key :pubkey_os_cacerts
  @fixtures Path.expand("../fixtures/pkix", __DIR__)

  setup do
    on_exit(fn ->
      Application.delete_env(:public_key, :cacerts_path)
      {:ok, _} = Application.ensure_all_started(:ex_ssl)
      _ = :public_key.cacerts_get()
    end)
  end

  test "the cache probe tracks the public trust store API" do
    _ = :public_key.cacerts_get()
    assert loaded?()
    assert :public_key.cacerts_clear()
    refute loaded?()
  end

  test "starting ex_ssl loads the OS trust store before any request" do
    restart_ex_ssl()
    assert loaded?()
  end

  test "a host without an OS trust store still boots ex_ssl" do
    Application.put_env(:public_key, :cacerts_path, Path.join(@fixtures, "missing.pem"))
    restart_ex_ssl()
    refute loaded?()
    assert Process.whereis(SSL.Supervisor) |> Process.alive?()

    # The request path keeps its existing failure for missing default trust.
    assert {:error, {:options, {:cacerts, :invalid}}} =
             SSL.Options.normalize("example.com", [])
  end

  test "explicit trust and verify_none never load the OS trust store" do
    root = File.read!(Path.join(@fixtures, "root.pem"))
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(root)
    :public_key.cacerts_clear()

    for options <- [
          [cacerts: [der]],
          [cacertfile: Path.join(@fixtures, "root.pem")],
          [verify: :verify_none]
        ] do
      assert {:ok, _} = SSL.Options.normalize("example.com", options)
      refute loaded?(), "#{inspect(Keyword.keys(options))} loaded the OS trust store"
    end
  end

  defp restart_ex_ssl do
    :ok = Application.stop(:ex_ssl)
    :public_key.cacerts_clear()
    refute loaded?()
    {:ok, _} = Application.ensure_all_started(:ex_ssl)
  end

  defp loaded?, do: :persistent_term.get(@cache_key, :not_loaded) != :not_loaded
end
