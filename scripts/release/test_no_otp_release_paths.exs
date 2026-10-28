Code.require_file("no_otp_release_audit.exs", __DIR__)
ExUnit.start()

defmodule NoOTP.ReleasePathsTest do
  use ExUnit.Case, async: false

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "no-otp-paths-#{System.unique_integer([:positive])}")

    release = Path.join(directory, "release")
    ebin = Path.join(release, "lib/path_fixture-1/ebin")
    File.mkdir_p!(ebin)

    # Standalone audit controls need only physical module filenames. These empty
    # fixtures run in their own VM; they do not load or replace candidate code.
    modules = [
      HTTP,
      SSL.Connection,
      Quic,
      QuicHttp3.Session,
      HTTP.ManagedTransport,
      HTTP.WebSocket,
      HTTP.EventSource
    ]

    for module <- modules do
      [{^module, bytes}] =
        Code.compile_quoted(
          quote do:
                  (defmodule unquote(module) do
                   end)
        )

      path = Path.join(ebin, Atom.to_string(module) <> ".beam")
      File.write!(path, bytes)
      {:module, ^module} = :code.load_binary(module, String.to_charlist(path), bytes)
    end

    keys = ["NO_OTP_RELEASE", "NO_OTP_VERSION"]
    original = Map.new(keys, &{&1, System.get_env(&1)})
    System.put_env("NO_OTP_RELEASE", release)
    System.put_env("NO_OTP_VERSION", "1.0.0")

    on_exit(fn ->
      Enum.each(original, fn {key, value} ->
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end)

      for module <- modules do
        :code.purge(module)
        :code.delete(module)
      end

      File.rm_rf!(directory)
    end)

    %{directory: directory, release: release}
  end

  test "standard release parent path resolves after checking its real components", context do
    target = Path.join(context.release, "releases/0.0.0/consolidated")
    File.mkdir_p!(target)
    raw = context.release <> "/lib/../releases/0.0.0/consolidated"
    runtime = runtime_with_path(raw)
    assert %{raw: ^raw, resolved: ^target, error: nil} = evidence(runtime, raw)
    assert clean_path?(runtime, raw)
  end

  test "a real parent path outside the release stays rejected", context do
    target = Path.join(context.directory, "outside")
    File.mkdir_p!(target)
    raw = context.release <> "/lib/../../outside"
    runtime = runtime_with_path(raw)
    assert %{raw: ^raw, resolved: ^target, error: nil} = evidence(runtime, raw)
    refute clean_path?(runtime, raw)
  end

  test "parent traversal never hides a symlink component", context do
    outside = Path.join(context.directory, "symlink-target")
    File.mkdir_p!(Path.join(outside, "branch"))
    File.mkdir_p!(Path.join(outside, "resolved"))
    File.mkdir_p!(Path.join(context.release, "lib/resolved"))
    link = Path.join(context.release, "lib/alias")
    File.ln_s!(Path.join(outside, "branch"), link)
    raw = context.release <> "/lib/alias/../resolved"
    runtime = runtime_with_path(raw)

    assert %{resolved: nil, error: %{reason: "symlink_component", component: ^link}} =
             evidence(runtime, raw)

    refute clean_path?(runtime, raw)
  end

  test "a missing component remains unconfirmed", context do
    raw = Path.join(context.release, "lib/vanished")
    File.mkdir_p!(raw)
    runtime = runtime_with_path(raw, fn -> File.rmdir!(raw) end)

    assert %{resolved: nil, error: %{reason: ":enoent", component: ^raw}} =
             evidence(runtime, raw)

    refute clean_path?(runtime, raw)
  end

  test "a parent component must still be a directory", context do
    ancestor = Path.join(context.release, "lib/file-ancestor")
    File.mkdir_p!(ancestor)
    File.mkdir_p!(Path.join(context.release, "lib/file-target"))
    raw = context.release <> "/lib/file-ancestor/../file-target"

    runtime =
      runtime_with_path(raw, fn ->
        File.rmdir!(ancestor)
        File.write!(ancestor, "ordinary file")
      end)

    component = ancestor <> "/.."

    assert %{resolved: nil, error: %{reason: ":enotdir", component: ^component}} =
             evidence(runtime, raw)

    refute clean_path?(runtime, raw)
  end

  defp runtime_with_path(raw, before_snapshot \\ fn -> :ok end) do
    original = :code.get_path()
    true = :code.add_patha(String.to_charlist(raw))

    try do
      before_snapshot.()
      NoOTP.ReleaseAudit.runtime()
    after
      true = :code.set_path(original)
    end
  end

  defp evidence(runtime, raw) do
    assert %{raw: ^raw} =
             record = Enum.find(runtime.canonical_path_evidence, &(&1.raw == raw))

    record
  end

  defp clean_path?(runtime, raw) do
    modules = Map.take(runtime.loaded_modules, ["HTTP"])

    runtime = %{
      runtime
      | code_paths: [raw],
        loaded_modules: modules,
        all_loaded_paths: modules,
        ssl_available: false,
        ssl_loaded: false,
        ssl_application_loaded: false,
        ssl_started: false
    }

    artifacts = %{
      ssl_app_dependencies: [],
      ssl_bundle_paths: [],
      ssl_boot_entries: [],
      direct_otp_ssl_imports: [],
      unresolved_dispatch: [],
      missing_abstract_code: [],
      duplicate_package_apps: [],
      checked_app_files: 1,
      checked_rel_files: 1,
      checked_boot_files: 1,
      checked_beams: 1,
      package_versions:
        Map.new(
          ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport),
          &{&1, "1.0.0"}
        )
    }

    NoOTP.ReleaseAudit.clean?(artifacts, runtime)
  end
end
