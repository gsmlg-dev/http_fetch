Code.require_file("no_otp_release_audit.exs", __DIR__)
ExUnit.start()

defmodule NoOTP.BlockedTrafficIsolationTest do
  use ExUnit.Case, async: true
  alias NoOTP.ReleaseAudit

  @packages ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)
  @version System.fetch_env!("NO_OTP_VERSION")
  @path "/owned/release/lib/client-1/ebin/client.beam"
  @artifacts %{
    ssl_app_dependencies: [],
    ssl_bundle_paths: [],
    ssl_boot_entries: [],
    direct_otp_ssl_imports: [],
    unresolved_dispatch: [%{kind: "unresolved_fun_invocation", line: 4}],
    missing_abstract_code: [],
    duplicate_package_apps: [],
    checked_app_files: 10,
    checked_rel_files: 1,
    checked_boot_files: 1,
    checked_beams: 10,
    package_versions: Map.new(@packages, &{&1, @version})
  }
  @runtime %{
    ssl_available: false,
    ssl_loaded: false,
    ssl_application_loaded: false,
    ssl_started: false,
    code_paths: [@path],
    loaded_modules: %{"HTTP" => @path},
    all_loaded_paths: %{"HTTP" => @path},
    canonical_release: %{resolved: "/owned/release", error: nil},
    canonical_path_evidence: [%{raw: @path, resolved: @path, error: nil}]
  }

  test "diagnostic isolation retains the strict unresolved-dispatch failure" do
    assert ReleaseAudit.isolated?(@artifacts, @runtime)
    refute ReleaseAudit.clean?(@artifacts, @runtime)
    assert ReleaseAudit.clean?(%{@artifacts | unresolved_dispatch: []}, @runtime)
  end

  for field <- [
        :ssl_app_dependencies,
        :ssl_bundle_paths,
        :ssl_boot_entries,
        :direct_otp_ssl_imports,
        :missing_abstract_code,
        :duplicate_package_apps
      ] do
    test "diagnostics reject artifact failure #{field}" do
      refute ReleaseAudit.isolated?(Map.put(@artifacts, unquote(field), [:finding]), @runtime)
    end
  end

  for field <- [:ssl_available, :ssl_loaded, :ssl_application_loaded, :ssl_started] do
    test "diagnostics reject runtime failure #{field}" do
      refute ReleaseAudit.isolated?(@artifacts, Map.put(@runtime, unquote(field), true))
    end
  end

  test "diagnostics reject missing inventory, wrong version and escaped code paths" do
    refute ReleaseAudit.isolated?(%{@artifacts | checked_beams: 0}, @runtime)
    refute ReleaseAudit.isolated?(%{@artifacts | package_versions: %{}}, @runtime)

    refute ReleaseAudit.isolated?(@artifacts, %{
             @runtime
             | canonical_path_evidence: [
                 %{raw: @path, resolved: "/host/ssl-1/ebin/ssl.beam", error: nil}
               ]
           })
  end
end
