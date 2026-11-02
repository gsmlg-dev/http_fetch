Code.require_file("no_otp_directed_review.exs", __DIR__)
ExUnit.start()

defmodule NoOTP.DirectedReviewTest do
  use ExUnit.Case, async: true
  alias NoOTP.DirectedReview

  @packages ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)

  setup do
    root = Path.join(System.tmp_dir!(), "directed-review-#{System.unique_integer([:positive])}")
    project = Path.join(root, "project")
    release = Path.join(root, "release")
    versions = Map.new(@packages, &{&1, "1.0.0-rc.0"})
    versions = Map.merge(versions, %{"telemetry" => "1.4.2", "no_otp_consumer" => "0.0.0"})

    for {package, _version} <- versions do
      directory = if package == "telemetry", do: "src", else: "lib"
      parent = if package == "no_otp_consumer", do: project, else: "#{project}/deps/#{package}"
      File.mkdir_p!(Path.join(parent, directory))
    end

    source = "#{project}/deps/http_fetch/lib/reviewed.ex"
    module = Module.concat(NoOTP, "DirectedFixture#{System.unique_integer([:positive])}")
    File.write!(source, "defmodule #{inspect(module)} do\n  def run(fun), do: fun.()\nend\n")
    [{^module, bytes}] = Code.compile_file(source)
    filename = Atom.to_string(module) <> ".beam"
    beam = "#{release}/lib/http_fetch-1.0.0-rc.0/ebin/#{filename}"
    built = "#{project}/build/lib/http_fetch/ebin/#{filename}"

    for path <- [beam, built] do
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, bytes)
    end

    finding = %{beam: beam, line: 2, kind: "unresolved_fun_invocation", resolution: "unconfirmed"}

    artifacts = %{
      checked_beams: 1,
      beam_inspections: [
        %{
          module: inspect(module),
          beam: beam,
          sha256: digest(beam),
          unresolved_dispatch: [finding]
        }
      ],
      unresolved_dispatch: [finding]
    }

    bundle = %{
      "schema" => 1,
      "scope" => "supported_public_api_and_approved_callbacks",
      "versions" => versions,
      "reviews" => %{"review.md" => "reviewed concrete producer and retained callback"},
      "sources" => %{"http_fetch/lib/reviewed.ex" => digest(source)},
      "occurrences" => [
        %{
          "module" => inspect(module),
          "mfa" => "run/1",
          "line" => 2,
          "kind" => "unresolved_fun_invocation",
          "source" => "http_fetch/lib/reviewed.ex",
          "proof" => "fixture"
        }
      ]
    }

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
      File.rm_rf!(root)
    end)

    %{
      artifacts: artifacts,
      bundle: bundle,
      project: project,
      release: release,
      source: source,
      module: module,
      beam: beam,
      built: built
    }
  end

  test "binds actual source and compiled sites without changing generic findings", context do
    original = context.artifacts
    receipt = bind(context)
    assert receipt.status == "PASS"
    assert receipt.remaining_dispatches == []
    assert [%{mfa: "run/1", proof: "fixture"}] = receipt.reviewed_dispatches
    assert original == context.artifacts
    assert DirectedReview.accepted?(Map.put(original, :directed_review, receipt))
    refute DirectedReview.accepted?(original)
  end

  test "a changed producer fails even when its invocation is unchanged", context do
    File.write!(context.source, File.read!(context.source) <> "# changed\n")
    assert_failed(context, "source census changed")
  end

  test "an extra production source cannot escape a selected-source review", context do
    File.write!(Path.join(Path.dirname(context.source), "extra.ex"), "# unreviewed source\n")
    assert_failed(context, "source census changed")
  end

  test "release and build bytes must both match the inspected BEAM", context do
    for path <- [context.beam, context.built] do
      original = File.read!(path)
      File.write!(path, original <> <<0>>)
      assert bind(context).status == "FAIL"
      File.write!(path, original)
    end
  end

  test "a new or missing compiled finding keeps the release blocked", context do
    [inspection] = context.artifacts.beam_inspections

    for findings <- [
          [],
          inspection.unresolved_dispatch ++
            [%{beam: context.beam, line: 4, kind: "unresolved_module_dispatch"}]
        ] do
      artifacts = %{
        context.artifacts
        | beam_inspections: [%{inspection | unresolved_dispatch: findings}],
          unresolved_dispatch: findings
      }

      assert_failed(%{context | artifacts: artifacts}, "unreviewed or missing compiled dispatch")
    end
  end

  test "wrong function, source, kind and duplicate proof rows are rejected", context do
    [occurrence] = context.bundle["occurrences"]

    for occurrences <- [
          [Map.put(occurrence, "mfa", "other/1")],
          [Map.put(occurrence, "source", "http_fetch/lib/other.ex")],
          [Map.put(occurrence, "kind", "unresolved_module_dispatch")],
          [occurrence, occurrence]
        ] do
      bundle = Map.put(context.bundle, "occurrences", occurrences)
      assert bind(%{context | bundle: bundle}).status == "FAIL"
    end
  end

  test "a compiled source outside the isolated dependency is rejected", context do
    outside = Path.join(Path.dirname(context.project), "unreviewed.ex")
    File.cp!(context.source, outside)
    :code.purge(context.module)
    :code.delete(context.module)
    [{_module, bytes}] = Code.compile_file(outside)
    File.write!(context.beam, bytes)
    File.write!(context.built, bytes)
    assert bind(context).status == "FAIL"
  end

  test "symlinked reviewed files do not supply source identity", context do
    outside = Path.join(Path.dirname(context.project), "source-copy.ex")
    File.rename!(context.source, outside)
    File.ln_s!(outside, context.source)
    assert bind(context).status == "FAIL"
  end

  test "changed scope and missing native receipts remain unaccepted", context do
    assert bind(%{context | bundle: Map.put(context.bundle, "scope", "arbitrary_internal_state")}).status ==
             "FAIL"

    receipt = bind(context)

    refute DirectedReview.accepted?(
             Map.put(context.artifacts, :directed_review, %{receipt | raw_dispatch_count: 0})
           )

    refute DirectedReview.accepted?(
             Map.put(context.artifacts, :directed_review, %{
               receipt
               | remaining_dispatches: [:unproved]
             })
           )
  end

  defp assert_failed(context, reason) do
    receipt = bind(context)
    assert receipt.status == "FAIL"
    assert receipt.error =~ reason
    assert receipt.reviewed_dispatches == []
    assert receipt.remaining_dispatches == context.artifacts.unresolved_dispatch
  end

  defp bind(context),
    do: DirectedReview.bind(context.artifacts, context.bundle, context.project, context.release)

  defp digest(path), do: :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)
end
