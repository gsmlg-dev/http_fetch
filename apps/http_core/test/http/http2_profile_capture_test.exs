defmodule HTTP.HTTP2ProfileCaptureTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.ProfileCapture

  @attrs %{
    product: "ExampleBrowser",
    version: "1.2.3",
    platform: "test-os",
    captured_at: "2026-09-25T00:00:00Z",
    tool: "independent-h2-capture 1.0",
    origin: "https://example.test/",
    protocol: :h2,
    connection_context: :cold,
    source: :captured_verified,
    license: "test-fixture",
    matched_fields: [:settings, :headers],
    known_differences: []
  }

  test "builds a manifest with a reproducible fixture digest" do
    assert {:ok, manifest} = ProfileCapture.build_manifest("fixture", @attrs)
    assert manifest.fixture_digest == ProfileCapture.digest("fixture")
    assert manifest.version_schema == 1
  end

  test "rejects incomplete or invalid provenance" do
    manifest = Map.put(@attrs, :fixture_digest, ProfileCapture.digest("fixture"))

    assert {:error, {:missing_manifest_field, :tool}} =
             ProfileCapture.validate_manifest(Map.delete(@attrs, :tool))

    assert {:error, {:invalid_manifest_field, :source}} =
             ProfileCapture.validate_manifest(%{manifest | source: :browser_latest})

    assert {:error, {:invalid_manifest_field, :connection_context}} =
             ProfileCapture.validate_manifest(%{manifest | connection_context: :warm})
  end

  test "rejects non-hex and non-sha256 fixture digests" do
    manifest = Map.put(@attrs, :fixture_digest, ProfileCapture.digest("fixture"))

    assert {:error, :invalid_fixture_digest} =
             ProfileCapture.validate_manifest(%{
               manifest
               | fixture_digest: String.duplicate("x", 64)
             })

    assert {:error, :invalid_fixture_digest} =
             ProfileCapture.validate_manifest(%{manifest | fixture_digest: "abc"})
  end
end
