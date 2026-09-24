defmodule HTTP.HTTP2FingerprintTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{Fingerprint, Frame, HPACK}

  test "observes ordered settings and redacts sensitive header values" do
    wire =
      HTTP.HTTP2.connection_preface() <>
        Frame.encode(:settings, 0, 0, <<4::16, 65_535::32, 1::16, 4096::32>>) <>
        Frame.encode(
          :headers,
          4,
          1,
          HPACK.encode_headers([
            {":method", "GET"},
            {"cookie", "secret"},
            {"x-test", "ok"}
          ])
        )

    assert {:ok, observation} = Fingerprint.observe(wire)
    assert observation.preface
    assert observation.settings == [{4, 65_535}, {1, 4096}]

    assert [[{":method", "GET"}, {"cookie", "[REDACTED]"}, {"x-test", "ok"}]] =
             observation.headers

    refute Map.has_key?(observation, :raw) and is_binary(observation.raw)
  end

  test "diff reports structured changes without raw capture" do
    assert {:ok, left} = Fingerprint.observe(Frame.encode(:settings, 0, 0, <<1::16, 1::32>>))
    assert {:ok, right} = Fingerprint.observe(Frame.encode(:settings, 0, 0, <<1::16, 2::32>>))
    diff = Fingerprint.diff(left, right)
    refute diff.equal?
    assert Map.has_key?(diff.changes, :settings)
  end

  test "records an explicit observation source and bounds parsing" do
    frame = Frame.encode(:ping, 0, 0, "12345678")
    assert {:ok, observation} = Fingerprint.observe(frame, source: :serialized)
    assert observation.source == :serialized
    assert {:error, :invalid_observation_source} = Fingerprint.observe(frame, source: :browser)
    assert {:error, :too_many_frames} = Fingerprint.observe(frame <> frame, max_frames: 1)
    assert {:error, :observation_too_large} = Fingerprint.observe(frame, max_observed_bytes: 1)
    assert {:error, :invalid_observation_limits} = Fingerprint.observe(frame, max_frames: -1)
    assert {:error, :invalid_observation_limits} = Fingerprint.observe(frame, max_raw_bytes: :all)
  end
end
