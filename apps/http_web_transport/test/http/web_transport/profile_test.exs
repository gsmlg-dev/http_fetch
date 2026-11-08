defmodule HTTP.WebTransport.ProfileTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport.Profile

  @settings %{0x20B8933B => 1, 0x33 => 1, 0x8 => 1}
  @reset %{draft: 11, local: true, peer: true, negotiated: true}
  @transport %{max_datagram_frame_size: 1200, reset_stream_at: <<>>}

  test "requires matching profile, datagrams, reliable reset and exclusive ownership" do
    assert :ok =
             Profile.validate(@settings, @transport, @transport,
               exclusive: true,
               reliable_reset: @reset
             )

    assert {:error, :exclusive_single_session_required} =
             Profile.validate(@settings, @transport, @transport)

    for key <- Map.keys(@settings) do
      assert {:error, _} =
               Profile.validate(Map.delete(@settings, key), @transport, @transport,
                 exclusive: true,
                 reliable_reset: @reset
               )
    end

    for role <- [:local, :peer], key <- Map.keys(@transport) do
      missing = Map.delete(@transport, key)
      {local, peer} = if role == :local, do: {missing, @transport}, else: {@transport, missing}

      assert {:error, _} =
               Profile.validate(@settings, local, peer, exclusive: true, reliable_reset: @reset)
    end

    assert {:error, _} =
             Profile.validate(Map.put(@settings, 0x20B8933B, 2), @transport, @transport,
               exclusive: true,
               reliable_reset: @reset
             )

    refute Profile.supported?()
  end

  test "legacy settings and nonempty reset parameters never admit draft17" do
    assert {:error, _} =
             Profile.validate(%{0x2C7CF000 => 1, 0x33 => 1, 0x8 => 1}, @transport, @transport,
               exclusive: true,
               reliable_reset: @reset
             )

    assert {:error, {:reliable_reset_required, :peer}} =
             Profile.validate(@settings, @transport, %{@transport | reset_stream_at: <<1>>},
               exclusive: true,
               reliable_reset: @reset
             )
  end

  test "parameter presence cannot replace engine negotiation evidence" do
    assert {:error, :reliable_reset_not_negotiated} =
             Profile.validate(@settings, @transport, @transport, exclusive: true)

    for {key, value} <- [draft: 9, local: false, peer: false, negotiated: false] do
      assert {:error, :reliable_reset_not_negotiated} =
               Profile.validate_reset(Map.put(@reset, key, value))
    end

    assert :ok = Profile.validate_reset(@reset)
    refute Profile.supported?()
  end
end
