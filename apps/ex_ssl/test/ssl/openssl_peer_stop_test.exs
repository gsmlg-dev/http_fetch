defmodule SSL.OpenSSLPeerStopTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, OpenSSLPeer}

  @moduletag :integration

  setup do
    directory =
      Path.join(System.tmp_dir!(), "exssl-peer-stop-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  # ExUnit runs on_exit callbacks in a process other than the test process that
  # owns the peer port, so stop/1 must settle without the owner's exit_status.
  test "stop terminates a peer from a process that does not own its port", %{fixtures: fixtures} do
    parent = self()

    owner =
      spawn_link(fn ->
        {:ok, peer} =
          OpenSSLPeer.start(
            certfile: fixtures.server.certificate,
            keyfile: fixtures.server.key
          )

        send(parent, {:peer, peer})
        receive do: (:done -> :ok)
      end)

    assert_receive {:peer, peer}, 5_000
    monitor = Port.monitor(peer.handle)

    try do
      assert :ok = OpenSSLPeer.stop(peer)
      assert_receive {:DOWN, ^monitor, :port, _, _}, 2_000
    after
      send(owner, :done)
    end
  end
end
