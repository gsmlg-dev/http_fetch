defmodule HTTP.Transport.AddressFamilyTest do
  use ExUnit.Case, async: true

  alias HTTP.Transport.AddressFamily

  test "preference is explicit and leaves pinned addresses and strict families unchanged" do
    refute AddressFamily.preferred?([])
    assert AddressFamily.preferred?(prefer_ipv6: true)
    refute AddressFamily.preferred?(prefer_ipv6: false)

    for address <- [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}] do
      refute AddressFamily.preferred?(prefer_ipv6: true, connect_address: address)
    end

    for family <- [:inet, :inet6] do
      refute AddressFamily.preferred?(prefer_ipv6: true, socket_opts: [family])
    end
  end

  test "an expired preference budget does not initiate a native connection" do
    assert {:error, :timeout} =
             AddressFamily.connect(
               "127.0.0.1",
               1,
               [:binary, active: false],
               [prefer_ipv6: true],
               0
             )
  end

  test "queued cancellation and deadline stop preference before a native attempt" do
    for {message, reason} <- [
          {:abort, :aborted},
          {:deadline, :request_timeout},
          {{:close_socket, make_ref()}, :aborted}
        ] do
      send(self(), message)

      assert {:error, ^reason} =
               AddressFamily.connect(
                 "127.0.0.1",
                 1,
                 [:binary, active: false],
                 [prefer_ipv6: true],
                 1_000
               )
    end
  end
end
