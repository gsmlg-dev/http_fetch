defmodule SSL.ManualTicketTest do
  use ExUnit.Case, async: true

  alias SSL.{Options, SessionTicket}

  test "manual mode without a candidate reserves the TLS13 ticket extensions" do
    assert {:ok, %{session_tickets: :manual, use_ticket: []} = options} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               session_tickets: :manual
             )

    assert List.last(options.profile.extensions) == {:pre_shared_key, :deferred}
    assert {:psk_key_exchange_modes, [1]} in options.profile.extensions
  end

  test "manual mode preserves an explicit mixed offer and requires TLS13 to be offered" do
    assert {:ok, options} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               session_tickets: :manual,
               versions: [:"tlsv1.3", :"tlsv1.2"]
             )

    assert {:supported_versions, [0x0304, 0x0303]} in options.profile.extensions

    assert {:error, {:options, {:session_tickets, :tls13_required}}} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               session_tickets: :manual,
               versions: [:"tlsv1.2"]
             )
  end

  test "manual candidates stay bounded and option errors never expose ticket material" do
    ticket = ticket()

    assert {:ok, %{use_ticket: [^ticket]}} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               session_tickets: :manual,
               use_ticket: [ticket]
             )

    for candidates <- [
          [],
          "private-manual-ticket",
          [ticket, :invalid],
          [ticket | :invalid],
          List.duplicate(ticket, 9)
        ] do
      assert {:error, reason} =
               Options.normalize(~c"example.test",
                 verify: :verify_none,
                 cacerts: [],
                 session_tickets: :manual,
                 use_ticket: candidates
               )

      assert reason == {:options, {:use_ticket, :unsupported_or_invalid}}
      refute inspect(reason) =~ "private-manual"
    end
  end

  test "explicit candidates require manual mode and are redacted in normalized options" do
    ticket = ticket()

    for mode <- [:disabled, :auto] do
      assert {:error, {:options, {:use_ticket, :manual_required}}} =
               Options.normalize(~c"example.test",
                 verify: :verify_none,
                 cacerts: [],
                 session_tickets: mode,
                 use_ticket: [ticket]
               )
    end

    assert {:ok, options} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               session_tickets: :manual,
               use_ticket: [ticket]
             )

    refute inspect(options) =~ "private-manual"
  end

  defp ticket do
    now = System.monotonic_time(:millisecond)

    %SessionTicket{
      ticket: "private-manual-ticket",
      psk: :binary.copy("private-manual-psk", 2) |> binary_part(0, 32),
      hash: :sha256,
      age_add: 0,
      issued_at: now,
      expires_at: now + 60_000,
      peer: %{chain: [<<1, 2, 3>>]},
      alpn: nil
    }
  end
end
