defmodule SSL.VerifyFunOptionsTest do
  use ExUnit.Case, async: true

  test "ordinary verification accepts the observed callback forms without invoking them" do
    tuple3 = {fn _, _, _ -> raise "callback ran during normalization" end, :initial}
    tuple4 = {fn _, _, _, _ -> raise "callback ran during normalization" end, :initial}
    legacy = fn _ -> raise "callback ran during normalization" end

    for callback <- [tuple3, tuple4, legacy, :undefined] do
      assert {:ok, options} =
               SSL.Options.normalize("example.test",
                 verify: :verify_none,
                 cacerts: [],
                 verify_fun: callback
               )

      assert options.verify == :verify_none
      assert options.verify_fun == callback
      assert options.trust_source == []
    end
  end

  test "malformed callbacks reject before CA file access and never retain the supplied term" do
    marker = "R44_PRIVATE_CALLBACK_MARKER"

    for callback <- [
          nil,
          false,
          marker,
          {fn _ -> true end, marker},
          {fn _, _ -> true end, marker},
          {fn _, _, _, _, _ -> true end, marker},
          {fn _, _, _ -> true end},
          {fn _, _, _ -> true end, marker, marker},
          {marker, marker}
        ] do
      assert {:error, {:options, {:verify_fun, :unsupported_or_invalid}}} =
               result =
               SSL.Options.normalize("example.test",
                 verify_fun: callback,
                 cacertfile: "/R44-must-not-read/missing-ca.pem"
               )

      refute inspect(result) =~ marker
    end
  end

  test "callback empty CA is distinct from malformed trust and no-callback peer policy" do
    callback = {fn _, _, state -> {:valid, state} end, :initial}

    for mode <- [:verify_peer, :verify_none] do
      assert {:ok, %{trust_source: []}} =
               SSL.Options.normalize("example.test",
                 verify: mode,
                 cacerts: [],
                 verify_fun: callback
               )

      assert {:error, {:options, {:cacerts, :invalid}}} =
               SSL.Options.normalize("example.test",
                 verify: mode,
                 cacerts: [<<1, 2, 3>>],
                 verify_fun: callback
               )
    end

    assert {:error, {:options, {:cacerts, :invalid}}} =
             SSL.Options.normalize("example.test", cacerts: [])
  end

  test "callback trust preserves capacity precedence and sanitizes malformed input" do
    callback = {fn _, _, _ -> raise "callback ran during normalization" end, :initial}
    private_marker = "R49_PRIVATE_CA_MARKER"

    for mode <- [:verify_peer, :verify_none] do
      for trust <- [List.duplicate(<<1, 2, 3>>, 4_097), [:binary.copy(<<0>>, 16_777_217)]] do
        assert {:error, :policy_capacity} =
                 SSL.Options.normalize("example.test",
                   verify: mode,
                   cacerts: trust,
                   verify_fun: callback
                 )
      end

      assert {:error, {:options, {:cacerts, :invalid}}} =
               result =
               SSL.Options.normalize("example.test",
                 verify: mode,
                 cacerts: [<<1, 2, 3>> <> private_marker],
                 verify_fun: callback
               )

      refute inspect(result) =~ private_marker
    end
  end

  test "undefined preserves the absent no-callback verify_none policy" do
    assert {:ok, absent} = SSL.Options.normalize("example.test", verify: :verify_none)

    assert {:ok, undefined} =
             SSL.Options.normalize("example.test", verify: :verify_none, verify_fun: :undefined)

    assert absent == undefined
    assert absent.trust_source == nil
    refute inspect(absent) =~ "verify_fun"
  end
end
