defmodule SSL.HonorCipherOrderTest do
  use ExUnit.Case, async: true

  alias SSL.Options

  @role_error {:error, {:option, :server_only, :honor_cipher_order}}
  @versions [
    [:"tlsv1.2"],
    [:"tlsv1.3"],
    [:"tlsv1.3", :"tlsv1.2"],
    [:"tlsv1.2", :"tlsv1.3"]
  ]

  test "explicit client values return the exact role error before connecting" do
    for versions <- @versions, value <- [true, false, nil, :bad, 0, "invalid"] do
      options = [honor_cipher_order: value, versions: versions]

      assert @role_error == Options.normalize("example.test", options)
      assert @role_error == SSL.connect({127, 0, 0, 1}, 0, options, 100)
      assert @role_error == SSL.connect({127, 0, 0, 1}, 0, options)
      assert @role_error == SSL.prepare_upgrade(options)
    end
  end

  test "role errors neither invoke nor retain supplied values before trust access" do
    marker = "R51_PRIVATE_HONOR_VALUE"
    callback = fn -> raise "honor value must never execute" end

    for value <- [marker, %{private: marker}, {callback, marker}, [marker | marker]] do
      options = [
        honor_cipher_order: value,
        cacertfile: "/R51-must-not-read/missing-ca.pem"
      ]

      result = Options.normalize("example.test", options)
      assert @role_error == result
      assert @role_error == SSL.connect({127, 0, 0, 1}, 0, options, 100)
      assert @role_error == SSL.prepare_upgrade(options)
      refute inspect(result) =~ marker
    end
  end

  test "undefined preserves omitted normalization and concrete profile order" do
    for versions <- @versions do
      options = [verify: :verify_none, cacerts: [], versions: versions]
      assert {:ok, omitted} = Options.normalize("example.test", options)

      assert {:ok, ^omitted} =
               Options.normalize("example.test", [honor_cipher_order: :undefined] ++ options)

      assert {:ok, ^omitted} =
               Options.normalize(
                 "example.test",
                 options ++ [honor_cipher_order: :undefined, ex_ssl: [profile: omitted.profile]]
               )

      assert {:ok, prepared} = SSL.prepare_upgrade(options)

      assert {:ok, ^prepared} =
               SSL.prepare_upgrade([honor_cipher_order: :undefined] ++ options)
    end
  end

  test "duplicate and malformed option containers keep their existing errors" do
    for options <- [
          [honor_cipher_order: true, honor_cipher_order: false],
          [honor_cipher_order: :undefined, honor_cipher_order: :undefined],
          [:honor_cipher_order],
          [{"honor_cipher_order", true}]
        ] do
      assert {:error, {:options, :invalid_options}} =
               Options.normalize("example.test", options)

      assert {:error, {:options, :invalid_options}} =
               SSL.connect({127, 0, 0, 1}, 0, options, 100)

      assert {:error, {:options, :invalid_options}} = SSL.prepare_upgrade(options)
    end
  end

  test "unrelated invalid options retain caller validation order" do
    assert {:error, {:options, {:verify, :unsupported_or_invalid}}} =
             Options.normalize("example.test", verify: :bad, honor_cipher_order: true)

    assert @role_error ==
             Options.normalize("example.test", honor_cipher_order: true, verify: :bad)

    assert {:error, {:options, {:verify, :unsupported_or_invalid}}} =
             Options.normalize("example.test", honor_cipher_order: :undefined, verify: :bad)
  end

  test "setopts does not admit a connection-only role option" do
    for value <- [true, false, :undefined, nil, :bad] do
      assert {:error, {:options, {:honor_cipher_order, :unsupported_or_invalid}}} =
               Options.normalize_setopts(honor_cipher_order: value)
    end
  end
end
