defmodule SSL.MiddleboxCompModeOptionsTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.{Materializer, Serializer}
  alias SSL.Options
  alias SSL.Protocol.ClientOffer

  @versions [[:"tlsv1.3"], [:"tlsv1.3", :"tlsv1.2"], [:"tlsv1.2", :"tlsv1.3"]]
  @base [verify: :verify_none, cacerts: [], server_name_indication: ~c"example.test"]

  test "boolean controls change only the default session ID policy" do
    for versions <- @versions do
      options = @base ++ [versions: versions, alpn_advertised_protocols: ["h2", "http/1.1"]]
      assert {:ok, omitted} = Options.normalize("example.test", options)
      assert omitted.profile.session_id == :random_32

      assert {:ok, ^omitted} =
               Options.normalize("example.test", options ++ [middlebox_comp_mode: true])

      assert {:ok, disabled} =
               Options.normalize("example.test", options ++ [middlebox_comp_mode: false])

      assert disabled.profile == %{omitted.profile | session_id: :empty}
    end
  end

  test "explicit booleans require TLS13 in the offered versions" do
    versions = [:"tlsv1.2"]

    assert {:ok, %{profile: %{session_id: :empty}}} =
             Options.normalize("example.test", @base ++ [versions: versions])

    for mode <- [true, false] do
      options = @base ++ [versions: versions, middlebox_comp_mode: mode]

      expected =
        {:error, {:options, :incompatible, [:middlebox_comp_mode, {:versions, versions}]}}

      assert expected == Options.normalize("example.test", options)
      assert expected == SSL.prepare_upgrade(options)
      assert expected == SSL.connect({127, 0, 0, 1}, 0, options, 100)
    end
  end

  test "concrete profiles preserve ordering and require exact session ID policies" do
    for versions <- @versions do
      options = @base ++ [versions: versions, alpn_advertised_protocols: ["h2", "http/1.1"]]
      assert {:ok, original} = Options.normalize("example.test", options)

      for policy <- [:random_32, :empty, {:fixed, <<>>}, {:fixed, <<7::256>>}] do
        profile = %{original.profile | session_id: policy}
        concrete = options ++ [ex_ssl: [profile: profile]]
        assert {:ok, %{profile: ^profile}} = Options.normalize("example.test", concrete)

        for {mode, required} <- [{true, :random_32}, {false, :empty}] do
          configured = concrete ++ [middlebox_comp_mode: mode]

          if policy == required do
            assert {:ok, %{profile: ^profile}} = Options.normalize("example.test", configured)
            assert {:ok, prepared} = SSL.prepare_upgrade(configured)
            assert {:ok, %{profile: ^profile}} = SSL.PreparedUpgrade.fetch_options(prepared)
          else
            expected = {:error, {:options, {:middlebox_comp_mode, :profile_conflict}}}
            assert expected == Options.normalize("example.test", configured)
            assert expected == SSL.prepare_upgrade(configured)
            assert expected == SSL.connect({127, 0, 0, 1}, 0, configured, 100)
          end
        end
      end
    end
  end

  test "materialized IDs have the requested length and fresh connection randomness" do
    for versions <- @versions, mode <- [:omitted, true, false] do
      options = @base ++ [versions: versions] ++ control(mode)
      assert {:ok, normalized} = Options.normalize("example.test", options)

      assert {:ok, first} =
               Materializer.materialize(
                 normalized.profile,
                 Options.capabilities(),
                 normalized.context
               )

      assert {:ok, second} =
               Materializer.materialize(
                 normalized.profile,
                 Options.capabilities(),
                 normalized.context
               )

      refute first.client_hello.random == second.client_hello.random

      if mode == false do
        assert first.client_hello.session_id == <<>>
        assert second.client_hello.session_id == <<>>
      else
        assert byte_size(first.client_hello.session_id) == 32
        assert byte_size(second.client_hello.session_id) == 32
        refute first.client_hello.session_id == second.client_hello.session_id
      end

      assert {:ok, wire} = Serializer.encode(first.client_hello)
      assert {:ok, offer} = ClientOffer.from_client_hello(wire)
      assert offer.legacy_session_id == first.client_hello.session_id
      assert offer.offered_versions == Enum.map(versions, &version_id/1)
    end
  end

  test "a concrete profile requiring SNI still rejects an upgrade without SNI" do
    assert {:ok, %{profile: profile}} = Options.normalize("example.test", @base)
    options = Keyword.delete(@base, :server_name_indication) ++ [ex_ssl: [profile: profile]]
    assert {:error, {:options, {:ex_ssl, :unsupported_profile}}} = SSL.prepare_upgrade(options)
  end

  test "omitted defaults and explicit default profiles retain their policy" do
    assert {:ok, omitted} = Options.normalize("example.test", @base)

    assert {:ok, ^omitted} =
             Options.normalize("example.test", @base ++ [middlebox_comp_mode: true])

    assert {:ok, disabled} =
             Options.normalize(
               "example.test",
               @base ++ [middlebox_comp_mode: false, ex_ssl: [profile: :default]]
             )

    assert disabled.profile == %{omitted.profile | session_id: :empty}
  end

  test "malformed values are redacted and never invoked" do
    marker = "R51_PRIVATE_MIDDLEBOX"
    callback = fn -> raise "middlebox callback must never execute" end

    for versions <- [[:"tlsv1.2"] | @versions],
        value <- [:undefined, nil, 0, marker, %{private: marker}, callback, [marker | marker]] do
      options = @base ++ [versions: versions, middlebox_comp_mode: value]
      expected = {:error, {:options, {:middlebox_comp_mode, :unsupported_or_invalid}}}
      result = Options.normalize("example.test", options)
      assert expected == result
      refute inspect(result) =~ marker
      assert expected == SSL.prepare_upgrade(options)
      assert expected == SSL.connect({127, 0, 0, 1}, 0, options, 100)
    end
  end

  test "containers, duplicates, caller validation order and setopts keep their errors" do
    for options <- [
          [middlebox_comp_mode: true, middlebox_comp_mode: false],
          [:middlebox_comp_mode],
          [{"middlebox_comp_mode", true}]
        ] do
      assert {:error, {:options, :invalid_options}} = Options.normalize("example.test", options)
    end

    assert {:error, {:options, {:verify, :unsupported_or_invalid}}} =
             Options.normalize("example.test", verify: :bad, middlebox_comp_mode: :bad)

    assert {:error, {:options, {:middlebox_comp_mode, :unsupported_or_invalid}}} =
             Options.normalize("example.test", middlebox_comp_mode: :bad, verify: :bad)

    for mode <- [true, false, :undefined] do
      assert {:error, {:options, {:middlebox_comp_mode, :unsupported_or_invalid}}} =
               Options.normalize_setopts(middlebox_comp_mode: mode)
    end
  end

  defp control(:omitted), do: []
  defp control(mode), do: [middlebox_comp_mode: mode]
  defp version_id(:"tlsv1.2"), do: 0x0303
  defp version_id(:"tlsv1.3"), do: 0x0304
end
