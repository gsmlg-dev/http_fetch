Mix.start()
Mix.Hex.start()

[specification] = System.argv()
packages = specification |> File.read!() |> JSON.decode!()

for {package, %{"version" => version, "archive" => archive}} <- packages do
  {:ok, result} = :mix_hex_tarball.unpack(File.read!(archive), :memory)
  metadata = result.metadata

  unless metadata["name"] == package and metadata["version"] == version,
    do: raise("incorrect server Hex identity: #{archive}")

  requirements = Map.keys(metadata["requirements"] || %{}) |> Enum.sort()

  expected =
    case package do
      "abyss" -> ~w(telemetry telemetry_metrics)
      "hell" -> ~w(telemetry)
      "abyss_raw" -> ~w(rustler)
    end

  unless requirements == expected,
    do: raise("unexpected #{package} dependencies: #{inspect(requirements)}")

  minimum = if package == "hell", do: ">= 1.18.0", else: "~> 1.18"
  unless metadata["elixir"] == minimum, do: raise("changed Elixir minimum for #{package}")
end

IO.puts("server Hex identities, isolated dependency boundaries and Elixir minimums validated")
