defmodule ReleaseArchives do
  @order ~w(ex_ssl elixir_quic http_core http_pool elixir_quic_http3 http_runtime http_fetch http_test http_web_socket http_event_source http_web_transport abyss hell)
  @deps %{
    "elixir_quic" => ~w(ex_ssl),
    "http_core" => ~w(ex_ssl elixir_quic),
    "http_pool" => ~w(http_core),
    "http_runtime" => ~w(http_core http_pool elixir_quic_http3),
    "http_test" => ~w(http_fetch),
    "elixir_quic_http3" => ~w(http_core elixir_quic),
    "http_fetch" => ~w(http_core http_pool http_runtime),
    "http_web_socket" => ~w(http_core http_runtime),
    "http_event_source" => ~w(http_core http_runtime),
    "http_web_transport" => ~w(http_core)
  }

  def run([version, directory]), do: validate(version, directory, @order)

  def run([version, directory, "--group", "core"]),
    do: validate(version, directory, @order -- ~w(http_test abyss hell))

  def run(_),
    do: raise("usage: elixir scripts/release/archives.exs VERSION ARCHIVE_DIR [--group core]")

  defp validate(version, directory, order) do
    Mix.start()
    Mix.Hex.start()

    for package <- order do
      archive = Path.join(directory, "#{package}-#{version}.tar")
      {:ok, result} = :mix_hex_tarball.unpack(File.read!(archive), :memory)
      metadata = result.metadata

      unless metadata["name"] == package and metadata["version"] == version,
        do: raise("incorrect Hex archive identity: #{archive}")

      requirements = metadata["requirements"] || %{}

      if package in ~w(abyss hell) do
        expected = if package == "abyss", do: ~w(telemetry telemetry_metrics), else: ~w(telemetry)

        unless Enum.sort(Map.keys(requirements)) == expected,
          do: raise("unexpected server dependencies in #{package}")

        minimum = if package == "abyss", do: "~> 1.18", else: ">= 1.18.0"

        unless metadata["elixir"] == minimum,
          do: raise("changed Elixir minimum for #{package}")
      end

      if package == "http_test" do
        unless get_in(requirements, ["plug", "optional"]) == true,
          do: raise("http_test must keep Plug optional")
      end

      for dependency <- Map.get(@deps, package, []) do
        entry = requirements[dependency]

        unless entry && entry["requirement"] == "== #{version}" && entry["optional"] == false &&
                 entry["repository"] in [nil, "hexpm"],
               do: raise("Hex archive #{package} lacks required #{dependency} == #{version}")
      end

      for dependency <- @order -- Map.get(@deps, package, []) do
        if requirements[dependency],
          do: raise("unexpected internal requirement #{dependency} in #{package}")
      end
    end

    IO.puts("selected Hex archive identities and internal requirements validated")
  end
end

ReleaseArchives.run(System.argv())
