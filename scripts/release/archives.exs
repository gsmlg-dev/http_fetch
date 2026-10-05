defmodule ReleaseArchives do
  @order ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)
  @deps %{
    "elixir_quic" => ~w(ex_ssl),
    "http_core" => ~w(ex_ssl elixir_quic),
    "http_runtime" => ~w(http_core elixir_quic_http3),
    "elixir_quic_http3" => ~w(http_core elixir_quic),
    "http_fetch" => ~w(http_core http_runtime),
    "http_web_socket" => ~w(http_core http_runtime),
    "http_event_source" => ~w(http_core http_runtime),
    "http_web_transport" => ~w(http_core)
  }

  def run([version, directory]) do
    Mix.start()
    Mix.Hex.start()

    for package <- @order do
      archive = Path.join(directory, "#{package}-#{version}.tar")
      {:ok, result} = :mix_hex_tarball.unpack(File.read!(archive), :memory)
      metadata = result.metadata

      unless metadata["name"] == package and metadata["version"] == version,
        do: raise("incorrect Hex archive identity: #{archive}")

      requirements = metadata["requirements"] || %{}

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

    IO.puts("all nine Hex archive identities and internal requirements validated")
  end

  def run(_), do: raise("usage: elixir scripts/release/archives.exs VERSION ARCHIVE_DIR")
end

ReleaseArchives.run(System.argv())
