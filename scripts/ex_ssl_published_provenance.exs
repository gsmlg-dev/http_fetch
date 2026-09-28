lock = elem(Code.eval_file("mix.lock"), 0)
expected_version = System.fetch_env!("EX_SSL_FIXTURE_VERSION")
expected_inner = System.fetch_env!("EX_SSL_HEX_INNER_CHECKSUM")
expected_outer = System.fetch_env!("EX_SSL_HEX_OUTER_CHECKSUM")

expected_lock =
  {:hex, :ex_ssl, expected_version, expected_inner, [:mix], [], "hexpm", expected_outer}

case lock[:ex_ssl] do
  {:hex, :ex_ssl, ^expected_version, ^expected_inner, _, _, "hexpm", ^expected_outer} -> :ok
  other -> raise "ex_ssl lock provenance mismatch: #{inspect(other)}"
end

dependency = Enum.find(Mix.Dep.cached(), &(&1.app == :ex_ssl)) || raise "ex_ssl is not resolved"

unless dependency.scm == Hex.SCM and dependency.status == {:ok, expected_version} do
  raise "ex_ssl is not a resolved Hex dependency: #{inspect(dependency)}"
end

unless Keyword.fetch!(dependency.opts, :lock) == expected_lock do
  raise "resolved ex_ssl dependency lock differs from expected Hex package"
end

dependency_destination = dependency.opts |> Keyword.fetch!(:dest) |> Path.expand()
dependency_build = dependency.opts |> Keyword.fetch!(:build) |> Path.expand()
expected_destination = Path.expand("deps/ex_ssl", File.cwd!())
expected_build = Path.expand("_build/test/lib/ex_ssl", File.cwd!())

unless dependency_destination == expected_destination and dependency_build == expected_build do
  raise "resolved ex_ssl dependency is outside this consumer build"
end

module_path = SSL.Connection |> :code.which() |> List.to_string() |> Path.expand()
expected_module_root = Path.join(expected_build, "ebin")

unless String.starts_with?(module_path, expected_module_root <> "/") do
  raise "SSL.Connection was loaded from #{module_path}, expected #{expected_module_root}"
end

IO.puts("runtime=hexpm/ex_ssl #{expected_version}")
IO.puts("resolved_scm=Hex.SCM")
IO.puts("resolved_destination=#{dependency_destination}")
IO.puts("resolved_build=#{dependency_build}")
IO.puts("resolved_from=#{dependency.from}")
IO.puts("hex_inner_checksum=#{expected_inner}")
IO.puts("hex_outer_checksum=#{expected_outer}")
IO.puts("loaded_ssl_connection=#{module_path}")
