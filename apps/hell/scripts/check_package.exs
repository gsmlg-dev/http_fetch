[artifact, destination, version] = System.argv()
Mix.ensure_application!(:hex)
%{metadata: metadata, contents: contents} = Hex.Tar.unpack!(artifact, :memory)

unless metadata["name"] == "hell" and metadata["app"] == "hell" and
         metadata["version"] == version do
  raise "artifact Hex name, OTP application and version must match hell #{version}"
end

# Write regular file contents ourselves so archive links cannot escape the consumer.
Enum.each(contents, fn {name, content} ->
  name = to_string(name)

  unless Path.type(name) == :relative and ".." not in Path.split(name) do
    raise "unsafe package path: #{inspect(name)}"
  end

  path = Path.join(destination, name)
  File.mkdir_p!(Path.dirname(path))
  File.write!(path, content)
end)

IO.puts("Validated and unpacked package: hell #{version} (OTP :hell)")
