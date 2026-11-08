ExUnit.start(exclude: [:integration, :e2e])
ExUnit.configure(exclude: [integration: true, e2e: true, slow: true])

defmodule Abyss.TestHost do
  @moduledoc false

  # Host-networking tests that assume Linux loopback semantics ("lo" interface,
  # 127.0.0.0/8 aliases, large loopback datagrams, directed loopback broadcast).
  # Used as `@tag skip: Abyss.TestHost.linux_only()` so it also applies under
  # `--include integration`, which overrides tag exclusion.
  def linux_only do
    if match?({:unix, :darwin}, :os.type()),
      do: "requires Linux loopback networking",
      else: false
  end
end
