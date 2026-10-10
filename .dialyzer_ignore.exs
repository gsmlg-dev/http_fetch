[
  # Dialyzer loses the Task.Supervisor.async_nolink/4 return shape in HTTP.fetch/2
  ~r/(apps\/http_fetch\/)?lib\/http\.ex:273.*invalid_contract/,
  ~r/(apps\/http_fetch\/)?lib\/http\.ex:274.*no_return/,

  # HTTP.Promise.then/3 opaque type issue with Task struct - Task.Supervisor returns opaque Task
  ~r/(apps\/http_fetch\/)?lib\/http\/promise\.ex:100.*contract_with_opaque/,

  # Quic.Streams.new/2 retains its public MapSet default. Elixir loses the opaque
  # origin of the compiled literal: https://github.com/elixir-lang/elixir/issues/15673
  # Pin the spec line and function so source drift exposes this exception for review.
  ~r/\A(?:apps\/elixir_quic\/)?lib\/quic\/streams\.ex:90:contract_with_opaque The @spec for new has an opaque subtype which is violated by the success typing\.\z/
]
