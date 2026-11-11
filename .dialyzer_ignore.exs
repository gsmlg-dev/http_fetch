[
  # Quic.Streams.new/2 retains its public MapSet default. Elixir loses the opaque
  # origin of the compiled literal: https://github.com/elixir-lang/elixir/issues/15673
  # Pin the spec line and function so source drift exposes this exception for review.
  ~r/\A(?:apps\/elixir_quic\/)?lib\/quic\/streams\.ex:93:contract_with_opaque The @spec for new has an opaque subtype which is violated by the success typing\.\z/
]
