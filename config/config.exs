import Config

config :logger, :default_formatter, metadata: [:reason, :event, :metadata, :measurements]
