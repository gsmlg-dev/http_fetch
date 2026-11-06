defmodule Abyss.QUIC.Handler do
  @moduledoc """
  Application binding for an `Abyss.QUIC` listener.

  Callbacks run in a per-connection worker. They receive opaque `elixir_quic`
  generation handles and byte-stream events; Abyss does not interpret ALPN or
  application payloads. `init/3` runs after attachment and receives negotiated
  metadata. `handle_event/2` receives public engine events and a `:tick` after
  each batch; the next poll starts after the configured interval. A matching
  engine close notification delivers `{:closed, reason}` once if processed
  before worker termination. Crashes and forced shutdown can prevent delivery.
  Each poll delivers at most `event_batch` engine notifications. Reads remain
  explicitly controlled by the handler through `Abyss.QUIC.read/3`.

  Callbacks must keep their own state bounded. Attachment and initialization
  share `init_timeout`; event draining and all callbacks in a batch share
  `callback_timeout`. Exceeding either budget kills the worker; the engine
  observes consumer death and closes only that connection.
  `terminate/2` is best effort and may be interrupted by the listener drain bound.
  FIN is directional and never implicitly closes the connection.
  """

  @callback init(connection :: term(), metadata :: map(), opts :: term()) ::
              {:ok, state :: term()} | {:error, reason :: term()}
  @callback handle_event(event :: term(), state :: term()) ::
              {:ok, state :: term()} | {:stop, reason :: term(), state :: term()}
  @callback terminate(reason :: term(), state :: term()) :: term()
  @optional_callbacks terminate: 2
end
