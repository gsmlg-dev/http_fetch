defmodule Abyss.DatagramHandler do
  @moduledoc """
  Application state transitions for the UDP datagram runtime.

  `init/2` receives application options and an immutable context with
  `endpoint_id`, `generation`, and `send` capability. The runtime owns sockets,
  admission, execution deadlines and actions. Callbacks return application
  state independently of this infrastructure.

  Actions are a finite list validated before effects begin. Multiple accepted
  actions are not atomic and local send completion does not prove delivery.
  Strict replies require real source/interface metadata and a capable backend.
  Optional managed events are serialized with datagrams for persistent policies.
  `:endpoint` state is initialized lazily and persists across inactivity and
  pause/resume within its generation. `idle_timeout` evicts only `:keyed` state;
  pending timers do not pin idle keys. Stop, generation replacement, explicit
  stop/error or callback failure can retire state and cancel its timers. This
  lifetime does not provide durable storage or recover unreturned state.
  `terminate/2` receives the last returned application state; a killed callback
  cannot return its unfinished state.
  """

  @type context :: %{
          endpoint_id: term(),
          generation: reference(),
          send: %Abyss.Dispatcher.SendCapability{}
        }
  @type action ::
          {:reply, binary()}
          | {:reply, binary(), :strict}
          | {:send, Abyss.Datagram.sockaddr(), binary()}
          | {:timer, term(), non_neg_integer(), term()}
          | {:cancel_timer, term()}
  @type transition ::
          {:ok, term(), [action()]}
          | {:stop, term(), term(), [action()]}
          | {:error, term(), term()}

  @callback init(options :: term(), context()) :: {:ok, term()} | {:error, term()}
  @callback handle_datagram(Abyss.Datagram.t(), state :: term()) :: transition()
  @callback handle_event(
              {:timer, term(), term()} | {:send_outcomes, reference(), reference(), list()},
              state :: term()
            ) :: transition()
  @callback terminate(reason :: term(), state :: term()) :: term()
  @optional_callbacks handle_event: 2, terminate: 2
end
