defmodule HTTP.Transport do
  @moduledoc false

  @type socket :: port() | :ssl.sslsocket()
  @type message :: {:data, binary()} | :closed | {:error, term()} | :unknown

  @callback connect(String.t(), non_neg_integer(), keyword(), timeout()) ::
              {:ok, socket()} | {:error, term()}
  @callback send(socket(), iodata()) :: :ok | {:error, term()}
  @callback setopts(socket(), keyword()) :: :ok | {:error, term()}
  @callback close(socket()) :: :ok
  @callback normalize_message(term(), socket()) :: message()
end
