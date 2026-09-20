defmodule HTTP.Transport do
  @moduledoc false

  @type socket :: port() | :ssl.sslsocket() | SSL.Socket.t()
  @type message :: {:data, binary()} | :closed | {:error, term()} | :unknown

  @callback connect(String.t(), non_neg_integer(), keyword(), timeout()) ::
              {:ok, socket()} | {:error, term()}
  @callback controlling_process(socket(), pid()) :: :ok | {:error, term()}
  @callback send(socket(), iodata()) :: :ok | {:error, term()}
  @callback recv(socket(), non_neg_integer(), timeout()) :: {:ok, binary()} | {:error, term()}
  @callback negotiated_protocol(socket()) :: {:ok, binary() | nil} | {:error, term()}
  @callback setopts(socket(), keyword()) :: :ok | {:error, term()}
  @callback close(socket()) :: :ok | {:error, term()}
  @callback normalize_message(term(), socket()) :: message()
end
