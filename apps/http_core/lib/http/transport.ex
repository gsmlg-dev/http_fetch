defmodule HTTP.Transport do
  @moduledoc false

  @type socket ::
          port() | :ssl.sslsocket() | HTTP.Transport.SSL.cancellable_socket() | SSL.Socket.t()
  @type message :: {:data, binary()} | :closed | {:error, term()} | :unknown

  @doc false
  def valid_connect_address?(address) when is_tuple(address) and tuple_size(address) in [4, 8] do
    maximum = if tuple_size(address) == 4, do: 255, else: 65_535
    address |> Tuple.to_list() |> Enum.all?(&(is_integer(&1) and &1 >= 0 and &1 <= maximum))
  end

  def valid_connect_address?(_address), do: false

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
