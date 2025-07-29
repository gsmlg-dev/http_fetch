defmodule HTTP.Response do
  @moduledoc """
  Represents an HTTP response with status, headers, body, and URL information.
  """

  defstruct status: 0,
            headers: %{},
            body: nil,
            url: nil

  @type t :: %__MODULE__{
          status: integer(),
          headers: %{String.t() => String.t()},
          body: String.t(),
          url: String.t()
        }

  @doc """
  Reads the response body as text.
  """
  @spec text(t()) :: String.t()
  def text(%__MODULE__{body: body}), do: body

  @doc """
  Parses the response body as JSON using Elixir's built-in `JSON` module (available in Elixir 1.18+).

  Returns:
    - `{:ok, map | list}` if the body is valid JSON.
    - `{:error, reason}` if the body cannot be parsed as JSON.
  """
  @spec json(t()) :: {:ok, map() | list()} | {:error, term()}
  def json(%__MODULE__{body: body}) do
    case JSON.decode(body) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, error} -> {:error, error}
    end
  end
end