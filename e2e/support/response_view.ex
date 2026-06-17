defmodule E2E.ResponseView do
  @moduledoc """
  E2E-friendly wrapper around `HTTP.Response` that decodes JSON bodies and
  exposes typed helpers for the fields the e2e tests assert against.

  Most tests follow this pattern:

      resp =
        E2E.Server.url("/json")
        |> HTTP.fetch()
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      assert view.json!() == %{"ok" => true, "n" => 42}
  """

  @enforce_keys [:status, :headers, :body]
  defstruct [:status, :headers, :body, :url, :stream]

  @type t :: %__MODULE__{
          status: non_neg_integer(),
          headers: HTTP.Headers.t(),
          body: binary() | nil,
          url: URI.t() | nil,
          stream: pid() | nil
        }

  @doc """
  Wraps an `HTTP.Response` (or its error tuple) into a `ResponseView`.

  Raises if given an `{:error, _}` tuple — e2e tests should assert on
  success paths, not on `{:error, _}`.
  """
  @spec from(HTTP.Response.t()) :: t()
  def from(%HTTP.Response{} = r) do
    %__MODULE__{
      status: r.status,
      headers: r.headers,
      body: r.body,
      url: r.url,
      stream: r.stream
    }
  end

  @doc "Returns the raw response body as a binary."
  @spec text(t()) :: binary()
  def text(%__MODULE__{body: body}) when is_binary(body), do: body

  def text(%__MODULE__{stream: pid}) when is_pid(pid) do
    HTTP.Response.read_all(%HTTP.Response{stream: pid})
  end

  def text(%__MODULE__{}), do: ""

  @doc "Decodes the body as JSON. Returns `{:ok, term}` or `{:error, reason}`."
  @spec json(t()) :: {:ok, term()} | {:error, term()}
  def json(%__MODULE__{} = view), do: view |> text() |> JSON.decode()

  @doc "Decodes the body as JSON, raising on failure."
  @spec json!(t()) :: term()
  def json!(%__MODULE__{} = view) do
    case json(view) do
      {:ok, decoded} -> decoded
      {:error, reason} -> raise "JSON decode failed: #{inspect(reason)}"
    end
  end

  @doc "Returns the value of a response header, or `nil` if absent."
  @spec get_header(t(), String.t()) :: String.t() | nil
  def get_header(%__MODULE__{headers: headers}, name) do
    HTTP.Headers.get(headers, name)
  end

  @doc """
  Reads the entire streaming body into a binary and decodes as JSON.

  Useful for the >5MB streaming path where `body` is `nil` and `stream` is a
  pid. Blocks until the stream completes.
  """
  @spec read_json(t()) :: {:ok, term()} | {:error, term()}
  def read_json(%__MODULE__{} = view), do: json(view)

  @doc "Returns the parsed SSE event list. Convenience wrapper around `E2E.SSE`."
  @spec sse_events(t()) :: [E2E.SSE.event()]
  def sse_events(%__MODULE__{} = view), do: view |> text() |> E2E.SSE.parse()
end
