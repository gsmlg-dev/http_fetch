defmodule HTTP.Adapter do
  @moduledoc """
  A two-stage request adapter for `HTTP.fetch/2`.

  Pass `adapter: {Module, configuration}` (or `adapter: Module`). `prepare/2`
  runs in the caller after Fetch input normalization and must return immutable
  context. `execute/3` runs in the request's existing Promise worker. Adapters
  return an `HTTP.Response` or `{:error, reason}`; Fetch applies telemetry and
  the requested error mode. Adapter errors never fall back to socket transport.

  Adapters own the resources they create and must register applicable streams
  with `HTTP.RequestLifecycle.current/0`. Simulated cleanup proves only those
  resources, not network or pool behavior.
  """

  @callback prepare(HTTP.Request.t(), term()) :: {:ok, term()} | {:error, term()}
  @callback execute(HTTP.Request.t(), term(), pid() | nil) ::
              HTTP.Response.t() | {:error, term()}

  @doc false
  def prepare(_request, nil), do: {:ok, nil}

  def prepare(request, module) when is_atom(module), do: prepare(request, {module, []})

  def prepare(request, {module, configuration}) when is_atom(module) do
    if Code.ensure_loaded?(module) and function_exported?(module, :prepare, 2) and
         function_exported?(module, :execute, 3) do
      # Validate the envelope with existing wire checks, without reading files.
      _ = request |> validation_request() |> HTTP.HTTP1.prepare_request()

      case module.prepare(request, configuration) do
        {:ok, context} -> {:ok, {module, context}}
        {:error, _} = error -> error
        _ -> {:error, {:invalid_adapter, :prepare_result}}
      end
    else
      {:error, {:invalid_adapter, :callbacks}}
    end
  end

  def prepare(_request, _selection), do: {:error, {:invalid_adapter, :configuration}}

  @doc false
  def execute(request, {module, context}, signal), do: module.execute(request, context, signal)

  defp validation_request(%HTTP.Request{body: %HTTP.FormData{} = form} = request) do
    parts = Enum.map(form.parts, &validation_part/1)
    %{request | body: %{form | parts: parts}}
  end

  defp validation_request(request), do: request

  defp validation_part({:file, name, filename, content_type, %File.Stream{}}),
    do: {:file, name, filename, content_type, ""}

  defp validation_part(part), do: part
end
