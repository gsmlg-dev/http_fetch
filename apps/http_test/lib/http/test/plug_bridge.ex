defmodule HTTP.Test.PlugBridge do
  @moduledoc false

  # Keep all Plug calls dynamic: a consumer without this optional dependency
  # must compile the complete core adapter, not merely avoid calling a module.
  def call(%HTTP.Request{} = request, plug, opts) do
    unless Code.ensure_loaded?(Plug.Test) and Code.ensure_loaded?(Plug.Conn),
      do: raise(ArgumentError, "HTTP.Test.plug requires the optional Plug dependency")

    limit = Keyword.get(opts, :body_limit, 1_048_576)

    unless is_integer(limit) and limit > 0,
      do: raise(ArgumentError, "Plug body_limit must be finite and positive")

    if is_pid(request.body),
      do:
        raise(ArgumentError, "Plug bridge requires a buffered request body; use stream fixtures")

    body = IO.iodata_to_binary(request.body || "")
    if byte_size(body) > limit, do: raise(ArgumentError, "Plug request body exceeds body_limit")

    method = request.method |> to_string() |> String.upcase()
    conn = apply(Plug.Test, :conn, [method, URI.to_string(request.url), body])

    headers =
      Enum.map(HTTP.Headers.to_list(request.headers), fn {name, value} ->
        {String.downcase(name), value}
      end)

    conn = Map.put(conn, :req_headers, headers)
    conn = invoke(conn, plug)
    response_body = IO.iodata_to_binary(Map.get(conn, :resp_body) || "")

    if byte_size(response_body) > limit,
      do: raise(ArgumentError, "Plug response body exceeds body_limit")

    if Map.get(conn, :state) == :chunked,
      do: raise(ArgumentError, "Plug bridge requires a buffered response; use stream fixtures")

    HTTP.Test.response(
      Map.get(conn, :status) || 200,
      response_body,
      Map.get(conn, :resp_headers, [])
    )
  end

  defp invoke(conn, {module, options}) when is_atom(module),
    do: apply(module, :call, [conn, apply(module, :init, [options])])

  defp invoke(conn, module) when is_atom(module), do: invoke(conn, {module, []})
  defp invoke(conn, fun) when is_function(fun, 1), do: fun.(conn)
end
