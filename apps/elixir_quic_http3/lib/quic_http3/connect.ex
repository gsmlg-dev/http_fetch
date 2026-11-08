defmodule QuicHttp3.Connect do
  @moduledoc "Explicit extended CONNECT validation and peer SETTINGS readiness."

  def ready(%{received_settings?: false}), do: :pending
  def ready(nil), do: :pending

  def ready(%{peer_settings: settings}) do
    if List.keyfind(settings, 8, 0) == {8, 1},
      do: :ready,
      else: {:error, :extended_connect_not_supported}
  end

  def fields(protocol, fields)
      when protocol in ["websocket", "webtransport-h3"] and is_list(fields) do
    if Enum.all?(fields, fn
         {name, value} when is_binary(name) and is_binary(value) ->
           String.valid?(name) and String.valid?(value) and
             not Enum.any?(:binary.bin_to_list(value), &(&1 < 32 or &1 == 127))

         _ ->
           false
       end),
       do: validate_fields(protocol, fields),
       else: {:error, :invalid_fields}
  end

  def fields(_, _), do: {:error, :unsupported_connect_protocol}

  defp validate_fields(protocol, fields) do
    {pseudo, regular} =
      Enum.split_while(fields, fn {name, _} -> String.starts_with?(name, ":") end)

    names = Enum.map(pseudo, &elem(&1, 0))
    values = Map.new(pseudo)

    cond do
      Enum.sort(names) != Enum.sort(~w(:method :scheme :authority :path)) ->
        {:error, :invalid_extended_connect_pseudo_headers}

      values[":method"] != "CONNECT" or values[":scheme"] != "https" or
        values[":authority"] == "" or not String.starts_with?(values[":path"], "/") ->
        {:error, :invalid_extended_connect_target}

      Enum.any?(regular, fn {name, value} ->
        String.starts_with?(name, ":") or name != String.downcase(name) or
          name in ~w(host connection upgrade keep-alive proxy-connection transfer-encoding content-length sec-websocket-key sec-websocket-accept) or
            (name == "te" and value != "trailers")
      end) ->
        {:error, :invalid_extended_connect_headers}

      true ->
        {:ok, pseudo ++ [{":protocol", protocol}] ++ regular}
    end
  end
end
