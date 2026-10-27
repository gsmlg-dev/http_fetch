defmodule SSL.PolicyIO.HTTP do
  @moduledoc false
  alias SSL.PolicyIO.Bounded

  alias SSL.PolicyIO
  @header 16_384
  @body 16_777_216
  @slice 65_536

  def get(context, url, timeout) do
    deadline =
      if context.deadline == :infinity,
        do: PolicyIO.now() + timeout,
        else: min(context.deadline, PolicyIO.now() + timeout)

    fetch(%{context | deadline: deadline}, to_string(url), context)
  catch
    _, _ -> {:error, :policy_http_failed}
  end

  defp fetch(context, url, settlement) when byte_size(url) <= @header do
    with %URI{scheme: "http", host: host, userinfo: nil, fragment: nil} = uri <- URI.parse(url),
         true <- is_binary(host) and byte_size(host) in 1..253,
         {:ok, addresses} <- addresses(host, context.deadline) do
      candidates(context, uri, addresses, settlement)
    else
      {:error, :policy_capacity} = error -> error
      _ -> {:error, :policy_http_failed}
    end
  end

  defp fetch(_, _, _), do: {:error, :policy_capacity}

  defp candidates(_, _, [], _), do: {:error, :policy_http_failed}

  defp candidates(context, uri, [{family, address} | rest], settlement) do
    with {:ok, generation, token} <- PolicyIO.call(context, :http),
         :ok <- available(context),
         {:ok, socket} <- :socket.open(family, :stream, :tcp) do
      result =
        try do
          with :use <-
                 PolicyIO.request(
                   context.observer,
                   {:policy, context.capability, {:http_enroll, generation, token, socket}},
                   settlement.deadline
                 ),
               :ok <- :socket.setopt(socket, :otp, :rcvbuf, @slice),
               :ok <- :socket.setopt(socket, :socket, :linger, %{onoff: false, linger: 0}),
               :ok <- available(context),
               :ok <-
                 :socket.connect(
                   socket,
                   %{family: family, addr: address, port: uri.port || 80},
                   PolicyIO.remaining(context.deadline)
                 ),
               :ok <- available(context),
               :ok <- :socket.send(socket, request(uri), PolicyIO.remaining(context.deadline)) do
            response(socket, context, <<>>)
          else
            _ -> {:error, :policy_http_failed}
          end
        after
          close(settlement, generation, socket)
        end

      case PolicyIO.settled(settlement, generation) do
        :ok ->
          case result do
            {:redirect, location} ->
              fetch(context, URI.merge(uri, location) |> URI.to_string(), settlement)

            {:error, :policy_http_failed} when rest != [] ->
              candidates(context, uri, rest, settlement)

            other ->
              other
          end

        _ ->
          {:error, :policy_io_unconfirmed}
      end
    else
      {:error, :auxiliary_limit} -> {:error, :policy_capacity}
      _ -> {:error, :policy_io_unconfirmed}
    end
  end

  # Retire the owner only after its acknowledged native close returns. When
  # admission is already closed, owner exit closes the socket instead of racing
  # an explicit two-stage close with the observer's kill. Only its original
  # socket monitor can establish auxiliary cleanup.
  defp close(context, generation, socket) do
    cleanup_deadline =
      case context.deadline do
        :infinity -> PolicyIO.now() + 1_000
        deadline -> deadline + 1_000
      end

    with :ok <- PolicyIO.call(context, {:http_begin_close, generation}),
         :ok <- :socket.close(socket),
         :ok <-
           PolicyIO.request(
             context.observer,
             {:policy, context.capability, {:http_close_finished, generation}},
             cleanup_deadline
           ) do
      :ok
    else
      _ -> throw(:policy_io_unconfirmed)
    end
  end

  defp addresses(host, deadline) do
    name = String.to_charlist(host)

    case :inet.parse_address(name) do
      {:ok, address} when tuple_size(address) == 4 ->
        {:ok, [{:inet, address}]}

      {:ok, address} when tuple_size(address) == 8 ->
        {:ok, [{:inet6, address}]}

      _ ->
        Enum.reduce_while([:inet, :inet6], {:ok, []}, fn family, {:ok, acc} ->
          resolve_family(name, family, deadline, acc)
        end)
    end
  end

  defp resolve_family(name, family, deadline, acc) do
    case :inet.getaddrs(name, family, PolicyIO.remaining(deadline)) do
      {:ok, values} ->
        with {:ok, values} <- Bounded.list(values, 32),
             {:ok, combined} <-
               Bounded.list(acc ++ Enum.map(values, &{family, &1}), 32) do
          {:cont, {:ok, combined}}
        else
          error -> {:halt, error}
        end

      _ ->
        {:cont, {:ok, acc}}
    end
  end

  defp available(context) do
    if PolicyIO.remaining(context.deadline) > 0 and Process.alive?(context.observer),
      do: :ok,
      else: {:error, :policy_http_failed}
  end

  defp request(uri) do
    path = (uri.path || "/") <> if(uri.query, do: "?" <> uri.query, else: "")
    authority = if String.contains?(uri.host, ":"), do: "[" <> uri.host <> "]", else: uri.host

    host =
      authority <> if(uri.port in [nil, 80], do: "", else: ":" <> Integer.to_string(uri.port))

    if String.contains?(path <> host, ["\r", "\n"]), do: throw(:invalid_uri)

    [
      "GET ",
      path,
      " HTTP/1.1\r\nHost: ",
      host,
      "\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
    ]
  end

  defp response(socket, context, buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {position, 4} when position + 4 <= @header ->
        <<headers::binary-size(^position), _::32, rest::binary>> = buffer

        with {:ok, status, headers} <- headers(headers) do
          response_body(status, headers, socket, context, rest)
        end

      :nomatch when byte_size(buffer) < @header ->
        with {:ok, bytes} <- recv(socket, context, @header - byte_size(buffer)),
             do: response(socket, context, buffer <> bytes)

      _ ->
        {:error, :policy_capacity}
    end
  end

  defp response_body(status, headers, socket, context, rest) do
    cond do
      status in [301, 302, 303, 307, 308] ->
        case headers["location"] do
          nil -> {:error, :policy_http_failed}
          location -> {:redirect, location}
        end

      status == 200 ->
        body(socket, context, headers, rest)

      true ->
        {:error, :policy_http_failed}
    end
  end

  defp headers(bytes) do
    [status | fields] = String.split(bytes, "\r\n")

    with ["HTTP/1." <> minor, code | _] when minor in ["0", "1"] <- String.split(status, " "),
         {number, ""} <- Integer.parse(code) do
      Enum.reduce_while(fields, {:ok, number, %{}}, fn field, {:ok, number, headers} ->
        header(field, number, headers)
      end)
    else
      _ -> {:error, :policy_http_failed}
    end
  end

  defp header(field, number, headers) do
    case String.split(field, ":", parts: 2) do
      [name, value] ->
        name = String.downcase(name)

        if Map.has_key?(headers, name),
          do: {:halt, {:error, :policy_http_failed}},
          else: {:cont, {:ok, number, Map.put(headers, name, String.trim(value))}}

      _ ->
        {:halt, {:error, :policy_http_failed}}
    end
  end

  defp body(socket, context, headers, rest) do
    cond do
      Map.get(headers, "content-encoding", "identity") != "identity" ->
        {:error, :policy_http_failed}

      headers["transfer-encoding"] == "chunked" and not Map.has_key?(headers, "content-length") ->
        chunks(socket, context, rest, [], 0, 0)

      Map.has_key?(headers, "transfer-encoding") ->
        {:error, :policy_http_failed}

      Map.has_key?(headers, "content-length") ->
        case Integer.parse(headers["content-length"]) do
          {size, ""} when size >= 0 and size <= @body -> fixed(socket, context, rest, size, [])
          _ -> {:error, :policy_capacity}
        end

      true ->
        until_close(socket, context, rest, [], 0)
    end
  end

  defp fixed(_socket, _context, bytes, remaining, acc) when byte_size(bytes) == remaining,
    do: {:ok, IO.iodata_to_binary(Enum.reverse([bytes | acc]))}

  defp fixed(socket, context, bytes, remaining, acc) when byte_size(bytes) < remaining do
    with {:ok, next} <- recv(socket, context, min(@slice, remaining - byte_size(bytes))),
         do: fixed(socket, context, next, remaining - byte_size(bytes), [bytes | acc])
  end

  defp fixed(_, _, _, _, _), do: {:error, :policy_http_failed}

  defp until_close(socket, context, bytes, acc, total) when total + byte_size(bytes) <= @body do
    case recv(socket, context, min(@slice, @body - total - byte_size(bytes) + 1)) do
      {:ok, next} -> until_close(socket, context, next, [bytes | acc], total + byte_size(bytes))
      {:error, :closed} -> {:ok, IO.iodata_to_binary(Enum.reverse([bytes | acc]))}
      _ -> {:error, :policy_http_failed}
    end
  end

  defp until_close(_, _, _, _, _), do: {:error, :policy_capacity}

  defp chunks(_, _, _, _, _, count) when count >= 65_536, do: {:error, :policy_capacity}

  defp chunks(socket, context, buffer, acc, total, count) do
    with {:ok, line, rest} <- line(socket, context, buffer),
         {size, ""} when size >= 0 <- Integer.parse(hd(String.split(line, ";", parts: 2)), 16),
         true <- total + size <= @body do
      if size == 0 do
        with {:ok, <<>>, <<>>} <- line(socket, context, rest),
             do: {:ok, IO.iodata_to_binary(Enum.reverse(acc))}
      else
        with {:ok, framed, tail} <- take(socket, context, rest, size + 2),
             <<data::binary-size(^size), "\r\n">> <- framed do
          chunks(socket, context, tail, [data | acc], total + size, count + 1)
        else
          _ -> {:error, :policy_http_failed}
        end
      end
    else
      false -> {:error, :policy_capacity}
      _ -> {:error, :policy_http_failed}
    end
  end

  defp line(socket, context, buffer) do
    case :binary.match(buffer, "\r\n") do
      {position, 2} when position <= @header ->
        <<line::binary-size(^position), _::16, rest::binary>> = buffer
        {:ok, line, rest}

      :nomatch when byte_size(buffer) < @header ->
        with {:ok, next} <- recv(socket, context, min(@slice, @header - byte_size(buffer))),
             do: line(socket, context, buffer <> next)

      _ ->
        {:error, :policy_capacity}
    end
  end

  defp take(_, _, buffer, size) when byte_size(buffer) >= size do
    <<data::binary-size(^size), rest::binary>> = buffer
    {:ok, data, rest}
  end

  defp take(socket, context, buffer, size) do
    with {:ok, bytes} <- recv(socket, context, min(@slice, size - byte_size(buffer))),
         do: take(socket, context, buffer <> bytes, size)
  end

  defp recv(socket, context, size) do
    with :ok <- available(context),
         :ok <- :socket.setopt(socket, :otp, :rcvbuf, {1, min(@slice, size)}) do
      :socket.recv(socket, 0, PolicyIO.remaining(context.deadline))
    end
  end
end
