defmodule HTTP.ProxyUserAgentTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  # Issue #171: proxy mode relays the caller's fields and adds no User-Agent.
  for {mode, fields, expected} <- [
        {:proxy, [], nil},
        {:proxy, [{"User-Agent", "Client/1"}], "Client/1"},
        {:fetch, [{"User-Agent", "Client/1"}], "Client/1"},
        {:fetch, [], :default}
      ] do
    test "#{mode} mode with #{inspect(fields)} sends #{inspect(expected)}" do
      head = fetch_head(unquote(mode), unquote(Macro.escape(fields)))

      case unquote(expected) do
        nil -> refute Map.has_key?(head, "user-agent")
        :default -> assert head["user-agent"] =~ "http_fetch/"
        value -> assert head["user-agent"] == value
      end
    end
  end

  defp fetch_head(mode, fields) do
    parent = self()

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :line, active: false, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        {:ok, _request_line} = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, {:head, read_headers(socket, %{})})
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        :gen_tcp.close(socket)
      end)

    on_exit(fn -> :gen_tcp.close(listener) end)

    response =
      "http://127.0.0.1:#{port}/"
      |> HTTP.fetch(request_mode: mode, headers: fields)
      |> HTTP.Promise.await()

    assert %HTTP.Response{status: 200} = response
    Task.await(peer)
    assert_receive {:head, head}
    head
  end

  defp read_headers(socket, acc) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, "\r\n"} ->
        acc

      {:ok, line} ->
        [name, value] = line |> String.trim_trailing("\r\n") |> String.split(":", parts: 2)
        read_headers(socket, Map.put(acc, String.downcase(name), String.trim(value)))
    end
  end
end
