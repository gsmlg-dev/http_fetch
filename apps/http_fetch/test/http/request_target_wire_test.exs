defmodule HTTP.RequestTargetWireTest do
  use ExUnit.Case, async: true

  for suffix <- ["", "?", "?key=%2F%3F&value=a%20b"],
      method <- [:post, :get, :delete],
      input <- [:string, :uri] do
    test "streaming proxy #{method} preserves #{inspect(suffix)} with #{input} input" do
      parent = self()

      {:ok, listener} =
        :gen_tcp.listen(0, [:binary, packet: :line, active: false, ip: {127, 0, 0, 1}])

      {:ok, port} = :inet.port(listener)

      peer =
        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)
          {:ok, line} = :gen_tcp.recv(socket, 0, 2_000)
          read_headers(socket)
          :ok = :inet.setopts(socket, packet: :raw)
          assert {:ok, "payload"} = :gen_tcp.recv(socket, 7, 2_000)
          send(parent, {:request_line, self(), line})
          :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
          assert_receive :release_body, 2_000
          :ok = :gen_tcp.send(socket, "ok")
          :gen_tcp.close(socket)
        end)

      on_exit(fn ->
        if Process.alive?(peer), do: Process.exit(peer, :kill)
        :gen_tcp.close(listener)
      end)

      target = "/up%2Fload" <> unquote(suffix)
      url = "http://127.0.0.1:#{port}" <> target <> "#fragment"
      url = if unquote(input) == :uri, do: URI.parse(url), else: url
      {:ok, body} = HTTP.Stream.from_enumerable(["pay", "load"])

      promise =
        HTTP.fetch(url,
          method: unquote(method),
          request_mode: :proxy,
          http_version: :http1,
          http1_reuse: false,
          redirect: :manual,
          body: body,
          duplex: :half,
          headers: [{"content-length", "7"}],
          stream_response: true,
          decode_body: false,
          telemetry: false,
          timeout: 2_000
        )

      completion = HTTP.Promise.completion(promise)
      response = HTTP.Promise.await(promise, 2_000)
      assert %HTTP.Response{status: 200, stream: stream} = response
      assert is_pid(stream)
      assert_receive {:request_line, ^peer, line}, 2_000

      assert line ==
               "#{unquote(method) |> Atom.to_string() |> String.upcase()} #{target} HTTP/1.1\r\n"

      send(peer, :release_body)
      assert HTTP.Response.read_all(response) == "ok"
      assert :ok = HTTP.RequestCompletion.await(completion, 2_000)
    end
  end

  defp read_headers(socket) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, "\r\n"} -> :ok
      {:ok, _header} -> read_headers(socket)
    end
  end
end
