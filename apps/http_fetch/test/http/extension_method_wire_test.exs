defmodule HTTP.ExtensionMethodWireTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias HTTP.HTTP2.HPACK
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @body "<d:propfind xmlns:d=\"DAV:\"><d:allprop/></d:propfind>"
  @authorization "Basic Zml4dHVyZTpwYXNzd29yZA=="

  for protocol <- [:http1, :h2c],
      mode <- [:fetch, :proxy],
      {method, token} <- [
        {:propfind, "PROPFIND"},
        {:report, "REPORT"},
        {"PROPFIND", "PROPFIND"},
        {"REPORT", "REPORT"},
        {"MiXeD", "MiXeD"}
      ] do
    test "#{protocol} #{mode} #{inspect(method)} sends body and auth through public fetch" do
      {url, peer} = start_peer(unquote(protocol), self(), unquote(token), 200)
      response = fetch(url, unquote(protocol), unquote(mode), unquote(method))
      assert %HTTP.Response{status: 200} = response
      assert HTTP.Response.read_all(response) == "ok"
      assert_receive {:peer_complete, ^peer}, 5_000
      send(peer, :close)
    end
  end

  for protocol <- [:http1, :h2c] do
    test "#{protocol} does not replay a DAV request after the peer closes after upload" do
      parent = self()

      {:ok, listener} =
        :gen_tcp.listen(0, [:binary, packet: :raw, active: false, ip: {127, 0, 0, 1}])

      {:ok, port} = :inet.port(listener)

      peer =
        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 5_000)

          if unquote(protocol) == :http1 do
            :ok = :inet.setopts(socket, packet: :line)
            assert {:ok, "REPORT /dav HTTP/1.1\r\n"} = :gen_tcp.recv(socket, 0, 5_000)
            read_headers(socket, [])
            :ok = :inet.setopts(socket, packet: :raw)
            assert {:ok, @body} = :gen_tcp.recv(socket, byte_size(@body), 5_000)
          else
            assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)
            :ok = :gen_tcp.send(socket, Peer.frame(4, 0, 0, <<>>))
            {id, headers} = request_headers(socket)
            assert {":method", "REPORT"} in headers
            assert Peer.body(socket, id) == @body
          end

          :gen_tcp.close(socket)
          {:ok, next_socket} = :gen_tcp.accept(listener, 5_000)

          if unquote(protocol) == :http1 do
            :ok = :inet.setopts(next_socket, packet: :line)
            assert {:ok, "GET /dav HTTP/1.1\r\n"} = :gen_tcp.recv(next_socket, 0, 5_000)
            read_headers(next_socket, [])
            :ok = :gen_tcp.send(next_socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
          else
            assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} =
                     :gen_tcp.recv(next_socket, 24, 5_000)

            :ok = :gen_tcp.send(next_socket, Peer.frame(4, 0, 0, <<>>))
            {id, headers} = request_headers(next_socket)
            assert {":method", "GET"} in headers
            :ok = Peer.response(next_socket, id, "ok")
          end

          :gen_tcp.close(next_socket)
          send(parent, {:no_replay, self()})
        end)

      on_exit(fn ->
        if Process.alive?(peer), do: Process.exit(peer, :kill)
        :gen_tcp.close(listener)
      end)

      url = "http://127.0.0.1:#{port}/dav"

      promise =
        HTTP.fetch(url,
          method: :report,
          http_version: unquote(protocol),
          http2_reuse: unquote(protocol) != :h2c,
          redirect: :manual,
          body: @body,
          timeout: 5_000
        )

      completion = HTTP.Promise.completion(promise)
      assert {:error, _reason} = HTTP.Promise.await(promise, 5_000)
      assert :ok = HTTP.RequestCompletion.await(completion, 5_000)
      assert %HTTP.Response{status: 200} = response = fetch(url, unquote(protocol), :fetch, :get)
      assert HTTP.Response.read_all(response) == "ok"

      assert_receive {:no_replay, ^peer}, 5_000
    end
  end

  for protocol <- [:http1, :h2c], method <- [:propfind, :report] do
    test "#{protocol} #{method} returns manual redirect without replaying the entity" do
      {url, peer} =
        start_peer(
          unquote(protocol),
          self(),
          unquote(method |> to_string() |> String.upcase()),
          302
        )

      response = fetch(url, unquote(protocol), :fetch, unquote(method))
      assert %HTTP.Response{status: 302} = response
      assert HTTP.Headers.get(response.headers, "location") == "/must-not-follow"
      assert HTTP.Response.read_all(response) == "ok"
      assert_receive {:peer_complete, ^peer}, 5_000
      send(peer, :close)
    end
  end

  test "malformed methods reject in the public API before opening a socket" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    for protocol <- [:http1, :h2c], method <- ["BAD\r\nMETHOD", "BAD METHOD", <<255>>, "ß"] do
      assert_raise ArgumentError, ~r/unsupported HTTP method/, fn ->
        HTTP.fetch("http://127.0.0.1:#{port}/dav", method: method, http_version: protocol)
      end
    end

    assert {:error, :timeout} = :gen_tcp.accept(listener, 100)
  end

  defp fetch(url, protocol, mode, method) do
    fetch_promise(url, protocol, mode, method) |> HTTP.Promise.await(5_000)
  end

  defp fetch_promise(url, protocol, mode, method) do
    HTTP.fetch(url,
      method: method,
      request_mode: mode,
      http_version: protocol,
      redirect: :manual,
      headers: [{"authorization", @authorization}, {"depth", "1"}],
      content_type: "application/xml",
      body: @body,
      telemetry: false,
      timeout: 5_000
    )
  end

  defp start_peer(:http1, parent, token, status) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :line, active: false, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        assert {:ok, line} = :gen_tcp.recv(socket, 0, 5_000)
        assert line == token <> " /dav HTTP/1.1\r\n"
        headers = read_headers(socket, [])
        assert {"authorization", @authorization} in headers
        assert {"depth", "1"} in headers
        assert {"content-type", "application/xml"} in headers
        assert {"content-length", to_string(byte_size(@body))} in headers
        :ok = :inet.setopts(socket, packet: :raw)
        assert {:ok, @body} = :gen_tcp.recv(socket, byte_size(@body), 5_000)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 #{status} Fixture\r\nLocation: /must-not-follow\r\nContent-Length: 2\r\n\r\nok"
          )

        send(parent, {:peer_complete, self()})
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      if Process.alive?(peer), do: Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {"http://127.0.0.1:#{port}/dav", peer}
  end

  defp start_peer(:h2c, parent, token, status) do
    Peer.start(parent, fn socket ->
      {id, headers} = request_headers(socket)
      assert {":method", token} in headers
      assert {"authorization", @authorization} in headers
      assert {"depth", "1"} in headers
      assert {"content-type", "application/xml"} in headers
      assert {"content-length", to_string(byte_size(@body))} in headers
      assert Peer.body(socket, id) == @body

      block =
        HPACK.encode_headers([
          {":status", to_string(status)},
          {"location", "/must-not-follow"}
        ])
        |> IO.iodata_to_binary()

      :ok = :gen_tcp.send(socket, [Peer.frame(1, 4, id, block), Peer.frame(0, 1, id, "ok")])
    end)
  end

  defp request_headers(socket) do
    case Peer.recv(socket) do
      {1, flags, id, block} ->
        assert Bitwise.band(flags, 4) == 4
        {:ok, _, headers} = HPACK.decode(HPACK.new_decoder(), block)
        {id, headers}

      _ ->
        request_headers(socket)
    end
  end

  defp read_headers(socket, headers) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, "\r\n"} ->
        headers

      {:ok, line} ->
        [name, value] = String.split(String.trim_trailing(line, "\r\n"), ":", parts: 2)
        read_headers(socket, [{String.downcase(name), String.trim(value)} | headers])
    end
  end
end
