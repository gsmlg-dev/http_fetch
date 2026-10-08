defmodule HTTP.ContentEncodingTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.HPACK
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @json ~s({"message":"decoded"})

  for protocol <- [:http1, :h2c], streaming? <- [false, true], encoding <- ["gzip", "deflate"] do
    test "#{protocol} #{encoding} streaming=#{streaming?} exposes decoded bytes to all consumers" do
      protocol = unquote(protocol)
      streaming? = unquote(streaming?)
      encoding = unquote(encoding)
      encoded = encode(@json, encoding)
      headers = [{"content-encoding", encoding}, {"content-type", "application/json"}]

      for consumer <- [:body, :text, :json, :array_buffer, :blob, :clone, :write_to] do
        response = fetch(protocol, encoded, headers, streaming?)
        assert HTTP.Headers.get(response.headers, "content-encoding") == encoding

        if streaming? do
          assert is_pid(response.body)
        else
          assert response.body == @json

          assert HTTP.Headers.get(response.headers, "content-length") ==
                   to_string(byte_size(encoded))
        end

        case consumer do
          :body ->
            assert HTTP.Response.read_all(response) == @json

          :text ->
            assert HTTP.Response.text(response) == @json

          :json ->
            assert HTTP.Response.json(response) == {:ok, %{"message" => "decoded"}}

          :array_buffer ->
            assert HTTP.Response.array_buffer(response) == @json

          :blob ->
            assert HTTP.Response.blob(response).data == @json

          :clone ->
            assert response |> HTTP.Response.clone() |> HTTP.Response.read_all() == @json

          :write_to ->
            path =
              Path.join(
                System.tmp_dir!(),
                "content-encoding-#{System.unique_integer([:positive])}"
              )

            on_exit(fn -> File.rm(path) end)
            assert HTTP.Response.write_to(response, path) == :ok
            assert File.read!(path) == @json
        end
      end
    end
  end

  for streaming? <- [false, true] do
    test "gzip archive bytes without Content-Encoding remain untouched, streaming=#{streaming?}" do
      archive = :zlib.gzip(@json)

      response =
        fetch(
          :http1,
          archive,
          [{"content-type", "application/octet-stream"}],
          unquote(streaming?)
        )

      assert HTTP.Response.read_all(response) == archive
    end

    test "unknown encoding chains pass through entirely, streaming=#{streaming?}" do
      encoded = :zlib.gzip(@json)
      response = fetch(:http1, encoded, [{"content-encoding", "br, gzip"}], unquote(streaming?))
      assert HTTP.Response.read_all(response) == encoded
    end

    test "known repeated encoding fields decode in reverse, streaming=#{streaming?}" do
      encoded = @json |> :zlib.gzip() |> :zlib.compress()

      response =
        fetch(
          :http1,
          encoded,
          [{"content-encoding", "GZip"}, {"content-encoding", "identity, deflate"}],
          unquote(streaming?)
        )

      assert HTTP.Response.read_all(response) == @json
    end

    test "concatenated gzip members decode completely, streaming=#{streaming?}" do
      encoded = :zlib.gzip("one") <> :zlib.gzip("two")
      response = fetch(:http1, encoded, [{"content-encoding", "gzip"}], unquote(streaming?))
      assert HTTP.Response.read_all(response) == "onetwo"
    end
  end

  for encoding <- ["gzip", "deflate"], malformed <- [:invalid, :truncated] do
    test "buffered #{encoding} #{malformed} returns a decoding error" do
      encoded = malformed(unquote(encoding), unquote(malformed))

      assert fetch(:http1, encoded, [{"content-encoding", unquote(encoding)}], false) ==
               {:error, {:invalid_content_encoding, unquote(encoding)}}
    end

    test "streamed #{encoding} #{malformed} fails consumption" do
      encoded = malformed(unquote(encoding), unquote(malformed))
      response = fetch(:http1, encoded, [{"content-encoding", unquote(encoding)}], true)

      assert_raise RuntimeError, ~r/invalid_content_encoding/, fn ->
        HTTP.Response.text(response)
      end
    end
  end

  test "HEAD retains encoding metadata without trying to decode a forbidden body" do
    response =
      fetch(:http1, :zlib.gzip(@json), [{"content-encoding", "gzip"}], false, method: :head)

    assert response.body == ""
    assert HTTP.Headers.get(response.headers, "content-encoding") == "gzip"
  end

  defp encode(body, "gzip"), do: :zlib.gzip(body)
  defp encode(body, "deflate"), do: :zlib.compress(body)
  defp malformed(_encoding, :invalid), do: "invalid"

  defp malformed(encoding, :truncated) do
    encoded = encode(@json, encoding)
    binary_part(encoded, 0, byte_size(encoded) - 2)
  end

  defp fetch(protocol, body, headers, streaming?, opts \\ []) do
    headers =
      if streaming?, do: headers, else: [{"content-length", to_string(byte_size(body))} | headers]

    {url, peer} = server(protocol, body, headers, streaming?)
    on_exit(fn -> if Process.alive?(peer), do: send(peer, :close) end)

    HTTP.fetch(url, Keyword.merge([http_version: protocol, timeout: 5_000], opts))
    |> HTTP.Promise.await()
  end

  defp server(:h2c, body, headers, _streaming?) do
    Peer.start(self(), fn socket ->
      {id, true} = Peer.request(socket)
      fields = HPACK.encode_headers([{":status", "200"} | headers]) |> IO.iodata_to_binary()
      :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, fields))
      for <<byte <- body>>, do: :ok = :gen_tcp.send(socket, Peer.frame(0, 0, id, <<byte>>))
      :ok = :gen_tcp.send(socket, Peer.frame(0, 1, id, ""))
    end)
  end

  defp server(:http1, body, headers, streaming?) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, _request} = :gen_tcp.recv(socket, 0, 5_000)
        headers = if streaming?, do: [{"transfer-encoding", "chunked"} | headers], else: headers

        wire_body =
          if streaming? do
            [for(<<byte <- body>>, do: ["1\r\n", <<byte>>, "\r\n"]), "0\r\n\r\n"]
          else
            body
          end

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 200 OK\r\n",
            Enum.map(headers, fn {key, value} -> [key, ": ", value, "\r\n"] end),
            "\r\n",
            wire_body
          ])

        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    :ok = :gen_tcp.controlling_process(listener, peer)
    {"http://localhost:#{port}/encoded", peer}
  end
end
