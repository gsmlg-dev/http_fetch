defmodule HTTP.HTTP2RequestLengthTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.HPACK
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  for method <- [:put, :get, :delete], bytes <- ["", "abcdef", :binary.copy("u", 131_072)] do
    test "preserves Content-Length for a #{byte_size(bytes)} byte streaming HTTP/2 #{method} upload" do
      bytes = unquote(bytes)

      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, headers, _decoder} = request_headers(socket, HPACK.new_decoder())
          assert {":method", unquote(String.upcase(to_string(method)))} in headers
          assert {"content-length", to_string(byte_size(bytes))} in headers
          refute Enum.any?(headers, fn {name, _} -> name == "transfer-encoding" end)
          assert Peer.body(socket, id) == bytes
          Peer.response(socket, id, "ok")
        end)

      chunks =
        Stream.unfold(bytes, fn
          "" ->
            nil

          remaining ->
            size = min(byte_size(remaining), 16_384)
            <<chunk::binary-size(^size), rest::binary>> = remaining
            {chunk, rest}
        end)

      {:ok, stream} = HTTP.Stream.from_enumerable(chunks)

      response =
        fetch(url,
          method: unquote(method),
          request_mode: :proxy,
          body: stream,
          duplex: "half",
          headers: [{"content-length", to_string(byte_size(bytes))}]
        )

      assert HTTP.Response.read_all(response) == "ok"
      assert_receive {:peer_complete, ^peer}, 5_000
      send(peer, :close)
    end
  end

  for chunks <- [["abc"], ["abc", "def"], ["abcdef"]] do
    test "HTTP/2 length mismatch for #{inspect(chunks)} resets only the upload" do
      expected = if unquote(chunks) == ["abcdef"], do: "", else: "abc"

      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, headers, decoder} = request_headers(socket, HPACK.new_decoder())
          assert {"content-length", "4"} in headers
          assert reset_body(socket, id, "") == expected
          {next_id, _headers, _decoder} = request_headers(socket, decoder)
          assert next_id > id
          Peer.response(socket, next_id, "still usable")
        end)

      {:ok, stream} = HTTP.Stream.from_enumerable(unquote(chunks))

      assert {:error, {:body_error, :content_length_mismatch}} =
               fetch(url,
                 method: :put,
                 body: stream,
                 duplex: :half,
                 headers: [{"content-length", "4"}]
               )

      assert %HTTP.Response{} = response = fetch(url)
      assert HTTP.Response.read_all(response) == "still usable"
      assert_receive {:peer_complete, ^peer}, 5_000
      send(peer, :close)
    end
  end

  defp fetch(url, opts \\ []) do
    HTTP.fetch(url, Keyword.merge([http_version: :h2c, timeout: 5_000], opts))
    |> HTTP.Promise.await()
  end

  defp request_headers(socket, decoder) do
    case Peer.recv(socket) do
      {1, flags, id, block} ->
        assert Bitwise.band(flags, 4) == 4
        {:ok, decoder, headers} = HPACK.decode(decoder, block)
        {id, headers, decoder}

      _ ->
        request_headers(socket, decoder)
    end
  end

  defp reset_body(socket, id, body) do
    case Peer.recv(socket) do
      {0, flags, ^id, bytes} ->
        assert Bitwise.band(flags, 1) == 0
        reset_body(socket, id, body <> bytes)

      {3, 0, ^id, <<8::32>>} ->
        body

      _ ->
        reset_body(socket, id, body)
    end
  end
end
