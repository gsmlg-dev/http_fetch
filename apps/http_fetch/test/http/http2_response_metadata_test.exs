defmodule HTTP.HTTP2ResponseMetadataTest do
  use ExUnit.Case, async: true

  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer
  alias HTTP.HTTP2.HPACK

  defp fetch(url, opts \\ []) do
    HTTP.fetch(url, Keyword.merge([http_version: :h2c, timeout: 5_000], opts))
    |> HTTP.Promise.await()
  end

  defp fields(headers), do: headers |> HPACK.encode_headers() |> IO.iodata_to_binary()

  defp headers(id, status, headers \\ [], flags \\ 4),
    do: Peer.frame(1, flags, id, fields([{":status", to_string(status)} | headers]))

  defp complete(peer) do
    assert_receive {:peer_complete, ^peer}, 5_000
    send(peer, :close)
  end

  test "retains multiple ordered 103 blocks and duplicate fields separately from final headers" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            headers(id, 103, [{"link", "first"}, {"link", "second"}]),
            headers(id, 103, [{"link", "third"}]),
            headers(id, 200, [{"content-length", "0"}], 5)
          ])
      end)

    response = fetch(url)
    assert [{103, first}, {103, second}] = response.informational
    assert HTTP.Headers.get_all(first, "link") == ["first", "second"]
    assert HTTP.Headers.get(second, "link") == "third"
    assert HTTP.Headers.get(response.headers, "link") == nil
    assert response.body == ""
    complete(peer)
  end

  for body <- ["body", ""] do
    test "buffered #{inspect(body)} body exposes separate duplicate trailers" do
      body = unquote(body)

      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, true} = Peer.request(socket)

          :ok =
            :gen_tcp.send(socket, [
              headers(id, 200, [{"content-length", to_string(byte_size(body))}]),
              Peer.frame(0, 0, id, body),
              Peer.frame(1, 5, id, fields([{"x-checksum", "first"}, {"x-checksum", "second"}]))
            ])
        end)

      response = fetch(url)
      assert response.body == body
      assert HTTP.Headers.get_all(response.trailers, "x-checksum") == ["first", "second"]
      assert HTTP.Headers.get(response.headers, "x-checksum") == nil
      complete(peer)
    end
  end

  test "stream trailers wait for final DATA delivery acknowledgement and precede end" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            headers(id, 200),
            Peer.frame(0, 0, id, "body"),
            Peer.frame(1, 5, id, fields([{"x-checksum", "verified"}]))
          ])
      end)

    response = fetch(url)
    stream = response.stream
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "body", ack}, 5_000
    refute_receive {:stream_trailers, ^stream, _}, 50
    refute_receive {:stream_end, ^stream}, 50
    send(stream, {:stream_chunk_ack, ack})
    assert_receive {:stream_trailers, ^stream, trailers}, 5_000
    assert HTTP.Headers.get(trailers, "x-checksum") == "verified"
    assert_receive {:stream_end, ^stream}, 5_000
    complete(peer)
  end

  test "129 informational blocks fail the finite retention count" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [List.duplicate(headers(id, 103), 129), headers(id, 200, [], 5)])
      end)

    assert fetch(url) == {:error, :http2_informational_limit}
    complete(peer)
  end

  defp split_headers(id, headers, end_stream? \\ false) do
    payload = fields(headers)
    <<first::binary-size(7), rest::binary>> = payload
    [Peer.frame(1, if(end_stream?, do: 1, else: 0), id, first), Peer.frame(9, 4, id, rest)]
  end

  defp fragmented_headers(id, headers, end_stream? \\ false) do
    payload = fields(headers)
    chunks = for <<part::binary-size(16_384) <- payload>>, do: part
    used = length(chunks) * 16_384
    rest = binary_part(payload, used, byte_size(payload) - used)
    chunks = if rest == "", do: chunks, else: chunks ++ [rest]
    last = length(chunks) - 1

    Enum.with_index(chunks, fn part, index ->
      Peer.frame(
        if(index == 0, do: 1, else: 9),
        if(index == last, do: 4, else: 0) + if(index == 0 and end_stream?, do: 1, else: 0),
        id,
        part
      )
    end)
  end

  test "split informational and trailer HEADERS/CONTINUATION preserve full blocks" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            split_headers(id, [{":status", "103"}, {"link", "complete-info"}]),
            headers(id, 200, [{"content-length", "0"}]),
            split_headers(id, [{"x-checksum", "complete-trailer"}], true)
          ])
      end)

    response = fetch(url)
    assert [{103, info}] = response.informational
    assert HTTP.Headers.get(info, "link") == "complete-info"
    assert HTTP.Headers.get(response.trailers, "x-checksum") == "complete-trailer"
    complete(peer)
  end

  test "informational aggregate bytes are bounded across individually valid blocks" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        block = [{":status", "103"}, {"link", :binary.copy("x", 33_000)}]

        :ok =
          :gen_tcp.send(socket, [
            fragmented_headers(id, block),
            fragmented_headers(id, block),
            headers(id, 200, [], 5)
          ])
      end)

    assert fetch(url) == {:error, :http2_informational_limit}
    complete(peer)
  end

  test "128 empty informational blocks fit the finite count budget" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [List.duplicate(headers(id, 103), 128), headers(id, 200, [], 5)])
      end)

    response = fetch(url)
    assert length(response.informational) == 128
    complete(peer)
  end

  for streamed? <- [false, true] do
    test "oversized retained trailer metadata fails #{if streamed?, do: "stream", else: "promise"}" do
      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, true} = Peer.request(socket)
          initial = if unquote(streamed?), do: [], else: [{"content-length", "0"}]

          :ok =
            :gen_tcp.send(socket, [
              headers(id, 200, initial),
              fragmented_headers(id, [{"x-checksum", :binary.copy("x", 65_510)}], true)
            ])
        end)

      if unquote(streamed?) do
        response = fetch(url)
        stream = response.stream
        send(stream, {:read_chunk, self()})
        assert_receive {:stream_error, ^stream, :http2_trailers_limit}, 5_000
        refute_receive {:stream_end, ^stream}
      else
        assert fetch(url) == {:error, :http2_trailers_limit}
      end

      complete(peer)
    end
  end

  for {trailer_fields, flags, reason} <- [
        {[{":status", "200"}], 5, :invalid_response_trailers},
        {[{"content-length", "0"}], 5, :invalid_response_trailers},
        {[{"x-checksum", "not-terminal"}], 4, :invalid_headers_transition}
      ] do
    test "invalid trailer #{inspect(trailer_fields)} flags #{flags} fails without success" do
      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, true} = Peer.request(socket)

          :ok =
            :gen_tcp.send(socket, [
              headers(id, 200, [{"content-length", "0"}]),
              Peer.frame(1, unquote(flags), id, fields(unquote(Macro.escape(trailer_fields))))
            ])
        end)

      assert fetch(url) == {:error, unquote(reason)}
      complete(peer)
    end
  end

  for kind <- [:binary, :stream] do
    test "informational response does not abandon #{kind} upload waiting on peer credit" do
      parent = self()

      {url, peer} =
        Peer.start(
          self(),
          fn socket ->
            {id, false} = Peer.request(socket)
            :ok = :gen_tcp.send(socket, headers(id, 103, [{"link", "upload-continues"}]))
            send(parent, {:informational_sent, self()})
            receive do: (:grant -> :ok)
            :ok = :gen_tcp.send(socket, Peer.frame(8, 0, id, <<65_535::32>>))
            assert Peer.body(socket, id) == "payload"
            :ok = :gen_tcp.send(socket, headers(id, 200, [], 5))
          end,
          settings: <<4::16, 0::32>>
        )

      body =
        case unquote(kind) do
          :binary ->
            "payload"

          :stream ->
            {:ok, stream} = HTTP.Stream.from_enumerable(["pay", "load"])
            stream
        end

      task = Task.async(fn -> fetch(url, method: :post, body: body, duplex: "half") end)
      assert_receive {:informational_sent, ^peer}, 5_000
      send(peer, :grant)
      response = Task.await(task, 5_000)
      assert response.status == 200
      assert [{103, _}] = response.informational
      complete(peer)
    end
  end

  test "metadata stays isolated across simultaneous streams on the same connection" do
    parent = self()

    {url, peer} =
      Peer.start(self(), fn socket ->
        {first, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [headers(first, 103, [{"link", "first"}]), headers(first, 200)])

        send(parent, {:first_response, self()})
        {second, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            headers(second, 103, [{"link", "second"}]),
            headers(second, 200, [{"content-length", "0"}]),
            Peer.frame(1, 5, second, fields([{"x-checksum", "second"}])),
            Peer.frame(1, 5, first, fields([{"x-checksum", "first"}]))
          ])
      end)

    first = fetch(url)
    assert_receive {:first_response, ^peer}, 5_000
    second = fetch(url)
    assert [{103, first_info}] = first.informational
    assert [{103, second_info}] = second.informational
    assert HTTP.Headers.get(first_info, "link") == "first"
    assert HTTP.Headers.get(second_info, "link") == "second"
    assert HTTP.Headers.get(second.trailers, "x-checksum") == "second"
    stream = first.stream
    send(stream, {:read_chunk, self()})
    assert_receive {:stream_trailers, ^stream, trailers}, 5_000
    assert HTTP.Headers.get(trailers, "x-checksum") == "first"
    assert_receive {:stream_end, ^stream}, 5_000
    complete(peer)
  end

  for terminal <- [:abort, :reset] do
    test "#{terminal} during unacknowledged final delivery cannot publish queued trailers as success" do
      parent = self()
      controller = HTTP.AbortController.new()

      {url, peer} =
        Peer.start(self(), fn socket ->
          {id, true} = Peer.request(socket)
          :ok = :gen_tcp.send(socket, [headers(id, 200), Peer.frame(0, 0, id, "pending")])
          send(parent, {:delivery_sent, self()})
          receive do: (:terminate -> :ok)
          wire = if unquote(terminal) == :reset, do: [Peer.frame(3, 0, id, <<8::32>>)], else: []

          :ok =
            :gen_tcp.send(socket, [wire, Peer.frame(1, 5, id, fields([{"x-checksum", "late"}]))])
        end)

      response = fetch(url, signal: controller)
      stream = response.stream
      send(stream, {:read_chunk, self(), :ack})
      assert_receive {:stream_chunk, ^stream, "pending", _ack}, 5_000
      assert_receive {:delivery_sent, ^peer}, 5_000
      if unquote(terminal) == :abort, do: HTTP.AbortController.abort(controller)
      send(peer, :terminate)
      expected = if unquote(terminal) == :abort, do: :aborted, else: {:stream_reset, :cancel}
      assert_receive {:stream_error, ^stream, ^expected}, 5_000
      refute_receive {:stream_trailers, ^stream, _}
      refute_receive {:stream_end, ^stream}
      complete(peer)
    end
  end

  test "256 trailer fields fit the finite count budget" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        trailers = List.duplicate({"x-checksum", "duplicate"}, 256)

        :ok =
          :gen_tcp.send(socket, [
            headers(id, 200, [{"content-length", "0"}]),
            Peer.frame(1, 5, id, fields(trailers))
          ])
      end)

    response = fetch(url)
    assert length(HTTP.Headers.get_all(response.trailers, "x-checksum")) == 256
    complete(peer)
  end

  test "257 trailer fields preserve the core HPACK field count rejection" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        trailers = List.duplicate({"x-checksum", "duplicate"}, 257)

        :ok =
          :gen_tcp.send(socket, [
            headers(id, 200, [{"content-length", "0"}]),
            Peer.frame(1, 5, id, fields(trailers))
          ])
      end)

    assert fetch(url) == {:error, {:transport_error, {:hpack, :hpack_field_count_exceeded}}}
    complete(peer)
  end

  test "metadata retention preserves connection HPACK state for a reused stream" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {first, true} = Peer.request(socket)

        {encoder, info} =
          HPACK.encode_headers(
            HPACK.new_encoder(),
            [{":status", "103"}, {"link", "indexed-info"}],
            indexing: :incremental
          )

        {encoder, final} =
          HPACK.encode_headers(encoder, [{":status", "200"}, {"content-length", "0"}],
            indexing: :incremental
          )

        {encoder, trailer} =
          HPACK.encode_headers(encoder, [{"x-checksum", "indexed-trailer"}],
            indexing: :incremental
          )

        :ok =
          :gen_tcp.send(socket, [
            Peer.frame(1, 4, first, info),
            Peer.frame(1, 4, first, final),
            Peer.frame(1, 5, first, trailer)
          ])

        {second, true} = Peer.request(socket)

        {encoder, info} =
          HPACK.encode_headers(encoder, [{":status", "103"}, {"link", "indexed-info"}],
            indexing: :incremental
          )

        {encoder, final} =
          HPACK.encode_headers(encoder, [{":status", "200"}, {"content-length", "0"}],
            indexing: :incremental
          )

        {_encoder, trailer} =
          HPACK.encode_headers(encoder, [{"x-checksum", "indexed-trailer"}],
            indexing: :incremental
          )

        :ok =
          :gen_tcp.send(socket, [
            Peer.frame(1, 4, second, info),
            Peer.frame(1, 4, second, final),
            Peer.frame(1, 5, second, trailer)
          ])
      end)

    for _ <- 1..2 do
      response = fetch(url)
      assert [{103, info}] = response.informational
      assert HTTP.Headers.get(info, "link") == "indexed-info"
      assert HTTP.Headers.get(response.trailers, "x-checksum") == "indexed-trailer"
    end

    complete(peer)
  end

  test "EOF after a trailer block drains previously validated final DATA first" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            headers(id, 200),
            Peer.frame(0, 0, id, "last"),
            Peer.frame(1, 5, id, fields([{"x-checksum", "complete"}]))
          ])

        :ok = :gen_tcp.shutdown(socket, :write)
      end)

    response = fetch(url)
    stream = response.stream
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "last", ack}, 5_000
    send(stream, {:stream_chunk_ack, ack})
    assert_receive {:stream_trailers, ^stream, trailers}, 5_000
    assert HTTP.Headers.get(trailers, "x-checksum") == "complete"
    assert_receive {:stream_end, ^stream}, 5_000
    complete(peer)
  end

  test "trailer metadata at exactly 65536 retained bytes completes" do
    value = :binary.copy("x", 65_494)

    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)

        :ok =
          :gen_tcp.send(socket, [
            headers(id, 200, [{"content-length", "0"}]),
            fragmented_headers(id, [{"x-checksum", value}], true)
          ])
      end)

    response = fetch(url)
    assert HTTP.Headers.get(response.trailers, "x-checksum") == value
    complete(peer)
  end
end
