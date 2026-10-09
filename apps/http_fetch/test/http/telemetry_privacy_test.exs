defmodule HTTP.TelemetryPrivacyTest do
  use ExUnit.Case, async: false

  alias HTTP.HTTP2.HPACK
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  @events [
    [:http_fetch, :request, :start],
    [:http_fetch, :request, :stop],
    [:http_fetch, :request, :exception],
    [:http_fetch, :response, :body_read_start],
    [:http_fetch, :response, :body_read_stop],
    [:http_fetch, :streaming, :start],
    [:http_fetch, :streaming, :chunk],
    [:http_fetch, :streaming, :stop],
    [:http_fetch, :http2, :body_bridge],
    [:http_fetch, :http2, :connection],
    [:http_fetch, :http2, :pool],
    [:http_fetch, :http2, :runtime],
    [:http_runtime, :stream, :start]
  ]
  @headers [
    {"authorization", "Bearer sentinel-token"},
    {"proxy-authorization", "Basic sentinel-proxy"},
    {"cookie", "sentinel-cookie"},
    {"x-custom-signature", "sentinel-signature"}
  ]

  setup context do
    handler = {__MODULE__, make_ref()}
    capture = %{owner: self(), caller_only?: context[:caller_telemetry] == true}
    :ok = :telemetry.attach_many(handler, @events, &__MODULE__.capture/4, capture)
    on_exit(fn -> :telemetry.detach(handler) end)
    :ok
  end

  def capture(event, measurements, metadata, %{owner: owner, caller_only?: caller_only?}) do
    if not caller_only? or self() == owner,
      do: send(owner, {:event, event, measurements, metadata})
  end

  for protocol <- [:http1, :h2c], mode <- [:buffered, :streamed, :exception] do
    test "real #{protocol} #{mode} traffic keeps telemetry secret-safe" do
      {url, peer} = peer(unquote(protocol), unquote(mode))
      on_exit(fn -> if Process.alive?(peer), do: send(peer, :close) end)

      result =
        HTTP.fetch(secret_url(url),
          headers: @headers,
          http_version: unquote(protocol),
          timeout: 5_000
        )
        |> HTTP.Promise.await()

      assert_receive {:wire_headers, fields}
      assert inspect(fields) =~ "sentinel-token"
      assert inspect(fields) =~ "sentinel-signature"
      assert inspect(fields) =~ "sentinel-path"

      if unquote(mode) == :exception do
        assert {:error, _} = result
        assert_receive {:event, [:http_fetch, :request, :exception], _, metadata}
        assert metadata == %{scheme: :http, error: :request_failed}
      else
        assert HTTP.Headers.get(result.headers, "set-cookie") == "sentinel-response-cookie"
        assert HTTP.Response.read_all(result) == "OK"
        assert_receive {:event, [:http_fetch, :request, :stop], _, metadata}

        assert metadata == %{
                 scheme: :http,
                 status: 200,
                 http_version: if(unquote(protocol) == :h2c, do: :http2, else: :http1)
               }
      end

      assert_receive {:event, [:http_fetch, :request, :start], _, metadata}
      assert metadata == %{scheme: :http, method: :get}

      for {_event, measurements, metadata} <- collected_events() do
        refute inspect({measurements, metadata}) =~ "sentinel"
      end
    end
  end

  for protocol <- [:http1, :h2c], mode <- [:buffered, :streamed, :exception] do
    test "real #{protocol} #{mode} per-request opt-out suppresses request and body events" do
      {url, peer} = peer(unquote(protocol), unquote(mode))
      on_exit(fn -> if Process.alive?(peer), do: send(peer, :close) end)

      result =
        HTTP.fetch(secret_url(url),
          headers: @headers,
          http_version: unquote(protocol),
          telemetry: false,
          timeout: 5_000
        )
        |> HTTP.Promise.await()

      assert_receive {:wire_headers, _}

      if unquote(mode) == :exception,
        do: assert(match?({:error, _}, result)),
        else: assert(HTTP.Response.read_all(result) == "OK")

      refute_receive {:event, [:http_fetch, :request, _], _, _}
      refute_receive {:event, [:http_fetch, :streaming, _], _, _}
      refute_receive {:event, [:http_fetch, :response, _], _, _}
      refute_receive {:event, [:http_fetch, :http2, :body_bridge], _, _}

      for {_event, measurements, metadata} <- collected_events() do
        refute inspect({measurements, metadata}) =~ "sentinel"
      end
    end
  end

  for upload <- [:binary, :producer] do
    test "H2 disabled #{upload} upload suppresses internal stream and bridge events" do
      body = :binary.copy("upload", 4_096)

      source =
        if unquote(upload) == :binary do
          body
        else
          {:ok, stream} = HTTP.Stream.from_enumerable([body], telemetry: false)
          stream
        end

      {url, peer} = peer(:h2c, :upload)
      on_exit(fn -> if Process.alive?(peer), do: send(peer, :close) end)

      response =
        HTTP.fetch(url,
          http_version: :h2c,
          method: :post,
          body: source,
          duplex: if(is_pid(source), do: :half),
          headers: [{"content-length", to_string(byte_size(body))}],
          telemetry: false,
          timeout: 5_000
        )
        |> HTTP.Promise.await()

      assert_receive {:uploaded, ^body}
      assert HTTP.Response.read_all(response) == "OK"
      refute_receive {:event, [:http_fetch, :request, _], _, _}
      refute_receive {:event, [:http_fetch, :streaming, _], _, _}
      refute_receive {:event, [:http_fetch, :http2, :body_bridge], _, _}
    end
  end

  test "global Fetch opt-out suppresses helpers and actual shared H2 counters" do
    disable(:http_fetch)

    HTTP.Telemetry.request_start(
      "GET",
      URI.parse("https://sentinel.test"),
      HTTP.Headers.new(@headers)
    )

    HTTP.Telemetry.response_body_read_start(1)
    HTTP.Runtime.Telemetry.stream(:fetch, :start, :http2, :ok)
    {url, peer} = peer(:h2c, :streamed)
    on_exit(fn -> if Process.alive?(peer), do: send(peer, :close) end)
    result = HTTP.fetch(url, http_version: :h2c) |> HTTP.Promise.await()
    assert_receive {:wire_headers, _}
    assert HTTP.Response.read_all(result) == "OK"
    refute_receive {:event, _, _, _}
  end

  @tag :caller_telemetry
  test "runtime global opt-out covers both shared event prefixes" do
    disable(:http_runtime)
    HTTP.Runtime.Telemetry.http2_pool(:reserve, :ok, %{reservations: 1})
    HTTP.Runtime.Telemetry.http2_connection(:admit, :active, %{active_streams: 1})
    HTTP.Runtime.Telemetry.http2_runtime(:peer_reset, :received, %{error_code: 8})
    HTTP.Runtime.Telemetry.stream(:fetch, :start, :http2, :ok)
    refute_receive {:event, _, _, _}
  end

  @tag :caller_telemetry
  test "helper telemetry assertions isolate emissions from other processes" do
    task =
      Task.async(fn ->
        HTTP.Runtime.Telemetry.http2_connection(:closed, :closed, %{active_streams: 0})
      end)

    Task.await(task)
    HTTP.Runtime.Telemetry.http2_connection(:admit, :active, %{active_streams: 1})

    assert_receive {:event, [:http_fetch, :http2, :connection], %{active_streams: 1},
                    %{event: :admit}}

    refute_receive {:event, _, _, _}, 0
  end

  defp disable(app) do
    original = Application.fetch_env(app, :telemetry)
    Application.put_env(app, :telemetry, false)

    on_exit(fn ->
      case original do
        {:ok, value} -> Application.put_env(app, :telemetry, value)
        :error -> Application.delete_env(app, :telemetry)
      end
    end)
  end

  defp collected_events(acc \\ []) do
    receive do
      {:event, event, measurements, metadata} ->
        collected_events([{event, measurements, metadata} | acc])
    after
      0 -> acc
    end
  end

  defp secret_url(url),
    do:
      String.replace(url, "http://", "http://sentinel-user:sentinel-password@") <>
        "/sentinel-path?secret=sentinel-query#sentinel-fragment"

  defp peer(:h2c, mode) do
    parent = self()

    Peer.start(parent, fn socket ->
      {id, fields} = request_headers(socket)
      send(parent, {:wire_headers, fields})
      if mode == :upload, do: send(parent, {:uploaded, Peer.body(socket, id)})

      if mode == :exception do
        :ok = :gen_tcp.send(socket, Peer.frame(3, 0, id, <<8::32>>))
      else
        fields = [{":status", "200"}, {"set-cookie", "sentinel-response-cookie"}]
        fields = if mode == :buffered, do: fields ++ [{"content-length", "2"}], else: fields

        :ok =
          :gen_tcp.send(socket, [
            Peer.frame(1, 4, id, IO.iodata_to_binary(HPACK.encode_headers(fields))),
            Peer.frame(0, 1, id, "OK")
          ])
      end
    end)
  end

  defp peer(:http1, mode) do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, request} = :gen_tcp.recv(socket, 0, 5_000)
        send(parent, {:wire_headers, request})

        case mode do
          :exception ->
            :ok = :gen_tcp.send(socket, "not an HTTP response\r\n\r\n")

          :buffered ->
            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: sentinel-response-cookie\r\n\r\nOK"
              )

          :streamed ->
            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: sentinel-response-cookie\r\n\r\n2\r\nOK\r\n0\r\n\r\n"
              )
        end

        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    :ok = :gen_tcp.controlling_process(listener, peer)
    {"http://localhost:#{port}/", peer}
  end

  defp request_headers(socket) do
    case Peer.recv(socket) do
      {1, _, id, bytes} ->
        {:ok, _, fields} = HPACK.decode(HPACK.new_decoder(), bytes)
        {id, fields}

      _ ->
        request_headers(socket)
    end
  end
end
