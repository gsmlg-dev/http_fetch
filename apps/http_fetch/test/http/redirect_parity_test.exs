defmodule HTTP.RedirectParityTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  # WHATWG Fetch: 20 redirects are followed and the 21st is a network error.
  @redirect_limit 20

  describe "HTTP/1.1" do
    test "exceeding the redirect limit returns :too_many_redirects" do
      test_pid = self()

      url =
        start_http1_server!(fn listener ->
          for _ <- 0..@redirect_limit do
            {:ok, socket} = :gen_tcp.accept(listener, 5_000)
            recv_header_block(socket, "")

            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n" <>
                  "Connection: close\r\n\r\n"
              )

            :gen_tcp.close(socket)
            send(test_pid, :redirect_served)
          end

          send(test_pid, {:extra_connection, :gen_tcp.accept(listener, 200)})
        end)

      assert {:error, :too_many_redirects} =
               HTTP.fetch(url, http_version: :http1, timeout: 5_000) |> HTTP.Promise.await()

      for _ <- 0..@redirect_limit, do: assert_receive(:redirect_served, 1_000)
      assert_receive {:extra_connection, {:error, :timeout}}, 1_000
    end

    test "the last permitted redirect is still followed" do
      url =
        start_http1_server!(fn listener ->
          for hop <- 1..(@redirect_limit + 1) do
            {:ok, socket} = :gen_tcp.accept(listener, 5_000)
            recv_header_block(socket, "")

            response =
              if hop <= @redirect_limit,
                do:
                  "HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n" <>
                    "Connection: close\r\n\r\n",
                else: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

            :ok = :gen_tcp.send(socket, response)
            :gen_tcp.close(socket)
          end
        end)

      response = HTTP.fetch(url, http_version: :http1, timeout: 5_000) |> HTTP.Promise.await()
      assert response.status == 200
      assert response.redirected
      assert HTTP.Response.text(response) == "ok"
    end

    for status <- [307, 308] do
      test "#{status} on a streamed upload returns :streaming_body_redirect_not_replayable" do
        test_pid = self()

        url =
          start_http1_server!(fn listener ->
            {:ok, socket} = :gen_tcp.accept(listener, 5_000)
            recv_header_block(socket, "")

            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 #{unquote(status)} Redirect\r\nLocation: /again\r\n" <>
                  "Content-Length: 0\r\n\r\n"
              )

            assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
            send(test_pid, {:extra_connection, :gen_tcp.accept(listener, 100)})
          end)

        {:ok, upload} = HTTP.Stream.start_link(0)

        assert {:error, :streaming_body_redirect_not_replayable} =
                 HTTP.fetch(url,
                   method: :post,
                   body: upload,
                   duplex: :half,
                   http_version: :http1,
                   timeout: 1_000
                 )
                 |> HTTP.Promise.await()

        assert_receive {:extra_connection, {:error, :timeout}}, 1_000
        refute Process.alive?(upload)
      end
    end
  end

  describe "HTTP/2 parity" do
    test "exceeding the redirect limit returns :too_many_redirects" do
      {url, peer} =
        Peer.start(self(), fn socket ->
          for _ <- 0..@redirect_limit do
            {id, true} = Peer.request(socket)

            :ok =
              :gen_tcp.send(
                socket,
                Peer.frame(1, 5, id, <<0x08, 0x03, "302", 0, 8, "location", 5, "/loop">>)
              )
          end
        end)

      assert {:error, :too_many_redirects} =
               HTTP.fetch(url, http_version: :h2c, http2_profile: :native_v1, timeout: 5_000)
               |> HTTP.Promise.await()

      assert_receive {:peer_complete, ^peer}, 1_000
      send(peer, :close)
    end
  end

  defp start_http1_server!(handler) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    pid =
      spawn_link(fn ->
        handler.(listener)
        :gen_tcp.close(listener)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listener)
    end)

    "http://127.0.0.1:#{port}/loop"
  end

  defp recv_header_block(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 5_000)
      recv_header_block(socket, acc <> data)
    end
  end
end
