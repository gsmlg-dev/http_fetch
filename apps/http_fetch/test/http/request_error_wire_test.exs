defmodule HTTP.RequestErrorWireTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "a saturated first pin times out before establishment and permits a successful second pin" do
    {:ok, blocked} = :gen_tcp.listen(0, [:binary, active: false, backlog: 0, ip: {127, 0, 0, 2}])
    {:ok, {_, port}} = :inet.sockname(blocked)
    {:ok, queued} = :gen_tcp.connect({127, 0, 0, 2}, port, [:binary, active: false], 500)
    {:ok, available} = :gen_tcp.listen(port, [:binary, active: false, ip: {127, 0, 0, 1}])

    on_exit(fn ->
      :gen_tcp.close(queued)
      :gen_tcp.close(blocked)
      :gen_tcp.close(available)
    end)

    deadline = System.monotonic_time(:millisecond) + 3_000

    opts = [
      method: :post,
      body: "once",
      redirect: :manual,
      error_mode: :structured,
      connect_timeout: 100,
      telemetry: false
    ]

    url = "http://pinned.invalid:#{port}/mutation"

    assert {:error,
            %{
              __struct__: HTTP.RequestError,
              phase: :connect,
              request_started: false,
              reason: :timeout
            } = error} =
             HTTP.fetch(
               url,
               opts ++
                 [
                   connect_address: {127, 0, 0, 2},
                   timeout: max(deadline - System.monotonic_time(:millisecond), 0)
                 ]
             )
             |> HTTP.Promise.await(4_000)

    assert HTTP.RequestError.pre_send?(error)

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(available, 2_000)
        {:ok, bytes} = :gen_tcp.recv(socket, 0, 2_000)
        assert bytes =~ "POST /mutation"

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
          )

        :gen_tcp.close(socket)
      end)

    assert %HTTP.Response{status: 200} =
             HTTP.fetch(
               url,
               opts ++
                 [
                   connect_address: {127, 0, 0, 1},
                   timeout: max(deadline - System.monotonic_time(:millisecond), 0)
                 ]
             )
             |> HTTP.Promise.await(4_000)

    Task.await(peer)
    assert System.monotonic_time(:millisecond) < deadline
  end

  for scheme <- ["http", "https"] do
    test "#{scheme} refusal exposes pre-send evidence and caller can try a second validated pin" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_tcp.close(listener) end)
      {:ok, {_, port}} = :inet.sockname(listener)
      url = "#{unquote(scheme)}://pinned.invalid:#{port}/mutation"

      options = [
        method: :post,
        body: "once",
        redirect: :manual,
        telemetry: false,
        error_mode: :structured,
        tls_backend: :ssl,
        ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")]
      ]

      assert {:error,
              %{
                __struct__: HTTP.RequestError,
                phase: :connect,
                request_started: false,
                reason: :econnrefused
              } = error} =
               HTTP.fetch(url, options ++ [connect_address: {127, 0, 0, 2}])
               |> HTTP.Promise.await(2_000)

      assert HTTP.RequestError.pre_send?(error)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)

      parent = self()

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 2_000)

          {transport, socket} =
            if unquote(scheme) == "https" do
              {:ok, socket} =
                :ssl.handshake(
                  tcp,
                  [
                    certfile: Path.join(@fixtures, "pinned.pem"),
                    keyfile: Path.join(@fixtures, "pinned.key"),
                    active: false,
                    mode: :binary
                  ],
                  2_000
                )

              {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
              send(parent, {:sni, info[:sni_hostname]})
              {:ssl, socket}
            else
              {:gen_tcp, tcp}
            end

          {:ok, head} = transport.recv(socket, 0, 2_000)
          send(parent, {:head, head})

          :ok =
            transport.send(
              socket,
              "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )

          transport.close(socket)
        end)

      assert %HTTP.Response{status: 200} =
               HTTP.fetch(url, options ++ [connect_address: {127, 0, 0, 1}])
               |> HTTP.Promise.await(2_000)

      assert_receive {:head, head}
      assert head =~ "Host: pinned.invalid:#{port}\r\n"
      assert head =~ "POST /mutation HTTP/1.1"
      if unquote(scheme) == "https", do: assert_receive({:sni, ~c"pinned.invalid"})
      Task.await(peer)
    end
  end

  for terminal <- [:close, :deadline, :source_error] do
    test "#{terminal} after request bytes never gives pre-send evidence" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_tcp.close(listener) end)
      {:ok, {_, port}} = :inet.sockname(listener)
      parent = self()

      peer =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)
          {:ok, bytes} = :gen_tcp.recv(socket, 0, 2_000)
          send(parent, {:accepted_bytes, bytes})

          if unquote(terminal) == :source_error do
            assert {:ok, entity} = :gen_tcp.recv(socket, 0, 2_000)
            assert entity == "7\r\npartial\r\n"
            send(parent, :partial_entity_received)
          end

          receive do
            :close -> :gen_tcp.close(socket)
            :await_close -> assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
          end
        end)

      {:ok, upload} = HTTP.Stream.start_link(0)

      promise =
        HTTP.fetch("http://pinned.invalid:#{port}/mutation",
          connect_address: {127, 0, 0, 1},
          redirect: :manual,
          method: :post,
          body: upload,
          duplex: "half",
          timeout: 500,
          telemetry: false,
          error_mode: :structured
        )

      assert_receive {:accepted_bytes, bytes}, 2_000
      assert bytes =~ "POST /mutation"

      case unquote(terminal) do
        :close ->
          send(peer.pid, :close)

        :deadline ->
          send(peer.pid, :await_close)

        :source_error ->
          assert :ok = HTTP.Stream.chunk(upload, "partial", 2_000)
          assert_receive :partial_entity_received, 2_000
          HTTP.Stream.error(upload, {:connect_failure, make_ref(), :econnrefused})
          send(peer.pid, :await_close)
      end

      assert {:error, %{__struct__: HTTP.RequestError, request_started: :unknown} = error} =
               HTTP.Promise.await(promise, 2_000)

      refute HTTP.RequestError.pre_send?(error)
      Task.await(peer)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    end
  end

  test "TLS establishment abort is ambiguous and the raw default remains compatible" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    assert {:error, :econnrefused} =
             HTTP.fetch("http://127.0.0.2:#{port}/") |> HTTP.Promise.await(2_000)

    controller = HTTP.AbortController.new()
    on_exit(fn -> if Process.alive?(controller), do: Agent.stop(controller) end)

    promise =
      HTTP.fetch("https://pinned.invalid:#{port}/",
        connect_address: {127, 0, 0, 1},
        redirect: :manual,
        signal: controller,
        error_mode: :structured,
        timeout: 2_000
      )

    {:ok, socket} = :gen_tcp.accept(listener, 2_000)
    assert {:ok, _client_hello} = :gen_tcp.recv(socket, 0, 2_000)
    HTTP.AbortController.abort(controller)

    assert {:error, %{__struct__: HTTP.RequestError, reason: :aborted} = error} =
             HTTP.Promise.await(promise, 2_000)

    refute HTTP.RequestError.pre_send?(error)
    :gen_tcp.close(socket)
  end

  test "cancellation and an expired total deadline do not grant permission for another pin" do
    controller = HTTP.AbortController.new()
    HTTP.AbortController.abort(controller)

    for options <- [[signal: controller], [timeout: 0]] do
      assert {:error, %{__struct__: HTTP.RequestError} = error} =
               HTTP.fetch(
                 "http://pinned.invalid:1/",
                 options ++
                   [
                     connect_address: {127, 0, 0, 1},
                     redirect: :manual,
                     error_mode: :structured,
                     telemetry: false
                   ]
               )
               |> HTTP.Promise.await(2_000)

      refute HTTP.RequestError.pre_send?(error)
    end
  end

  test "a failed redirected connection cannot make the earlier mutation replay-safe" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        {:ok, bytes} = :gen_tcp.recv(socket, 0, 2_000)
        assert bytes =~ "POST /mutation"

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.2:#{port}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
          )

        :gen_tcp.close(socket)
      end)

    assert {:error, %{__struct__: HTTP.RequestError} = error} =
             HTTP.fetch("http://127.0.0.1:#{port}/mutation",
               method: :post,
               body: "once",
               error_mode: :structured,
               telemetry: false
             )
             |> HTTP.Promise.await(2_000)

    refute HTTP.RequestError.pre_send?(error)
    Task.await(peer)
  end
end
