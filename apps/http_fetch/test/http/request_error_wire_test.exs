defmodule HTTP.RequestErrorWireTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @ipv4 {127, 0, 0, 1}
  @ipv6 {0, 0, 0, 0, 0, 0, 0, 1}

  @tag :integration
  test "a saturated first pin times out before establishment and permits a successful second pin" do
    {blocked, available, port} = paired_listeners(10)

    on_exit(fn ->
      :gen_tcp.close(blocked)
      :gen_tcp.close(available)
    end)

    queued = saturate_pin(port)
    refute queued == []
    on_exit(fn -> Enum.each(queued, &:gen_tcp.close/1) end)

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
                   connect_address: @ipv6,
                   timeout: max(deadline - System.monotonic_time(:millisecond), 0)
                 ]
             )
             |> HTTP.Promise.await(4_000)

    assert HTTP.RequestError.pre_send?(error)
    assert {:error, :timeout} = :gen_tcp.accept(available, 0)

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(available, 2_000)
        bytes = receive_mutation(:gen_tcp, socket)
        assert bytes =~ "POST /mutation HTTP/1.1\r\n"
        assert bytes =~ "Host: pinned.invalid:#{port}\r\n"

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
    assert {:error, :timeout} = :gen_tcp.accept(available, 0)
    assert System.monotonic_time(:millisecond) < deadline
  end

  # Reserve both loopback families before opening any client sockets. Backlog
  # zero means the OS default on some kernels; one gives a bounded fill target,
  # whose saturation is still independently proved by native timed-out dials.
  defp paired_listeners(attempts, backlog \\ 1) do
    {:ok, available} = :gen_tcp.listen(0, [:binary, active: false, ip: @ipv4])
    {:ok, {_, port}} = :inet.sockname(available)

    case :gen_tcp.listen(port, [
           :inet6,
           :binary,
           active: false,
           ipv6_v6only: true,
           backlog: backlog,
           ip: @ipv6
         ]) do
      {:ok, blocked} ->
        {blocked, available, port}

      {:error, :eaddrinuse} when attempts > 1 ->
        :gen_tcp.close(available)
        paired_listeners(attempts - 1, backlog)

      {:error, reason} ->
        :gen_tcp.close(available)
        flunk("could not reserve paired listeners: #{inspect(reason)}")
    end
  end

  defp saturate_pin(port, queued \\ [], remaining \\ 32) do
    result = :gen_tcp.connect(@ipv6, port, [:inet6, :binary, active: false], 100)

    case result do
      {:ok, socket} when remaining > 0 ->
        on_exit(fn -> :gen_tcp.close(socket) end)
        saturate_pin(port, [socket | queued], remaining - 1)

      {:error, :timeout} ->
        # A second independent native dial must also time out while all queued
        # connections are retained. A single successful fill is not saturation.
        assert {:error, :timeout} =
                 :gen_tcp.connect(@ipv6, port, [:inet6, :binary, active: false], 100)

        queued

      other ->
        if match?({:ok, _}, other), do: :gen_tcp.close(elem(other, 1))
        flunk("could not establish saturated native IPv6 backlog: #{inspect(other)}")
    end
  end

  for scheme <- ["http", "https"] do
    @tag :integration
    test "#{scheme} refusal exposes pre-send evidence and caller can try a second validated pin" do
      {refused, listener, port} = paired_listeners(10, 16)
      :ok = :gen_tcp.close(refused)
      on_exit(fn -> :gen_tcp.close(listener) end)
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
               HTTP.fetch(url, options ++ [connect_address: @ipv6])
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

          head = receive_mutation(transport, socket)
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
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    end
  end

  for terminal <- [:close, :deadline, :source_error] do
    @tag :integration
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

  @tag :integration
  test "TLS establishment abort is ambiguous and the raw default remains compatible" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ipv4])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    refused_port = refused_ipv4_port()
    refute refused_port == port

    assert {:error, :econnrefused} =
             HTTP.fetch("http://127.0.0.1:#{refused_port}/") |> HTTP.Promise.await(2_000)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)

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

  @tag :integration
  test "a failed redirected connection cannot make the earlier mutation replay-safe" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ipv4])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    refused_port = refused_ipv4_port()
    refute refused_port == port

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        bytes = receive_mutation(:gen_tcp, socket)
        assert bytes =~ "POST /mutation HTTP/1.1\r\n"
        assert bytes =~ "Host: 127.0.0.1:#{port}\r\n"

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:#{refused_port}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
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
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  defp refused_ipv4_port do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ipv4])
    {:ok, {_, port}} = :inet.sockname(listener)
    :ok = :gen_tcp.close(listener)
    port
  end

  defp receive_mutation(transport, socket, buffer \\ <<>>) do
    assert byte_size(buffer) <= 65_536

    case :binary.split(buffer, "\r\n\r\n") do
      [head, body] when byte_size(body) >= 4 ->
        assert body == "once"
        assert Regex.match?(~r/\r\ncontent-length:\s*4\r\n/i, head <> "\r\n")
        buffer

      _ ->
        assert {:ok, bytes} = transport.recv(socket, 0, 2_000)
        receive_mutation(transport, socket, buffer <> bytes)
    end
  end
end
