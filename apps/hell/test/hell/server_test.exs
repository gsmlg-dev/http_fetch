defmodule Hell.ServerTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  use Machete

  defmodule Echo do
    use Hell.Handler

    @impl Hell.Handler
    def handle_connection(socket, state) do
      {:ok, data} = Hell.Socket.recv(socket, 0)
      Hell.Socket.send(socket, data)
      {:close, state}
    end
  end

  defmodule LongEcho do
    use Hell.Handler

    @impl Hell.Handler
    def handle_data(data, socket, state) do
      Hell.Socket.send(socket, data)
      {:continue, state}
    end
  end

  defmodule Goodbye do
    use Hell.Handler

    @impl Hell.Handler
    def handle_shutdown(socket, state) do
      Hell.Socket.send(socket, "GOODBYE")
      {:close, state}
    end
  end

  defmodule ReadOpt do
    use Hell.Handler

    @impl Hell.Handler
    def handle_data(data, socket, state) do
      opts = [String.to_atom(data)]
      Hell.Socket.send(socket, inspect(Hell.Socket.getopts(socket, opts)))
      {:close, state}
    end
  end

  defmodule Error do
    use Hell.Handler

    @impl Hell.Handler
    def handle_error(error, _socket, state) do
      # Send error to test process
      case :proplists.get_value(:test_pid, state) do
        pid when is_pid(pid) ->
          send(pid, error)
          :ok

        _ ->
          raise "missing :test_pid for Error handler"
      end
    end
  end

  defmodule PeerCert do
    use Hell.Handler

    @impl Hell.Handler
    def handle_connection(socket, state) do
      {:ok, der} = Hell.Socket.peercert(socket)
      Hell.Socket.send(socket, der)
      {:close, state}
    end
  end

  defmodule Whoami do
    use Hell.Handler

    @impl Hell.Handler
    def handle_connection(socket, state) do
      Hell.Socket.send(socket, :erlang.pid_to_list(self()))
      {:continue, state}
    end
  end

  test "should handle multiple connections as expected" do
    {:ok, _, port} = start_handler(Echo)
    {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
    {:ok, other_client} = :gen_tcp.connect(:localhost, port, active: false)

    :ok = :gen_tcp.send(client, "HELLO")
    :ok = :gen_tcp.send(other_client, "BONJOUR")

    # Invert the order to ensure we handle concurrently
    assert :gen_tcp.recv(other_client, 0) == {:ok, ~c"BONJOUR"}
    assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}

    :gen_tcp.close(client)
    :gen_tcp.close(other_client)
  end

  describe "num_connections handling" do
    test "should properly handle too many connections by queueing" do
      {:ok, _, port} = start_handler(LongEcho, num_acceptors: 1, num_connections: 1)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      {:ok, other_client} = :gen_tcp.connect(:localhost, port, active: false)

      :ok = :gen_tcp.send(client, "HELLO")
      :ok = :gen_tcp.send(other_client, "BONJOUR")

      # Give things enough time to send if they were going to
      Process.sleep(100)

      # Ensure that we haven't received anything on the second connection yet
      assert :gen_tcp.recv(other_client, 0, 10) == {:error, :timeout}
      assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}

      # Close our first connection to make room for the second to be accepted
      :gen_tcp.close(client)

      # Give things enough time to send if they were going to
      Process.sleep(100)

      # Ensure that the second connection unblocked
      assert :gen_tcp.recv(other_client, 0) == {:ok, ~c"BONJOUR"}
      :gen_tcp.close(other_client)
    end

    test "should properly handle too many connections if none close in time" do
      {:ok, _, port} =
        start_handler(LongEcho,
          num_acceptors: 1,
          num_connections: 1,
          max_connections_retry_wait: 100
        )

      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      {:ok, other_client} = :gen_tcp.connect(:localhost, port, active: false)

      :ok = :gen_tcp.send(client, "HELLO")
      :ok = :gen_tcp.send(other_client, "BONJOUR")

      # Give things enough time to send if they were going to
      Process.sleep(100)

      # Ensure that we haven't received anything on the second connection yet
      assert :gen_tcp.recv(other_client, 0, 10) == {:error, :timeout}
      assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}

      # Give things enough time for the second connection to time out
      Process.sleep(500)

      # Ensure that the first connection is still open and the second connection closed
      :ok = :gen_tcp.send(client, "HELLO")
      assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}
      assert :gen_tcp.recv(other_client, 0) == {:error, :closed}
      :gen_tcp.close(other_client)

      # Close the first connection and ensure new connections are now accepted
      :gen_tcp.close(client)

      # Give things enough time for the first connection to time out
      Process.sleep(500)

      {:ok, third_client} = :gen_tcp.connect(:localhost, port, active: false)
      :ok = :gen_tcp.send(third_client, "BUONGIORNO")

      # Give things enough time to send if they were going to
      Process.sleep(100)

      assert :gen_tcp.recv(third_client, 0) == {:ok, ~c"BUONGIORNO"}
    end

    test "should emit telemetry events as expected" do
      TelemetryHelpers.attach_all_events(LongEcho)

      {:ok, _, port} =
        start_handler(LongEcho,
          num_acceptors: 1,
          num_connections: 1,
          max_connections_retry_count: 0
        )

      # Prove the first connection occupies the only slot before triggering rejection.
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      :ok = :gen_tcp.send(client, "HELLO")
      assert :gen_tcp.recv(client, 0, 1000) == {:ok, ~c"HELLO"}

      # Retry timing is covered above; this test observes rejection and its telemetry directly.
      {:ok, other_client} = :gen_tcp.connect(:localhost, port, active: false)
      assert :gen_tcp.recv(other_client, 0, 1000) == {:error, :closed}

      assert_receive {:telemetry, [:hell, :acceptor, :spawn_error], measurements, metadata},
                     1000

      assert measurements ~> %{monotonic_time: integer()}
      assert metadata ~> %{handler: LongEcho, telemetry_span_context: reference()}
      :gen_tcp.close(client)
      :gen_tcp.close(other_client)
    end
  end

  test "should enumerate active connection processes" do
    {:ok, server_pid, port} = start_handler(Whoami)
    {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
    {:ok, other_client} = :gen_tcp.connect(:localhost, port, active: false)

    {:ok, pid_1} = :gen_tcp.recv(client, 0)
    {:ok, pid_2} = :gen_tcp.recv(other_client, 0)
    pid_1 = :erlang.list_to_pid(pid_1)
    pid_2 = :erlang.list_to_pid(pid_2)

    {:ok, pids} = Hell.connection_pids(server_pid)
    assert Enum.sort(pids) == Enum.sort([pid_1, pid_2])

    :gen_tcp.close(client)
    Process.sleep(100)

    assert {:ok, [pid_2]} == Hell.connection_pids(server_pid)

    :gen_tcp.close(other_client)
    Process.sleep(100)

    assert {:ok, []} == Hell.connection_pids(server_pid)
  end

  describe "suspend / resume" do
    test "suspend should stop accepting connections but keep existing ones open" do
      {:ok, server_pid, port} = start_handler(LongEcho, port: 9999)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)

      :ok = Hell.suspend(server_pid)

      # New connections should fail
      assert :gen_tcp.connect(:localhost, port, [active: false], 100) == {:error, :econnrefused}

      # But existing ones should still be open
      :ok = :gen_tcp.send(client, "HELLO")
      assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}

      # Now we resume the server
      :ok = Hell.resume(server_pid)

      # New connections should succeed
      {:ok, new_client} = :gen_tcp.connect(:localhost, port, active: false)
      :ok = :gen_tcp.send(new_client, "HELLO")
      assert :gen_tcp.recv(new_client, 0) == {:ok, ~c"HELLO"}
      :gen_tcp.close(new_client)

      # And existing ones should still be open
      :ok = :gen_tcp.send(client, "HELLO")
      assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}
      :gen_tcp.close(client)
    end
  end

  describe "shutdown" do
    test "it should stop accepting connections but allow existing ones to complete" do
      {:ok, server_pid, port} = start_handler(Echo)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)
      task = Task.async(fn -> Hell.stop(server_pid) end)
      # Make sure that the stop has had a chance to shutdown the acceptors
      Process.sleep(100)

      assert :gen_tcp.connect(:localhost, port, [active: false], 100) == {:error, :econnrefused}

      :ok = :gen_tcp.send(client, "HELLO")
      assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}
      :gen_tcp.close(client)

      Task.await(task)

      refute Process.alive?(server_pid)
    end

    test "it should give connections a chance to say goodbye" do
      {:ok, server_pid, port} = start_handler(Goodbye)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)
      task = Task.async(fn -> Hell.stop(server_pid) end)
      # Make sure that the stop has had a chance to shutdown the acceptors
      Process.sleep(100)

      assert :gen_tcp.recv(client, 0) == {:ok, ~c"GOODBYE"}
      :gen_tcp.close(client)

      Task.await(task)

      refute Process.alive?(server_pid)
    end

    test "it should still work after a suspend / resume cycle" do
      {:ok, server_pid, port} = start_handler(Goodbye)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)

      :ok = Hell.suspend(server_pid)
      :ok = Hell.resume(server_pid)

      task = Task.async(fn -> Hell.stop(server_pid) end)
      # Make sure that the stop has had a chance to shutdown the acceptors
      Process.sleep(100)

      assert :gen_tcp.recv(client, 0) == {:ok, ~c"GOODBYE"}
      :gen_tcp.close(client)

      Task.await(task)

      refute Process.alive?(server_pid)
    end

    test "it should forcibly shutdown connections after shutdown_timeout" do
      {:ok, server_pid, port} = start_handler(Echo, shutdown_timeout: 500)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)
      task = Task.async(fn -> Hell.stop(server_pid) end)
      # Make sure that the stop is still waiting on the open client, and the client is still alive
      Process.sleep(100)
      assert Process.alive?(server_pid)
      :gen_tcp.send(client, "HELLO")
      assert :gen_tcp.recv(client, 0) == {:ok, ~c"HELLO"}

      # Make sure that the stop finished by shutdown_timeout
      Process.sleep(500)
      refute Process.alive?(server_pid)

      # Clean up by waiting on the shutdown task
      Task.await(task)
    end

    test "it waits for acceptor telemetry before completing shutdown" do
      TelemetryHelpers.attach_all_events(Echo)
      {:ok, server_pid, _} = start_handler(Echo, num_acceptors: 1)

      assert_receive {:telemetry, [:hell, :acceptor, :start], _,
                      %{telemetry_span_context: acceptor_span}},
                     500

      pool = Hell.Server.acceptor_pool_supervisor_pid(server_pid)
      [acceptor_supervisor] = Hell.AcceptorPoolSupervisor.acceptor_supervisor_pids(pool)

      {:acceptor, acceptor, _, _} =
        List.keyfind(Supervisor.which_children(acceptor_supervisor), :acceptor, 0)

      :erlang.suspend_process(acceptor)

      try do
        task = Task.async(fn -> Hell.stop(server_pid) end)
        assert_receive {:telemetry, [:hell, :listener, :stop], _, _}, 500
        assert Task.yield(task, 100) == nil

        :erlang.resume_process(acceptor)
        assert Task.await(task) == :ok

        assert_receive {:telemetry, [:hell, :acceptor, :stop], _,
                        %{telemetry_span_context: ^acceptor_span}},
                       500

        refute_receive {:telemetry, [:hell, :acceptor, :stop], _,
                        %{telemetry_span_context: ^acceptor_span}},
                       100
      after
        try do
          :erlang.resume_process(acceptor)
        catch
          :error, :badarg -> :ok
        end
      end
    end

    test "it completes every acceptor span across multiple listener sockets" do
      TelemetryHelpers.attach_all_events(Echo)

      {:ok, server_pid, _} =
        start_handler(Echo,
          num_acceptors: 4,
          num_listen_sockets: 2,
          transport_options: [reuseport: true]
        )

      spans =
        for _ <- 1..4 do
          assert_receive {:telemetry, [:hell, :acceptor, :start], _,
                          %{telemetry_span_context: span}},
                         500

          span
        end

      assert MapSet.size(MapSet.new(spans)) == 4
      Hell.stop(server_pid)

      for span <- spans do
        assert_receive {:telemetry, [:hell, :acceptor, :stop], %{connections: 0},
                        %{telemetry_span_context: ^span}},
                       500
      end
    end

    test "it should emit telemetry events as expected" do
      TelemetryHelpers.attach_all_events(Echo)

      {:ok, server_pid, _} = start_handler(Echo, num_acceptors: 1)

      assert_receive {:telemetry, [:hell, :listener, :start], measurements, metadata},
                     500

      assert measurements ~> %{monotonic_time: integer(), system_time: integer()}

      assert metadata
             ~> %{
               handler: Echo,
               telemetry_span_context: reference(),
               local_address: {0, 0, 0, 0},
               local_port: integer(),
               transport_module: Hell.Transports.TCP,
               transport_options: []
             }

      assert_receive {:telemetry, [:hell, :acceptor, :start], measurements, metadata},
                     500

      assert measurements ~> %{monotonic_time: integer(), system_time: integer()}

      assert metadata
             ~> %{
               handler: Echo,
               telemetry_span_context: reference(),
               parent_telemetry_span_context: reference()
             }

      Hell.stop(server_pid)

      assert_receive {:telemetry, [:hell, :acceptor, :stop], measurements, metadata},
                     500

      assert measurements ~> %{monotonic_time: integer(), duration: integer(), connections: 0}

      assert metadata
             ~> %{
               handler: Echo,
               telemetry_span_context: reference(),
               parent_telemetry_span_context: reference()
             }

      assert_receive {:telemetry, [:hell, :listener, :stop], measurements, metadata},
                     500

      assert measurements ~> %{monotonic_time: integer(), duration: integer()}

      assert metadata
             ~> %{
               handler: Echo,
               telemetry_span_context: reference(),
               local_address: {0, 0, 0, 0},
               local_port: integer(),
               transport_module: Hell.Transports.TCP,
               transport_options: []
             }
    end
  end

  describe "status / info" do
    test "should report status across the suspend / resume lifecycle" do
      {:ok, server_pid, port} = start_handler(LongEcho)
      assert Hell.status(server_pid) == :running

      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)

      :ok = Hell.suspend(server_pid)
      assert Hell.status(server_pid) == :suspended

      # Suspending does not affect existing connections, and info reflects both facts
      assert {:ok, %{status: :suspended, local_info: nil, active_connections: 1}} =
               Hell.info(server_pid)

      :ok = Hell.resume(server_pid)
      assert Hell.status(server_pid) == :running

      :gen_tcp.close(client)
    end

    test "should report local info and track active connection counts" do
      {:ok, server_pid, port} = start_handler(LongEcho)

      assert {:ok, %{status: :running, local_info: {_ip, ^port}, active_connections: 0}} =
               Hell.info(server_pid)

      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      {:ok, other_client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the sockets have transitioned ownership to the connection processes
      Process.sleep(100)

      assert {:ok, %{active_connections: 2}} = Hell.info(server_pid)

      :gen_tcp.close(client)
      :gen_tcp.close(other_client)
      Process.sleep(100)

      assert {:ok, %{active_connections: 0}} = Hell.info(server_pid)
    end
  end

  describe "configuration" do
    test "tcp should allow default options to be overridden" do
      {:ok, _, port} = start_handler(ReadOpt, transport_options: [send_timeout: 1230])
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      :gen_tcp.send(client, "send_timeout")
      {:ok, ~c"{:ok, [send_timeout: 1230]}"} = :gen_tcp.recv(client, 0, 100)
    end

    test "tcp should not allow hardcoded options to be overridden" do
      {:ok, _, port} = start_handler(ReadOpt, transport_options: [mode: :list])
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      :gen_tcp.send(client, "mode")
      {:ok, ~c"{:ok, [mode: :binary]}"} = :gen_tcp.recv(client, 0, 100)
    end

    test "tcp should allow Erlang style bare options" do
      {:ok, _, port} = start_handler(Echo, transport_options: [:inet6])
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      :gen_tcp.send(client, "HI")
      {:ok, ~c"HI"} = :gen_tcp.recv(client, 0, 100)
    end

    test "tcp should allow inet_backend option" do
      {:ok, _, port} = start_handler(Echo, transport_options: [inet_backend: :socket])
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
      :gen_tcp.send(client, "HI")
      {:ok, ~c"HI"} = :gen_tcp.recv(client, 0, 100)
    end

    test "ssl should allow default options to be overridden" do
      {:ok, _, port} =
        start_handler(ReadOpt,
          transport_module: Hell.Transports.SSL,
          transport_options: [
            send_timeout: 1230,
            certfile: Path.join(__DIR__, "../support/cert.pem"),
            keyfile: Path.join(__DIR__, "../support/key.pem")
          ]
        )

      {:ok, client} =
        :ssl.connect(:localhost, port,
          active: false,
          verify: :verify_none,
          cacertfile: Path.join(__DIR__, "../support/ca.pem")
        )

      :ssl.send(client, "send_timeout")
      # Observe the configured value independently of TLS scheduling latency.
      {:ok, ~c"{:ok, [send_timeout: 1230]}"} = :ssl.recv(client, 0, 1_000)
    end

    test "ssl should not allow hardcoded options to be overridden" do
      {:ok, _, port} =
        start_handler(ReadOpt,
          transport_module: Hell.Transports.SSL,
          transport_options: [
            mode: :list,
            certfile: Path.join(__DIR__, "../support/cert.pem"),
            keyfile: Path.join(__DIR__, "../support/key.pem")
          ]
        )

      {:ok, client} =
        :ssl.connect(:localhost, port,
          active: false,
          verify: :verify_none,
          cacertfile: Path.join(__DIR__, "../support/ca.pem")
        )

      :ssl.send(client, "mode")
      {:ok, ~c"{:ok, [mode: :binary]}"} = :ssl.recv(client, 0, 100)
    end

    test "ssl should allow Erlang style bare options" do
      {:ok, _, port} =
        start_handler(Echo,
          transport_module: Hell.Transports.SSL,
          transport_options:
            [:inet6] ++
              [
                certfile: Path.join(__DIR__, "../support/cert.pem"),
                keyfile: Path.join(__DIR__, "../support/key.pem")
              ]
        )

      {:ok, client} =
        :ssl.connect(:localhost, port,
          active: false,
          verify: :verify_none,
          cacertfile: Path.join(__DIR__, "../support/ca.pem")
        )

      :ssl.send(client, "HI")
      {:ok, ~c"HI"} = :ssl.recv(client, 0, 100)
    end

    test "ssl mTLS exposes the client certificate to the handler" do
      certfile = Path.join(__DIR__, "../support/cert.pem")
      keyfile = Path.join(__DIR__, "../support/key.pem")
      cacertfile = Path.join(__DIR__, "../support/ca.pem")

      {:ok, _, port} =
        start_handler(PeerCert,
          transport_module: Hell.Transports.SSL,
          transport_options: [
            certfile: certfile,
            keyfile: keyfile,
            verify: :verify_peer,
            cacertfile: cacertfile,
            fail_if_no_peer_cert: true
          ]
        )

      {:ok, client} =
        :ssl.connect(~c"localhost", port,
          mode: :binary,
          active: false,
          verify: :verify_none,
          certfile: certfile,
          keyfile: keyfile
        )

      [{:Certificate, client_der, _}] = certfile |> File.read!() |> :public_key.pem_decode()

      assert {:ok, ^client_der} = recv_all(client, byte_size(client_der))
      :ssl.close(client)
    end

    test "ssl rejects TLS 1.2 versions option" do
      assert {:error, reason} =
               start_supervised(
                 {Hell,
                  port: 0,
                  handler_module: Echo,
                  transport_module: Hell.Transports.SSL,
                  transport_options: [
                    certfile: Path.join(__DIR__, "../support/cert.pem"),
                    keyfile: Path.join(__DIR__, "../support/key.pem"),
                    versions: [:"tlsv1.2"]
                  ]}
               )

      assert inspect(reason) =~ "{:unsupported_option, :versions}"
    end

    test "ssl transport BEAM does not import OTP :ssl" do
      {:ok, {_, [imports: imports]}} =
        :beam_lib.chunks(:code.which(Hell.Transports.SSL), [:imports])

      imported = imports |> Enum.map(&elem(&1, 0)) |> MapSet.new()

      assert MapSet.disjoint?(imported, MapSet.new([:ssl, :tls_socket, :ssl_gen_statem]))
    end
  end

  describe "invalid configuration" do
    # SSL startup behaviour with invalid PEM files changed in OTP 28.1. See OTP-19706
    major = :erlang.system_info(:otp_release) |> List.to_string()
    vsn_file = Path.join([:code.root_dir(), "releases", major, "OTP_VERSION"])
    {:ok, contents} = File.read(vsn_file)

    if contents >= "28.1\n" do
      @tag capture_log: true
      test "it should error if a certificate is not found (OTP 28.1+)" do
        assert {:error, _} =
                 start_supervised(
                   {Hell,
                    port: 0,
                    handler_module: Error,
                    handler_options: [test_pid: self()],
                    transport_module: Hell.Transports.SSL,
                    transport_options: [
                      certfile: Path.join(__DIR__, "./not/a/cert.pem"),
                      keyfile: Path.join(__DIR__, "./not/a/key.pem"),
                      alpn_preferred_protocols: ["foo"]
                    ]}
                 )
      end
    else
      @tag capture_log: true
      test "it should error if a certificate is not found (pre-OTP-28.1)" do
        on_exit(TelemetryHelpers.attach_all_events(Error))

        {:ok, server_pid, port} =
          start_handler(Error,
            handler_options: [test_pid: self()],
            transport_module: Hell.Transports.SSL,
            transport_options: [
              certfile: Path.join(__DIR__, "./not/a/cert.pem"),
              keyfile: Path.join(__DIR__, "./not/a/key.pem"),
              alpn_preferred_protocols: ["foo"]
            ]
          )

        {:error, _} =
          :ssl.connect(~c"localhost", port,
            active: false,
            verify: :verify_peer,
            cacertfile: Path.join(__DIR__, "../support/ca.pem")
          )

        Process.sleep(500)

        Hell.stop(server_pid)

        # Depending on whether the peer closes before socket ownership is transferred, the
        # certificate error is observed either by the handler or while setting up the connection.
        # Both paths must surface an error without activating a non-owning handler.
        result =
          receive do
            {:options, {:certfile, _, _}} ->
              :handler_error

            {:telemetry, [:hell, :acceptor, :spawn_error], measurements, metadata} ->
              {:ownership_error, measurements, metadata}
          after
            1_000 -> :timeout
          end

        case result do
          :handler_error ->
            :ok

          {:ownership_error, measurements, metadata} ->
            assert measurements
                   ~> %{
                     monotonic_time: integer(),
                     error: {:controlling_process, atom()}
                   }

            assert metadata ~> %{handler: Error, telemetry_span_context: reference()}

          :timeout ->
            flunk("expected the certificate or ownership-transfer error to be reported")
        end
      end
    end

    @tag capture_log: true
    test "handshake should fail if the client offers only unsupported ciphers" do
      server_args = [
        port: 0,
        handler_module: Error,
        handler_options: [test_pid: self()],
        transport_module: Hell.Transports.SSL,
        transport_options: [
          certfile: Path.join(__DIR__, "../support/cert.pem"),
          keyfile: Path.join(__DIR__, "../support/key.pem"),
          alpn_preferred_protocols: ["foo"],
          ciphers: [:tls_aes_256_gcm_sha384]
        ]
      ]

      {:ok, server_pid} = start_supervised({Hell, server_args})
      {:ok, {_ip, port}} = Hell.listener_info(server_pid)

      # The client offers only a TLS 1.3 suite the server excludes.
      {:error, _} =
        :ssl.connect(~c"localhost", port,
          active: false,
          verify: :verify_peer,
          cacertfile: Path.join(__DIR__, "../support/ca.pem"),
          versions: [:"tlsv1.3"],
          ciphers: [
            %{cipher: :aes_128_gcm, key_exchange: :any, mac: :aead, prf: :sha256}
          ]
        )

      Process.sleep(500)

      Hell.stop(server_pid)

      # RFC 8446 section 4.1.1: no shared cipher suite aborts with handshake_failure.
      assert_received {:tls_alert, {:handshake_failure, _}}
    end
  end

  defp recv_all(client, length, acc \\ "")

  defp recv_all(_client, length, acc) when byte_size(acc) >= length, do: {:ok, acc}

  defp recv_all(client, length, acc) do
    case :ssl.recv(client, 0, 1_000) do
      {:ok, data} -> recv_all(client, length, acc <> data)
      error -> error
    end
  end

  defp start_handler(handler, opts \\ []) do
    resolved_args = opts |> Keyword.put_new(:port, 0) |> Keyword.put(:handler_module, handler)
    {:ok, server_pid} = start_supervised({Hell, resolved_args})
    {:ok, {_ip, port}} = Hell.listener_info(server_pid)
    {:ok, server_pid, port}
  end
end
