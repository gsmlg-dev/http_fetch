defmodule ExSSL.TestSupport.LocalTLSPeer do
  @moduledoc false

  defstruct [:listener, :listener_kind, :port, :task, :certfile, :keyfile, :tmpdir]

  @type t :: t(:ssl.sslsocket() | :gen_tcp.socket(), :ssl | :tcp)
  @type t(listener, kind) :: %__MODULE__{
          listener: listener,
          listener_kind: kind,
          port: :inet.port_number(),
          task: Task.t(),
          certfile: String.t(),
          keyfile: String.t(),
          tmpdir: String.t()
        }

  @type certificate_files :: %{
          certfile: String.t(),
          cafile: String.t(),
          keyfile: String.t(),
          ecdsa_certfile: String.t(),
          ecdsa_keyfile: String.t(),
          expired_certfile: String.t(),
          chain_certfile: String.t(),
          chain_keyfile: String.t(),
          intermediate_certfile: String.t(),
          tmpdir: String.t()
        }

  @spec certificate_authorities() :: [binary()]
  def certificate_authorities do
    %{cafile: cafile} = certificates()

    cafile
    |> File.read!()
    |> :public_key.pem_decode()
    |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)
  end

  @spec server_certificate() :: binary()
  def server_certificate do
    %{certfile: certfile} = certificates()
    [{:Certificate, der, :not_encrypted}] = certfile |> File.read!() |> :public_key.pem_decode()
    der
  end

  @spec certificate_from_pem!(Path.t()) :: binary()
  def certificate_from_pem!(path) do
    [{:Certificate, der, :not_encrypted}] = path |> File.read!() |> :public_key.pem_decode()
    der
  end

  @spec start((:ssl.sslsocket() -> term()), keyword()) :: {:ok, t(:ssl.sslsocket(), :ssl)}
  def start(handler, options \\ []) when is_function(handler, 1) and is_list(options) do
    :ok = :ssl.start()
    certificates = certificates()
    {certfile, keyfile} = certificate_pair(certificates, Keyword.get(options, :certificate, :rsa))

    tls_options =
      [
        certfile: String.to_charlist(certfile),
        keyfile: String.to_charlist(keyfile),
        versions: [:"tlsv1.3"],
        verify: :verify_none,
        reuseaddr: true,
        active: false,
        mode: :binary,
        packet: :raw
      ]
      |> Keyword.merge(Keyword.get(options, :ssl_options, []))

    {:ok, listener} = :ssl.listen(0, tls_options)

    {:ok, {_address, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, socket} = :ssl.transport_accept(listener, 5_000)

        case :ssl.handshake(socket, 5_000) do
          {:ok, socket} -> handler.(socket)
          {:error, reason} -> {:handshake_error, reason}
        end
      end)

    {:ok,
     %__MODULE__{
       listener: listener,
       listener_kind: :ssl,
       port: port,
       task: task,
       certfile: certfile,
       keyfile: keyfile,
       tmpdir: certificates.tmpdir
     }}
  end

  @spec start_starttls((:ssl.sslsocket() -> term())) :: {:ok, t(:gen_tcp.socket(), :tcp)}
  def start_starttls(handler) when is_function(handler, 1) do
    :ok = :ssl.start()
    %{certfile: certfile, keyfile: keyfile, tmpdir: tmpdir} = certificates()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 5_000)
        :ok = :gen_tcp.send(tcp, "220 local STARTTLS peer\r\n")
        {:ok, "STARTTLS\r\n"} = :gen_tcp.recv(tcp, 0, 5_000)
        :ok = :gen_tcp.send(tcp, "220 begin TLS\r\n")

        case :ssl.handshake(tcp,
               certfile: String.to_charlist(certfile),
               keyfile: String.to_charlist(keyfile),
               versions: [:"tlsv1.3"],
               verify: :verify_none,
               active: false,
               mode: :binary,
               packet: :raw,
               reuseaddr: true
             ) do
          {:ok, socket} -> handler.(socket)
          {:error, reason} -> {:handshake_error, reason}
        end
      end)

    {:ok,
     %__MODULE__{
       listener: listener,
       listener_kind: :tcp,
       port: port,
       task: task,
       certfile: certfile,
       keyfile: keyfile,
       tmpdir: tmpdir
     }}
  end

  @spec observe_client_hello(pid()) :: {:ok, %{port: :inet.port_number(), task: Task.t()}}
  def observe_client_hello(observer) when is_pid(observer) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, bytes} = :gen_tcp.recv(socket, 0, 5_000)
        send(observer, {:client_hello_observed, bytes})
        :ok = :gen_tcp.close(socket)
        :ok = :gen_tcp.close(listener)
      end)

    {:ok, %{port: port, task: task}}
  end

  @spec start_fragmenting_proxy(:inet.port_number(), pid()) ::
          {:ok, %{listener: port(), port: :inet.port_number(), ref: reference(), task: Task.t()}}
  def start_fragmenting_proxy(upstream_port, observer)
      when is_integer(upstream_port) and is_pid(observer) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)
    ref = make_ref()

    task =
      Task.async(fn ->
        with {:ok, downstream} <- :gen_tcp.accept(listener, 5_000),
             {:ok, upstream} <-
               :gen_tcp.connect(
                 ~c"127.0.0.1",
                 upstream_port,
                 [:binary, active: false, packet: :raw],
                 5_000
               ) do
          client_to_server =
            Task.async(fn -> forward(downstream, upstream, :client_to_server, observer, ref) end)

          server_to_client =
            Task.async(fn -> forward(upstream, downstream, :server_to_client, observer, ref) end)

          result = Task.await(client_to_server, :infinity)
          :gen_tcp.close(downstream)
          :gen_tcp.close(upstream)
          _ = Task.shutdown(server_to_client, 1_000)
          result
        end
      end)

    {:ok, %{listener: listener, port: port, ref: ref, task: task}}
  end

  @spec start_record_gate_proxy(:inet.port_number(), pid()) ::
          {:ok,
           %{
             listener: port(),
             port: :inet.port_number(),
             ref: reference(),
             task: Task.t(),
             controller: pid()
           }}
  def start_record_gate_proxy(upstream_port, observer),
    do: start_record_gate_proxy(upstream_port, observer, [])

  @spec start_record_gate_proxy(:inet.port_number(), pid(), keyword()) ::
          {:ok,
           %{
             listener: port(),
             port: :inet.port_number(),
             ref: reference(),
             task: Task.t(),
             controller: pid()
           }}
  def start_record_gate_proxy(upstream_port, observer, options)
      when is_integer(upstream_port) and is_pid(observer) and is_list(options) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)
    ref = make_ref()
    initially_gated = Keyword.get(options, :initially_gated, false)

    controller =
      spawn(fn ->
        if initially_gated, do: send(observer, {:tls_record_proxy, ref, :gated})

        receive do
          {:start, upstream, downstream, task_pid, gated} ->
            record_gate_loop({upstream, downstream}, observer, ref, task_pid, gated)

          :stop_record_gate_proxy ->
            :ok
        end
      end)

    task =
      Task.async(fn ->
        with {:ok, downstream} <- :gen_tcp.accept(listener, 5_000),
             {:ok, upstream} <-
               :gen_tcp.connect(
                 ~c"127.0.0.1",
                 upstream_port,
                 [:binary, active: false, packet: :raw],
                 5_000
               ) do
          client_to_server =
            Task.async(fn ->
              receive do
                :start -> forward(downstream, upstream, :client_to_server, observer, ref)
              end
            end)

          :ok = :gen_tcp.controlling_process(upstream, controller)
          :ok = :gen_tcp.controlling_process(downstream, client_to_server.pid)
          send(controller, {:start, upstream, downstream, self(), initially_gated})
          send(client_to_server.pid, :start)

          receive do
            {:record_gate_proxy_done, ^controller} -> :ok
          end

          _ = Task.shutdown(client_to_server, 1_000)
          _ = :gen_tcp.close(downstream)
          _ = :gen_tcp.close(upstream)
          _ = :gen_tcp.close(listener)
        end
      end)

    {:ok, %{listener: listener, port: port, ref: ref, task: task, controller: controller}}
  end

  @spec start_backpressure_proxy(:inet.port_number(), pid(), keyword()) ::
          {:ok,
           %{
             listener: port(),
             port: :inet.port_number(),
             ref: reference(),
             task: Task.t(),
             controller: pid()
           }}
  def start_backpressure_proxy(upstream_port, observer, options \\ [])
      when is_integer(upstream_port) and is_pid(observer) do
    hold_upstream_close = Keyword.get(options, :hold_upstream_close, false)
    listen_port = Keyword.get(options, :port, 0)

    {:ok, listener} =
      :gen_tcp.listen(listen_port, [
        :binary,
        active: false,
        packet: :raw,
        reuseaddr: true,
        recbuf: 4_096
      ])

    {:ok, {_address, port}} = :inet.sockname(listener)
    ref = make_ref()

    controller =
      spawn(fn ->
        receive do
          {:start, downstream, upstream, parent} ->
            backpressure_forward(downstream, upstream, observer, ref, parent)

          :stop ->
            :ok
        end
      end)

    task =
      Task.async(fn ->
        with {:ok, downstream} <- :gen_tcp.accept(listener, 5_000),
             {:ok, upstream} <-
               :gen_tcp.connect(
                 ~c"127.0.0.1",
                 upstream_port,
                 [:binary, active: false, packet: :raw],
                 5_000
               ) do
          server_to_client =
            spawn(fn ->
              receive do
                {:start, parent} -> direct_forward(upstream, downstream, parent)
              end
            end)

          :ok = :gen_tcp.controlling_process(downstream, controller)
          :ok = :gen_tcp.controlling_process(upstream, server_to_client)
          send(controller, {:start, downstream, upstream, self()})
          send(server_to_client, {:start, self()})
          send(observer, {:backpressure_proxy, ref, :ready})

          receive do
            {:proxy_direction_done, ^server_to_client, {:error, :closed}}
            when hold_upstream_close ->
              # Preserve downstream backpressure after the TLS peer's FIN.
              # Only explicit controller cleanup may release that queue.
              send(observer, {:backpressure_proxy, ref, :upstream_closed})

              receive do
                {:proxy_direction_done, ^controller, result} -> result
              end

            {:proxy_direction_done, _pid, result} ->
              result
          end

          Process.exit(controller, :kill)
          Process.exit(server_to_client, :kill)
          _ = :gen_tcp.close(downstream)
          _ = :gen_tcp.close(upstream)
          _ = :gen_tcp.close(listener)
        end
      end)

    {:ok, %{listener: listener, port: port, ref: ref, task: task, controller: controller}}
  end

  @spec pause_client_to_server(%{controller: pid(), ref: reference()}, pid()) :: :ok
  def pause_client_to_server(%{controller: controller, ref: ref}, observer) do
    send(controller, {:pause, observer, ref})
    :ok
  end

  @spec resume_client_to_server(%{controller: pid(), ref: reference()}, pid()) :: :ok
  def resume_client_to_server(%{controller: controller, ref: ref}, observer) do
    send(controller, {:resume, observer, ref})
    :ok
  end

  @spec stop_backpressure_proxy(%{listener: port(), task: Task.t(), controller: pid()}) :: term()
  def stop_backpressure_proxy(%{listener: listener, task: task, controller: controller}) do
    send(controller, :stop)
    _ = :gen_tcp.close(listener)
    Task.yield(task, 6_000) || Task.shutdown(task, 6_000)
  end

  @spec gate_server_records(%{controller: pid()}) :: :ok
  def gate_server_records(%{controller: controller}) do
    send(controller, :gate_server_records)
    :ok
  end

  @spec release_server_record(%{controller: pid()}) :: :ok
  def release_server_record(%{controller: controller}) do
    send(controller, :release_server_record)
    :ok
  end

  @spec close_record_gate_downstream(%{controller: pid()}) :: :ok
  def close_record_gate_downstream(%{controller: controller}) do
    send(controller, :close_record_gate_downstream)
    :ok
  end

  @spec stop_record_gate_proxy(%{listener: port(), task: Task.t(), controller: pid()}) :: term()
  def stop_record_gate_proxy(%{listener: listener, task: task, controller: controller}) do
    send(controller, :stop_record_gate_proxy)
    _ = :gen_tcp.close(listener)
    Task.shutdown(task, 6_000)
  end

  @spec stop_fragmenting_proxy(%{listener: port(), task: Task.t()}) :: term()
  def stop_fragmenting_proxy(%{listener: listener, task: task}) do
    _ = :gen_tcp.close(listener)
    Task.shutdown(task, 6_000)
  end

  defp backpressure_forward(downstream, upstream, observer, ref, parent) do
    :ok = :inet.setopts(downstream, active: :once)
    backpressure_forward(downstream, upstream, observer, ref, parent, false, nil)
  end

  defp record_gate_loop({upstream, downstream}, observer, ref, parent, gated) do
    :ok = :inet.setopts(upstream, active: :once)
    record_gate_loop({upstream, downstream}, observer, ref, parent, <<>>, :queue.new(), gated, 0)
  end

  defp backpressure_forward(downstream, upstream, observer, ref, parent, paused, held) do
    receive do
      {:pause, caller, ^ref} ->
        send(caller, {:backpressure_proxy, ref, :paused})
        backpressure_forward(downstream, upstream, observer, ref, parent, true, held)

      {:resume, caller, ^ref} ->
        result = if held, do: :gen_tcp.send(upstream, held), else: :ok

        if result == :ok do
          :ok = :inet.setopts(downstream, active: :once)
          send(caller, {:backpressure_proxy, ref, :resumed})
          backpressure_forward(downstream, upstream, observer, ref, parent, false, nil)
        else
          send(parent, {:proxy_direction_done, self(), result})
        end

      :stop ->
        send(parent, {:proxy_direction_done, self(), :stopped})

      {:tcp, ^downstream, bytes} when paused ->
        send(observer, {:backpressure_proxy, ref, :held, byte_size(bytes)})
        backpressure_forward(downstream, upstream, observer, ref, parent, true, bytes)

      {:tcp, ^downstream, bytes} ->
        case :gen_tcp.send(upstream, bytes) do
          :ok ->
            :ok = :inet.setopts(downstream, active: :once)
            backpressure_forward(downstream, upstream, observer, ref, parent, false, nil)

          {:error, reason} ->
            send(parent, {:proxy_direction_done, self(), {:error, reason}})
        end

      {:tcp_closed, ^downstream} ->
        send(parent, {:proxy_direction_done, self(), :closed})

      {:tcp_error, ^downstream, reason} ->
        send(parent, {:proxy_direction_done, self(), {:error, reason}})
    end
  end

  defp direct_forward(source, destination, parent) do
    case :gen_tcp.recv(source, 0, :infinity) do
      {:ok, bytes} ->
        case :gen_tcp.send(destination, bytes) do
          :ok -> direct_forward(source, destination, parent)
          {:error, reason} -> send(parent, {:proxy_direction_done, self(), {:error, reason}})
        end

      {:error, reason} ->
        send(parent, {:proxy_direction_done, self(), {:error, reason}})
    end
  end

  defp record_gate_loop(
         {upstream, downstream},
         observer,
         ref,
         parent,
         buffer,
         queue,
         gated,
         permits
       ) do
    receive do
      :gate_server_records ->
        send(observer, {:tls_record_proxy, ref, :gated})

        record_gate_loop(
          {upstream, downstream},
          observer,
          ref,
          parent,
          buffer,
          queue,
          true,
          permits
        )

      :release_server_record ->
        {queue, permits} = release_record(downstream, observer, ref, queue, permits)

        record_gate_loop(
          {upstream, downstream},
          observer,
          ref,
          parent,
          buffer,
          queue,
          gated,
          permits
        )

      :stop_record_gate_proxy ->
        send(parent, {:record_gate_proxy_done, self()})

      :close_record_gate_downstream ->
        _ = :gen_tcp.close(downstream)
        send(observer, {:tls_record_proxy, ref, :downstream_closed})
        send(parent, {:record_gate_proxy_done, self()})

      {:tcp, ^upstream, bytes} ->
        {records, buffer} = take_tls_records(buffer <> bytes, [])

        {queue, permits} =
          forward_records(records, downstream, observer, ref, queue, gated, permits)

        :ok = :inet.setopts(upstream, active: :once)

        record_gate_loop(
          {upstream, downstream},
          observer,
          ref,
          parent,
          buffer,
          queue,
          gated,
          permits
        )

      {:tcp_closed, ^upstream} ->
        if gated do
          send(observer, {:tls_record_proxy, ref, :upstream_closed})

          record_gate_loop(
            {upstream, downstream},
            observer,
            ref,
            parent,
            buffer,
            queue,
            gated,
            permits
          )
        else
          _ = :gen_tcp.close(downstream)
          send(parent, {:record_gate_proxy_done, self()})
        end

      {:tcp_error, ^upstream, _reason} ->
        _ = :gen_tcp.close(downstream)
        send(parent, {:record_gate_proxy_done, self()})
    end
  end

  defp forward_records([], _downstream, _observer, _ref, queue, _gated, permits),
    do: {queue, permits}

  defp forward_records([record | rest], downstream, observer, ref, queue, false, permits) do
    :ok = :gen_tcp.send(downstream, record)
    forward_records(rest, downstream, observer, ref, queue, false, permits)
  end

  defp forward_records([record | rest], downstream, observer, ref, queue, true, permits)
       when permits > 0 do
    :ok = :gen_tcp.send(downstream, record)
    send(observer, {:tls_record_proxy, ref, :released, 1})
    forward_records(rest, downstream, observer, ref, queue, true, permits - 1)
  end

  defp forward_records([record | rest], downstream, observer, ref, queue, true, permits) do
    queue = :queue.in(record, queue)
    send(observer, {:tls_record_proxy, ref, :queued, :queue.len(queue)})
    send(observer, {:tls_record_proxy, ref, :record, record})
    forward_records(rest, downstream, observer, ref, queue, true, permits)
  end

  defp release_record(downstream, observer, ref, queue, permits) do
    case :queue.out(queue) do
      {{:value, record}, queue} ->
        :ok = :gen_tcp.send(downstream, record)
        send(observer, {:tls_record_proxy, ref, :released, 1})
        {queue, permits}

      {:empty, queue} ->
        {queue, permits + 1}
    end
  end

  defp take_tls_records(buffer, records) when byte_size(buffer) < 5,
    do: {Enum.reverse(records), buffer}

  defp take_tls_records(<<_type, _version::16, length::16, rest::binary>> = buffer, records)
       when byte_size(rest) < length,
       do: {Enum.reverse(records), buffer}

  defp take_tls_records(<<type, version::16, length::16, rest::binary>>, records) do
    <<record_body::binary-size(^length), remainder::binary>> = rest

    take_tls_records(remainder, [<<type, version::16, length::16, record_body::binary>> | records])
  end

  defp certificate_pair(%{certfile: certfile, keyfile: keyfile}, :rsa), do: {certfile, keyfile}

  defp certificate_pair(%{ecdsa_certfile: certfile, ecdsa_keyfile: keyfile}, :ecdsa),
    do: {certfile, keyfile}

  defp certificate_pair(%{expired_certfile: certfile, keyfile: keyfile}, :expired),
    do: {certfile, keyfile}

  defp certificate_pair(%{chain_certfile: certfile, chain_keyfile: keyfile}, :intermediate_chain),
    do: {certfile, keyfile}

  @spec stop(t()) :: term()
  def stop(%__MODULE__{listener: listener, listener_kind: kind, task: task}) do
    _ = if(kind == :tcp, do: :gen_tcp.close(listener), else: :ssl.close(listener))
    Task.await(task, 6_000)
  end

  @spec client_options() :: [
          :binary
          | {:active, false}
          | {:packet, :raw}
          | {:verify, :verify_peer}
          | {:cacerts, [binary()]}
          | {:server_name_indication, nonempty_charlist()}
          | {:customize_hostname_check, [{:match_fun, function()}, ...]}
          | {:versions, [:"tlsv1.3", ...]},
          ...
        ]
  def client_options do
    [
      :binary,
      active: false,
      packet: :raw,
      verify: :verify_peer,
      cacerts: certificate_authorities(),
      server_name_indication: ~c"exssl.test",
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ],
      versions: [:"tlsv1.3"]
    ]
  end

  @spec start_openssl() :: {:ok, %{port: :inet.port_number(), port_handle: port()}}
  def start_openssl do
    %{certfile: certfile, keyfile: keyfile} = certificates()
    port = available_port()

    executable =
      System.find_executable("openssl") || raise "openssl is required for interop tests"

    port_handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        args: [
          "s_server",
          "-accept",
          Integer.to_string(port),
          "-cert",
          certfile,
          "-key",
          keyfile,
          "-tls1_3",
          "-www",
          "-quiet"
        ]
      ])

    peer = %{port: port, port_handle: port_handle}

    try do
      await_openssl(port, 40)
      {:ok, peer}
    rescue
      exception ->
        stop_openssl(peer)
        reraise exception, __STACKTRACE__
    end
  end

  @spec stop_openssl(%{required(:port_handle) => port(), optional(atom()) => term()}) :: :ok
  def stop_openssl(%{port_handle: port_handle}) do
    # s_server -quiet ignores stdin EOF, so closing its BEAM port is insufficient.
    # Signal the exact owned child and wait for process exit before returning.
    case Port.info(port_handle, :os_pid) do
      nil ->
        :ok

      {:os_pid, pid} ->
        _ = System.cmd("kill", ["-TERM", Integer.to_string(pid)], stderr_to_stdout: true)

        receive do
          {^port_handle, {:exit_status, _status}} -> :ok
        after
          2_000 -> raise "openssl test peer did not terminate"
        end
    end
  end

  defp available_port do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false])
    {:ok, {_address, port}} = :inet.sockname(listener)
    :ok = :gen_tcp.close(listener)
    port
  end

  defp await_openssl(_port, 0), do: raise("openssl s_server did not start")

  defp await_openssl(port, attempts) do
    case :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 50) do
      {:ok, socket} ->
        :ok = :gen_tcp.close(socket)

      {:error, _reason} ->
        Process.sleep(25)
        await_openssl(port, attempts - 1)
    end
  end

  defp forward(source, destination, direction, observer, ref) do
    case :gen_tcp.recv(source, 0, 5_000) do
      {:ok, bytes} ->
        bytes = coalesce(source, bytes, 8)
        send(observer, {:tls_proxy, ref, direction, bytes})

        case send_fragments(destination, bytes, [1, 2, 3, 5, 8, 13]) do
          :ok -> forward(source, destination, direction, observer, ref)
          :closed -> :closed
          {:error, reason} -> {:error, reason}
        end

      {:error, :closed} ->
        :closed

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp coalesce(_socket, bytes, 0), do: bytes

  defp coalesce(socket, bytes, remaining) do
    case :gen_tcp.recv(socket, 0, 0) do
      {:ok, more} -> coalesce(socket, bytes <> more, remaining - 1)
      {:error, :timeout} -> bytes
      {:error, :closed} -> bytes
      {:error, _reason} -> bytes
    end
  end

  defp send_fragments(socket, bytes, sizes), do: send_fragments(socket, bytes, sizes, sizes)
  defp send_fragments(_socket, <<>>, _sizes, _all_sizes), do: :ok

  defp send_fragments(socket, bytes, [], all_sizes),
    do: send_fragments(socket, bytes, all_sizes, all_sizes)

  defp send_fragments(socket, bytes, [size | sizes], all_sizes) do
    length = min(size, byte_size(bytes))
    <<chunk::binary-size(^length), rest::binary>> = bytes

    case :gen_tcp.send(socket, chunk) do
      :ok -> send_fragments(socket, rest, sizes, all_sizes)
      {:error, :closed} -> :closed
      {:error, reason} -> {:error, reason}
    end
  end

  @spec certificates() :: certificate_files()
  def certificates do
    key = {__MODULE__, :certificates}

    case :persistent_term.get(key, nil) do
      nil ->
        suffix = Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
        tmpdir = Path.join(System.tmp_dir!(), "ex-ssl-test-#{suffix}")
        File.mkdir_p!(tmpdir)
        cafile = Path.join(tmpdir, "ca.pem")
        cakeyfile = Path.join(tmpdir, "ca-key.pem")
        certfile = Path.join(tmpdir, "server.pem")
        keyfile = Path.join(tmpdir, "server-key.pem")
        ecdsa_certfile = Path.join(tmpdir, "server-ecdsa.pem")
        ecdsa_keyfile = Path.join(tmpdir, "server-ecdsa-key.pem")
        requestfile = Path.join(tmpdir, "server.csr")
        ecdsa_requestfile = Path.join(tmpdir, "server-ecdsa.csr")
        expired_certfile = Path.join(tmpdir, "server-expired.pem")
        intermediate_keyfile = Path.join(tmpdir, "intermediate-key.pem")
        intermediate_requestfile = Path.join(tmpdir, "intermediate.csr")
        intermediate_certfile = Path.join(tmpdir, "intermediate.pem")
        chain_keyfile = Path.join(tmpdir, "server-chain-key.pem")
        chain_requestfile = Path.join(tmpdir, "server-chain.csr")
        chain_leaf_certfile = Path.join(tmpdir, "server-chain-leaf.pem")
        chain_certfile = Path.join(tmpdir, "server-chain.pem")
        intermediate_extensions = Path.join(tmpdir, "intermediate.ext")
        ca_config = Path.join(tmpdir, "ca.cnf")
        indexfile = Path.join(tmpdir, "index.txt")
        serialfile = Path.join(tmpdir, "serial")
        extensions = Path.join(tmpdir, "server.ext")

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "req",
              "-x509",
              "-newkey",
              "rsa:2048",
              "-nodes",
              "-keyout",
              cakeyfile,
              "-out",
              cafile,
              "-subj",
              "/CN=ex-ssl test CA",
              "-addext",
              "basicConstraints=critical,CA:TRUE",
              "-addext",
              "keyUsage=critical,keyCertSign,cRLSign",
              "-days",
              "2"
            ],
            stderr_to_stdout: true
          )

        File.write!(
          intermediate_extensions,
          "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n"
        )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "req",
              "-newkey",
              "rsa:2048",
              "-nodes",
              "-keyout",
              intermediate_keyfile,
              "-out",
              intermediate_requestfile,
              "-subj",
              "/CN=ex-ssl test intermediate CA"
            ],
            stderr_to_stdout: true
          )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "x509",
              "-req",
              "-in",
              intermediate_requestfile,
              "-CA",
              cafile,
              "-CAkey",
              cakeyfile,
              "-CAcreateserial",
              "-out",
              intermediate_certfile,
              "-days",
              "2",
              "-extfile",
              intermediate_extensions
            ],
            stderr_to_stdout: true
          )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "req",
              "-newkey",
              "rsa:2048",
              "-nodes",
              "-keyout",
              chain_keyfile,
              "-out",
              chain_requestfile,
              "-subj",
              "/CN=exssl.test"
            ],
            stderr_to_stdout: true
          )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "req",
              "-newkey",
              "rsa:2048",
              "-nodes",
              "-keyout",
              keyfile,
              "-out",
              requestfile,
              "-subj",
              "/CN=exssl.test"
            ],
            stderr_to_stdout: true
          )

        File.write!(indexfile, "")
        File.write!(serialfile, "01\n")

        File.write!(
          ca_config,
          """
          [ ca ]
          default_ca = local_ca
          [ local_ca ]
          database = #{indexfile}
          serial = #{serialfile}
          new_certs_dir = #{tmpdir}
          certificate = #{cafile}
          private_key = #{cakeyfile}
          default_md = sha256
          policy = policy_any
          x509_extensions = server_extensions
          [ policy_any ]
          commonName = supplied
          [ server_extensions ]
          subjectAltName = DNS:exssl.test
          basicConstraints = critical,CA:FALSE
          keyUsage = critical,digitalSignature,keyEncipherment
          extendedKeyUsage = serverAuth
          """
        )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "ca",
              "-batch",
              "-config",
              ca_config,
              "-in",
              requestfile,
              "-out",
              expired_certfile,
              "-startdate",
              "20200101000000Z",
              "-enddate",
              "20200102000000Z"
            ],
            stderr_to_stdout: true
          )

        File.write!(
          extensions,
          "subjectAltName=DNS:exssl.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
        )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "x509",
              "-req",
              "-in",
              chain_requestfile,
              "-CA",
              intermediate_certfile,
              "-CAkey",
              intermediate_keyfile,
              "-CAcreateserial",
              "-out",
              chain_leaf_certfile,
              "-days",
              "2",
              "-extfile",
              extensions
            ],
            stderr_to_stdout: true
          )

        File.write!(
          chain_certfile,
          File.read!(chain_leaf_certfile) <> File.read!(intermediate_certfile)
        )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "x509",
              "-req",
              "-in",
              requestfile,
              "-CA",
              cafile,
              "-CAkey",
              cakeyfile,
              "-CAcreateserial",
              "-out",
              certfile,
              "-days",
              "2",
              "-extfile",
              extensions
            ],
            stderr_to_stdout: true
          )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "ecparam",
              "-name",
              "prime256v1",
              "-genkey",
              "-noout",
              "-out",
              ecdsa_keyfile
            ],
            stderr_to_stdout: true
          )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "req",
              "-new",
              "-key",
              ecdsa_keyfile,
              "-out",
              ecdsa_requestfile,
              "-subj",
              "/CN=exssl.test"
            ],
            stderr_to_stdout: true
          )

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "x509",
              "-req",
              "-in",
              ecdsa_requestfile,
              "-CA",
              cafile,
              "-CAkey",
              cakeyfile,
              "-CAcreateserial",
              "-out",
              ecdsa_certfile,
              "-days",
              "2",
              "-extfile",
              extensions
            ],
            stderr_to_stdout: true
          )

        certs = %{
          certfile: certfile,
          cafile: cafile,
          keyfile: keyfile,
          ecdsa_certfile: ecdsa_certfile,
          ecdsa_keyfile: ecdsa_keyfile,
          expired_certfile: expired_certfile,
          chain_certfile: chain_certfile,
          chain_keyfile: chain_keyfile,
          intermediate_certfile: intermediate_certfile,
          tmpdir: tmpdir
        }

        :persistent_term.put(key, certs)
        certs

      certs ->
        certs
    end
  end
end
