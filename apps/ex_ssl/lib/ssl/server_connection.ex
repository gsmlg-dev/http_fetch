defmodule SSL.ServerConnection do
  @moduledoc false
  # TCP TLS 1.3 server connection: :hello -> :client_finished -> :connected -> :closing.
  # With client authentication the encrypted client flight passes through
  # :client_certificate -> :client_certificate_verify before :client_finished;
  # application data is accepted only in :connected.
  #
  # The process owns the carrier and answers the same call protocol as
  # SSL.Connection, so SSL.send/recv/setopts/close work on server sockets.
  # After the handshake every carrier write is a job for an SSL.ConnectionWriter
  # process, sent in encryption order and bounded by the carrier's
  # `send_timeout` (and a reservation deadline), so a blocked write does not stop
  # receive processing or control calls (#161). `:closing` serves plaintext still
  # buffered after the peer closed. No NewSessionTicket is issued.
  @behaviour :gen_statem

  alias SSL.{
    Capabilities,
    ConnectionWriter,
    Diagnostics,
    IodataCursor,
    Options,
    ServerOptions,
    Socket,
    TCPOptions
  }

  alias SSL.Crypto.{KeyExchange, KeySchedule, TrafficState}

  alias SSL.Protocol.{
    ClientOffer,
    HandshakeFramer,
    HandshakeMachine,
    Record,
    RecordFramer,
    ServerFlight,
    ServerHandshake
  }

  @ccs <<20, 3, 3, 0, 1, 1>>
  @client_flight [:client_certificate, :client_certificate_verify, :client_finished]
  @handshaking [:hello | @client_flight]
  @max_fragment 16_384
  @max_plaintext 1_048_576
  @rearm_reserve 65_536
  # Rejected 0-RTT bytes a server skips (RFC 8446 §4.2.10); no ticket is ever
  # issued, so this bounds what a client may send under a foreign PSK.
  @max_early_data 16_384
  # Each skipped record costs an AEAD trial decryption and minimum-size records
  # draw nothing from the byte budget, so the record count is capped as well.
  @max_early_records 64
  # A pre-authentication ClientHello is buffered up to this size. Real hellos
  # are 0.2-2 KiB (a few KiB with post-quantum key shares or ECH); 64 KiB is
  # far above that, while the 1 MiB default would let each unauthenticated
  # connection pin a megabyte.
  @max_client_hello 65_536
  # AEAD tag plus the inner content type: the smallest per-record overhead.
  @record_overhead 17
  @alerts %{
    close_notify: 0,
    unexpected_message: 10,
    bad_record_mac: 20,
    record_overflow: 22,
    handshake_failure: 40,
    bad_certificate: 42,
    unsupported_certificate: 43,
    certificate_revoked: 44,
    certificate_expired: 45,
    certificate_unknown: 46,
    illegal_parameter: 47,
    unknown_ca: 48,
    access_denied: 49,
    decode_error: 50,
    decrypt_error: 51,
    protocol_version: 70,
    insufficient_security: 71,
    internal_error: 80,
    inappropriate_fallback: 86,
    user_canceled: 90,
    missing_extension: 109,
    unsupported_extension: 110,
    unrecognized_name: 112,
    bad_certificate_status_response: 113,
    unknown_psk_identity: 115,
    certificate_required: 116,
    no_application_protocol: 120
  }
  @alert_names Map.new(@alerts, fn {name, code} -> {code, name} end)

  defmodule State do
    @moduledoc false
    @derive {Inspect, only: [:socket, :armed, :size, :closed]}
    defstruct [
      :socket,
      :tcp,
      :owner,
      :owner_monitor,
      :config,
      :core,
      :read,
      :write,
      :client_secret,
      :suite,
      :alpn,
      :peercert,
      :handshake_from,
      :deadline,
      :recv,
      :write_token,
      :records,
      :framer,
      :writer,
      :writer_monitor,
      buffer: :queue.new(),
      # Writer jobs in send order: %{token, kind, from}; kind is :application, :control
      # or {:shutdown, how}. Waiters are reservations queued behind an application job.
      jobs: :queue.new(),
      waiters: :queue.new(),
      output_aborted: false,
      size: 0,
      active: false,
      active_terminal: false,
      # Upper bound on plaintext bytes per active-once message (#169).
      active_chunk_size: :infinity,
      armed: false,
      started: false,
      ccs_received: false,
      ccs_sent: false,
      early_data: 0,
      early_records: 0,
      closed: false,
      close_reason: :closed,
      write_closed: false
    ]
  end

  def child_spec(args),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [args]}, restart: :temporary}

  @doc false
  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  @doc """
  Starts an unhandshaked server connection that takes ownership of `tcp`.

  The `:ex_ssl` application must be started; `SSL.listen/2` and the upgrade
  `SSL.handshake/3` ensure it once before calling this.
  """
  @spec start(:gen_tcp.socket(), map(), pid()) :: {:ok, Socket.t()} | {:error, term()}
  def start(tcp, config, owner) when is_port(tcp) and is_map(config) and is_pid(owner) do
    ref = make_ref()
    status = :atomics.new(1, signed: false)

    case SSL.ConnectionSupervisor.start_server({owner, ref, status, config}) do
      {:ok, pid} -> attach(pid, Socket.new(pid, ref, status), tcp)
      {:error, _} -> {:error, :closed}
    end
  end

  def start(_tcp, _config, _owner), do: {:error, :badarg}

  @doc "Runs the TLS 1.3 server handshake within `timeout`."
  @spec handshake(Socket.t(), timeout()) :: {:ok, Socket.t()} | {:error, term()}
  def handshake(socket, timeout) do
    with {:ok, deadline} <- Options.deadline(timeout), do: call(socket, {:handshake, deadline})
  end

  defp attach(pid, socket, tcp) do
    case :gen_tcp.controlling_process(tcp, pid) do
      :ok ->
        with :ok <- call(socket, {:attach, tcp}), do: {:ok, socket}

      {:error, _} = error ->
        _ = DynamicSupervisor.terminate_child(SSL.ConnectionSupervisor, pid)
        error
    end
  end

  defp call(%Socket{pid: pid, ref: ref} = socket, request) do
    :gen_statem.call(pid, {ref, request}, :infinity)
  catch
    :exit, _ -> {:error, Socket.terminal_error(socket)}
  end

  defp call(_, _), do: {:error, :badarg}

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init({owner, ref, status, config}) do
    Process.flag(:sensitive, true)

    {:ok, :hello,
     %State{
       socket: Socket.new(self(), ref, status),
       owner: owner,
       owner_monitor: Process.monitor(owner),
       config: config,
       active_chunk_size: Map.get(config, :active_chunk_size, :infinity),
       records: RecordFramer.new(),
       framer: HandshakeFramer.new()
     }}
  end

  @impl true
  def handle_event({:call, from}, {ref, _request}, _name, %{socket: %{ref: actual}})
      when ref != actual,
      do: reply(from, {:error, :badarg})

  def handle_event({:call, from}, {_ref, {:attach, tcp}}, :hello, %{tcp: nil} = data) do
    case :inet.setopts(tcp, [:binary, packet: :raw, active: false]) do
      :ok -> {:keep_state, %{data | tcp: tcp}, [{:reply, from, :ok}]}
      {:error, _} = error -> {:stop_and_reply, :normal, [{:reply, from, error}], data}
    end
  end

  def handle_event(
        {:call, from},
        {_ref, {:handshake, deadline}},
        :hello,
        %{started: false, tcp: tcp} = data
      )
      when not is_nil(tcp) do
    data = %{data | started: true, handshake_from: from, deadline: deadline}
    continue(:hello, data, [{{:timeout, :handshake}, Options.remaining(deadline), :expired}])
  end

  def handle_event({:call, from}, {_ref, {:handshake, _deadline}}, name, _data)
      when name in [:connected, :closing],
      do: reply(from, {:error, :already_connected})

  def handle_event({:call, from}, {_ref, {:handshake, _deadline}}, name, %{started: true})
      when name in @handshaking,
      do: reply(from, {:error, :already_started})

  def handle_event({:call, from}, {_ref, :close}, name, data) do
    Socket.mark_terminal(data.socket, true)
    data = if name == :connected, do: close_notify(data), else: data
    notify_pending(data, {:error, :closed})
    {:stop_and_reply, :normal, [{:reply, from, :ok}], data}
  end

  def handle_event({:call, from}, {_ref, {:controlling_process, owner}}, _name, data) do
    cond do
      elem(from, 0) != data.owner ->
        reply(from, {:error, :not_owner})

      owner == data.owner ->
        reply(from, :ok)

      not Process.alive?(owner) ->
        reply(from, {:error, :noproc})

      true ->
        Process.demonitor(data.owner_monitor, [:flush])
        data = %{data | owner: owner, owner_monitor: Process.monitor(owner)}
        {:keep_state, data, [{:reply, from, :ok}]}
    end
  end

  def handle_event({:call, from}, {_ref, request}, name, data)
      when name in [:connected, :closing],
      do: connected_call(from, request, name, data)

  # As with OTP :ssl, carrier addresses are available before the handshake.
  def handle_event({:call, from}, {_ref, :peername}, _name, %{tcp: tcp}) when not is_nil(tcp),
    do: reply(from, :inet.peername(tcp))

  def handle_event({:call, from}, {_ref, :sockname}, _name, %{tcp: tcp}) when not is_nil(tcp),
    do: reply(from, :inet.sockname(tcp))

  def handle_event({:call, from}, _request, _name, _data), do: reply(from, {:error, :closed})

  def handle_event(:info, {:tcp, tcp, bytes}, name, %{tcp: tcp} = data) do
    data = %{data | armed: false}

    case RecordFramer.feed(data.records, bytes) do
      {:ok, records, framer} -> process(name, records, %{data | records: framer})
      {:error, reason} -> fail(name, record_alert(reason), data)
    end
  end

  def handle_event(:info, {:tcp_closed, tcp}, name, %{tcp: tcp} = data)
      when name == :connected do
    Socket.mark_terminal(data.socket, false)
    continue(:closing, transport_closed(data))
  end

  def handle_event(:info, {:tcp_closed, tcp}, name, %{tcp: tcp} = data),
    do: fail(name, :closed, data)

  # Like an EOF, a transport error after the handshake keeps decrypted
  # plaintext deliverable and reports the error only after it is drained (#158).
  def handle_event(:info, {:tcp_error, tcp, reason}, :connected, %{tcp: tcp} = data) do
    Socket.mark_terminal(data.socket, false)
    continue(:closing, transport_closed(%{data | close_reason: reason}))
  end

  def handle_event(:info, {:tcp_error, tcp, reason}, name, %{tcp: tcp} = data),
    do: fail(name, reason, data)

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _, _},
        name,
        %{owner_monitor: monitor} = data
      ) do
    Socket.mark_terminal(data.socket, true)
    notify_pending(data, {:error, :closed})
    {:stop, :normal, if(name == :connected, do: close_notify(data), else: data)}
  end

  def handle_event(:info, {:writer_result, writer, token, result}, name, %{writer: writer} = data) do
    case :queue.out(data.jobs) do
      {{:value, %{token: ^token} = job}, jobs} ->
        job_done(name, job, result, %{data | jobs: jobs})

      _stale ->
        :keep_state_and_data
    end
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _, _},
        name,
        %{writer_monitor: monitor} = data
      ),
      do: fail(name, :closed, %{data | writer: nil, writer_monitor: nil})

  # A reservation deadline bounds its application job like the carrier send_timeout.
  def handle_event({:timeout, :write}, :expired, name, data) do
    if writing?(data), do: job_failed(name, :timeout, data), else: :keep_state_and_data
  end

  def handle_event({:timeout, :handshake}, :expired, name, data),
    do: fail(name, :timeout, data)

  def handle_event({:timeout, :recv}, :expired, name, %{recv: %{from: from}} = data),
    do: continue(name, %{data | recv: nil}, [{:reply, from, {:error, :timeout}}])

  def handle_event(_type, _content, _name, _data), do: :keep_state_and_data

  @impl true
  def terminate(_reason, _name, data) do
    Socket.mark_terminal(data.socket, false)
    _ = close_transport(data)
    if data.writer, do: Process.exit(data.writer, :kill)
    :ok
  end

  @impl true
  def format_status(status),
    do:
      Map.merge(status, %{data: :redacted, reason: :redacted, log: [], queue: [], postponed: []})

  ## Application calls (:connected and :closing)

  defp connected_call(from, {:recv, length, deadline}, name, data) do
    cond do
      length > @max_plaintext ->
        reply(from, {:error, :emsgsize})

      data.active != false or data.recv != nil ->
        reply(from, {:error, :einval})

      true ->
        timer = {{:timeout, :recv}, Options.remaining(deadline), :expired}
        continue(name, %{data | recv: %{from: from, length: length}}, [timer])
    end
  end

  defp connected_call(from, :reserve_write, name, data),
    do: connected_call(from, {:reserve_write, :infinity}, name, data)

  defp connected_call(from, {:reserve_write, deadline}, :connected, data)
       when deadline == :infinity or is_integer(deadline) do
    cond do
      data.write_closed ->
        reply(from, {:error, :closed})

      data.write_token != nil and Process.alive?(data.write_token.owner) ->
        reply(from, {:error, :busy})

      deadline != :infinity and Options.remaining(deadline) == 0 ->
        reply(from, {:error, :timeout})

      # As before #161, a reservation made while a write is in flight waits for it.
      writing?(data) ->
        {:keep_state, %{data | waiters: :queue.in({from, deadline}, data.waiters)}}

      true ->
        {data, actions} = grant(from, deadline, data)
        {:keep_state, data, actions}
    end
  end

  defp connected_call(
         from,
         {:send, token, cursor, _size},
         :connected,
         %{write_token: %{token: token, owner: owner} = write} = data
       )
       when elem(from, 0) == owner do
    data = %{data | write_token: nil}

    case protect_application(data.write, cursor, []) do
      {:ok, records, write_state} ->
        data = enqueue(%{data | write: write_state}, :application, from, records)

        timer =
          if write.deadline == :infinity,
            do: [],
            else: [{{:timeout, :write}, Options.remaining(write.deadline), :expired}]

        {:keep_state, data, timer}

      {:error, {:fatal_alert, alert, reason}} ->
        fail_reply(from, alert(alert, reason), data)

      {:error, reason} ->
        fail_reply(from, reason, data)
    end
  end

  defp connected_call(from, {:setopts, options}, name, data) do
    carrier =
      TCPOptions.mutable(options) ++ Keyword.take(options, [:send_timeout, :send_timeout_close])

    cond do
      options[:active] == :once and data.recv != nil ->
        reply(from, {:error, :einval})

      (result = carrier_setopts(data.tcp, carrier)) != :ok ->
        reply(from, result)

      true ->
        data =
          case Keyword.fetch(options, :active) do
            {:ok, :once} -> %{data | active: :once, active_terminal: true}
            {:ok, false} -> %{data | active: false, active_terminal: false}
            :error -> data
          end

        data = %{
          data
          | active_chunk_size: Keyword.get(options, :active_chunk_size, data.active_chunk_size)
        }

        continue(name, data, [{:reply, from, :ok}])
    end
  end

  defp connected_call(from, :negotiated_protocol, _name, data) do
    if is_binary(data.alpn),
      do: reply(from, {:ok, data.alpn}),
      else: reply(from, {:error, :protocol_not_negotiated})
  end

  defp connected_call(from, :peercert, _name, %{peercert: nil}),
    do: reply(from, {:error, :no_peercert})

  defp connected_call(from, :peercert, _name, data), do: reply(from, {:ok, data.peercert})

  defp connected_call(from, {:connection_information, keys}, _name, data) do
    # Diagnostics reads only the negotiated TLS 1.3 suite from a client machine.
    # The default key list of SSL.connection_information/1 also reports the peer.
    machine = %HandshakeMachine{server_hello: %{cipher_suite: data.suite}}
    keys = if keys == Diagnostics.keys(), do: keys ++ [:peer_authenticated], else: keys
    peer = %{peer_authenticated: if(data.peercert, do: :client, else: false)}
    reply(from, Diagnostics.connection_information(machine, keys, peer))
  end

  defp connected_call(from, _request, _name, %{tcp: nil}), do: reply(from, {:error, :closed})

  defp connected_call(from, :peername, _name, data), do: reply(from, :inet.peername(data.tcp))
  defp connected_call(from, :sockname, _name, data), do: reply(from, :inet.sockname(data.tcp))

  defp connected_call(from, {:getopts, keys}, _name, data) when is_list(keys) do
    case :inet.getopts(data.tcp, List.delete(keys, :active)) do
      {:ok, values} ->
        values = if :active in keys, do: [{:active, data.active} | values], else: values
        reply(from, {:ok, values})

      error ->
        reply(from, error)
    end
  end

  defp connected_call(from, {:getstat, :all}, _name, data),
    do: reply(from, :inet.getstat(data.tcp))

  defp connected_call(from, {:getstat, keys}, _name, data) when is_list(keys),
    do: reply(from, :inet.getstat(data.tcp, keys))

  defp connected_call(from, {:shutdown, how}, :connected, data)
       when how in [:read, :write, :read_write] do
    cond do
      how == :read ->
        reply(from, :gen_tcp.shutdown(data.tcp, how))

      # close_notify and the TCP shutdown follow the writes already queued.
      not :queue.is_empty(data.jobs) ->
        bytes = if data.write_closed, do: [], else: alert_record(data, 1, 0)
        {:keep_state, enqueue(%{data | write_closed: true}, {:shutdown, how}, from, bytes)}

      true ->
        data = close_notify(data)
        {:keep_state, data, [{:reply, from, :gen_tcp.shutdown(data.tcp, how)}]}
    end
  end

  # The reservation is gone (consumed, or the connection was reset): not an unsupported call.
  defp connected_call(from, {:send, _token, _cursor, _size}, :connected, _data),
    do: reply(from, {:error, :closed})

  defp connected_call(from, _request, :closing, _data), do: reply(from, {:error, :closed})
  defp connected_call(from, _request, _name, _data), do: reply(from, {:error, :enotsup})

  ## Record processing

  defp process(name, records, data, actions \\ [])
  defp process(name, [], data, actions), do: continue(name, data, actions)

  defp process(name, [record | rest], data, actions) do
    case record(name, record, data) do
      {:ok, next, data} -> process(next, rest, data, actions)
      {:ok, next, data, more} -> process(next, rest, data, actions ++ more)
      {:peer_closed, data} -> peer_closed(data, actions)
      {:error, reason, data} -> fail(name, reason, data)
    end
  end

  # RFC 8446 §5: one middlebox-compatibility change_cipher_spec after the first ClientHello.
  defp record(name, @ccs, %{ccs_received: false, core: core} = data)
       when name in @handshaking and not is_nil(core),
       do: {:ok, name, %{data | ccs_received: true}}

  defp record(name, <<21, 3, _minor, _length::16, payload::binary>>, data)
       when name in @handshaking,
       do: peer_alert(payload, data)

  defp record(:hello, <<22, 3, minor, _::16, payload::binary>>, data) when minor in 1..3 do
    limit = [
      max_handshake_length: min(data.config.limits[:max_handshake_length], @max_client_hello)
    ]

    case HandshakeFramer.feed(data.framer, payload, limit) do
      {:ok, [], framer} ->
        {:ok, :hello, %{data | framer: framer}}

      {:ok, [<<1, _::binary>> = hello], framer} ->
        if HandshakeFramer.buffered_size(framer) == 0,
          do: client_hello(hello, %{data | framer: framer}),
          else: unexpected(:handshake_after_client_hello, data)

      {:ok, _messages, _framer} ->
        unexpected(:expected_client_hello, data)

      {:error, reason} ->
        {:error, {:alert, :decode_error, reason}, data}
    end
  end

  # RFC 8446 §4.2.10: after a HelloRetryRequest, early data offered in the first
  # ClientHello is skipped by its outer application_data type.
  defp record(:hello, <<23, _::binary>> = record, %{core: %{phase: :retry}} = data),
    do: skip_early_data(:hello, record, data)

  defp record(name, <<23, _::binary>> = record, data) when name in @client_flight do
    case Record.decrypt(data.read, record) do
      {:error, :authentication_failed} -> skip_early_data(name, record, data)
      {:error, reason} -> {:error, record_alert(reason), data}
      {:ok, type, bytes, read} -> client_record(name, type, bytes, %{data | early_data: 0}, read)
    end
  end

  defp record(:connected, <<23, _::binary>> = record, data) do
    case decrypt(data, record) do
      # RFC 8446 §5.1: handshake fragments must not interleave with other record types.
      {:ok, type, _bytes, _read} = ok when type in [:application_data, :alert] ->
        if HandshakeFramer.buffered_size(data.framer) == 0,
          do: connected_record(ok, data),
          else: unexpected(:handshake_interleaved, data)

      other ->
        connected_record(other, data)
    end
  end

  # Records after a peer close_notify are discarded.
  defp record(:closing, _record, data), do: {:ok, :closing, data}
  defp record(_name, _record, data), do: unexpected(:unexpected_record, data)

  defp connected_record(result, data) do
    case result do
      {:ok, :application_data, bytes, read} ->
        buffer(%{data | read: read}, bytes)

      {:ok, :alert, <<1, 0>>, read} ->
        {:peer_closed, %{data | read: read}}

      {:ok, :alert, <<1, 90>>, read} ->
        {:ok, :connected, %{data | read: read}}

      {:ok, :alert, payload, _read} ->
        peer_alert(payload, data)

      {:ok, :handshake, bytes, read} ->
        post_handshake(%{data | read: read}, bytes)

      {:error, reason, data} ->
        {:error, reason, data}
    end
  end

  defp client_record(name, :handshake, bytes, data, read),
    do: client_flight(name, bytes, %{data | read: read})

  defp client_record(_name, :alert, payload, data, _read), do: peer_alert(payload, data)

  defp client_record(_name, type, _bytes, data, _read),
    do: unexpected({:unexpected_inner_content_type, type}, data)

  # Rejected early data is skipped only while the client offered it, no record
  # has yet decrypted under the handshake key, and the budget allows it.
  defp skip_early_data(name, <<_type, _version::16, length::16, _::binary>>, data)
       when data.early_data > 0 and data.early_records < @max_early_records and
              length - @record_overhead <= data.early_data do
    {:ok, name,
     %{
       data
       | early_data: data.early_data - max(length - @record_overhead, 0),
         early_records: data.early_records + 1
     }}
  end

  defp skip_early_data(:hello, _record, data), do: unexpected(:unexpected_record, data)

  defp skip_early_data(_name, _record, data),
    do: {:error, record_alert(:authentication_failed), data}

  # RFC 8446 §6: an alert is exactly a level and a description byte.
  defp peer_alert(<<_level, description>>, data), do: {:error, {:peer_alert, description}, data}

  defp peer_alert(payload, data),
    do: {:error, {:alert, :decode_error, {:alert_length, byte_size(payload)}}, data}

  defp decrypt(data, record) do
    case Record.decrypt(data.read, record) do
      {:ok, _type, _bytes, _read} = ok -> ok
      {:error, reason} -> {:error, record_alert(reason), data}
    end
  end

  defp client_flight(name, bytes, data) do
    limit = [max_handshake_length: data.config.limits[:max_handshake_length]]

    case HandshakeFramer.feed(data.framer, bytes, limit) do
      {:ok, messages, framer} -> client_messages(name, messages, %{data | framer: framer})
      {:error, reason} -> {:error, {:alert, :decode_error, reason}, data}
    end
  end

  # Each message advances the client flight one step; Finished must end it
  # (RFC 8446 §5.1: no handshake bytes may follow it under the old key).
  defp client_messages(name, [], data), do: {:ok, name, data}

  defp client_messages(:client_finished, [<<20, _::binary>> = finished], data) do
    if HandshakeFramer.buffered_size(data.framer) == 0,
      do: verify_finished(finished, data),
      else: unexpected(:handshake_after_client_finished, data)
  end

  defp client_messages(:client_finished, _messages, data),
    do: unexpected(:expected_client_finished, data)

  defp client_messages(name, [message | rest], data) do
    result =
      if name == :client_certificate,
        do: ServerHandshake.accept_client_certificate(data.core, message),
        else: ServerHandshake.accept_client_certificate_verify(data.core, message)

    case result do
      {:ok, core} -> client_messages(client_state(core), rest, %{data | core: core})
      {:error, {alert, reason}} -> {:error, alert(alert, reason), data}
    end
  end

  defp client_state(%{phase: :client_certificate}), do: :client_certificate
  defp client_state(%{phase: :client_certificate_verify}), do: :client_certificate_verify
  defp client_state(%{phase: :finished}), do: :client_finished

  defp verify_finished(finished, data) do
    with :ok <- ServerHandshake.finish(data.core, finished),
         {:ok, read} <- KeySchedule.traffic_state(data.read.cipher_suite, data.client_secret) do
      :gen_statem.reply(data.handshake_from, {:ok, data.socket})

      peercert = if data.core.peer, do: data.core.peer.leaf_der
      {writer, writer_monitor} = ConnectionWriter.start(self())

      {:ok, :connected,
       %{
         data
         | read: read,
           writer: writer,
           writer_monitor: writer_monitor,
           core: nil,
           client_secret: nil,
           handshake_from: nil,
           peercert: peercert
       }, [{{:timeout, :handshake}, :cancel}]}
    else
      {:error, {alert, reason}} -> {:error, alert(alert, reason), data}
      {:error, reason} -> {:error, alert(:internal_error, reason), data}
    end
  end

  defp client_hello(hello, data) do
    case select_identity(hello, data) do
      {:ok, data} -> accept_hello(hello, data)
      {:error, :timeout} -> {:error, :timeout, data}
      {:error, {alert, reason}} -> {:error, alert(alert, reason), data}
    end
  end

  # The identity is chosen once from the first ClientHello; a retried hello keeps
  # its server_name (RFC 8446 §4.1.2). An unparsable hello is left to accept_hello.
  defp select_identity(_hello, %{core: core} = data) when not is_nil(core), do: {:ok, data}

  defp select_identity(hello, data) do
    case ClientOffer.from_client_hello(hello) do
      {:ok, offer} ->
        selection = [
          signature_schemes: offer.signature_schemes,
          certificate_signature_schemes: offer.certificate_signature_schemes,
          timeout: Options.remaining(data.deadline)
        ]

        with {:ok, config} <-
               ServerOptions.select_identity(
                 data.config,
                 ClientOffer.server_name(offer),
                 selection
               ),
             do: {:ok, %{data | config: config}}

      {:error, _reason} ->
        {:ok, data}
    end
  end

  defp accept_hello(hello, data) do
    case ServerHandshake.accept_hello(data.config, hello, data.core) do
      {:retry, core, retry} ->
        bytes = [plaintext(retry), compat_ccs(core, data)]

        with :ok <- transmit(data, bytes),
             do: {:ok, :hello, %{data | core: core, ccs_sent: true, early_data: early_data(core)}}

      {:ok, core} ->
        server_flight(core, %{data | early_data: early_data(core)})

      {:error, {alert, reason}} ->
        {:error, alert(alert, reason), data}
    end
  end

  defp server_flight(core, data) do
    spec = Capabilities.resolve(:cipher_suite, core.suite)
    group = Capabilities.resolve(:group, core.group).name

    with {:ok, pair} <- KeyExchange.generate(group),
         {:ok, core, hello, messages} <-
           ServerHandshake.flight(core, data.config, pair, :crypto.strong_rand_bytes(32)),
         {:ok, handshake_write} <-
           KeySchedule.traffic_state(spec.name, core.secrets.server_handshake_secret),
         {:ok, read} <-
           KeySchedule.traffic_state(spec.name, core.secrets.client_handshake_secret),
         {:ok, write} <- KeySchedule.traffic_state(spec.name, core.application_secrets.server),
         {:ok, flight} <- protect(handshake_write, :handshake, IO.iodata_to_binary(messages)),
         :ok <- transmit(data, [plaintext(hello), compat_ccs(core, data), flight]) do
      {:ok, client_state(core),
       %{
         data
         | core: %{
             core
             | application_secrets: nil,
               secrets: Map.take(core.secrets, [:hash, :client_handshake_secret])
           },
           read: read,
           write: write,
           client_secret: core.application_secrets.client,
           suite: core.suite,
           alpn: core.alpn,
           ccs_sent: true,
           framer: HandshakeFramer.new()
       }}
    else
      {:error, _reason, _data} = error -> error
      {:error, {alert, reason}} when is_atom(alert) -> {:error, alert(alert, reason), data}
      {:error, reason} -> {:error, alert(:internal_error, reason), data}
    end
  end

  # The server accepts no PSK, so an early_data offer is always rejected.
  defp early_data(core), do: if(42 in core.offer.extension_ids, do: @max_early_data, else: 0)

  defp compat_ccs(%{offer: %{legacy_session_id: id}}, %{ccs_sent: false}) when id != <<>>,
    do: @ccs

  defp compat_ccs(_core, _data), do: []

  # RFC 8446 §5.1/§4.6.3: a KeyUpdate ends its record; clients send no other post-handshake message.
  defp post_handshake(data, bytes) do
    case HandshakeFramer.feed(data.framer, bytes) do
      {:ok, [], framer} ->
        {:ok, :connected, %{data | framer: framer}}

      {:ok, [<<24, _::binary>> = message], framer} ->
        if HandshakeFramer.buffered_size(framer) == 0,
          do: key_update(message, %{data | framer: framer}),
          else: unexpected(:partial_message_after_key_update, data)

      {:ok, _messages, _framer} ->
        unexpected(:unsupported_post_handshake, data)

      {:error, reason} ->
        {:error, {:alert, :decode_error, reason}, data}
    end
  end

  # After close_notify the write side is closed, so a requested update gets no reply.
  defp key_update(message, data) do
    hash = Capabilities.resolve(:cipher_suite, data.suite).hash

    with {:ok, %ServerFlight.KeyUpdate{request_update: request?}, <<>>} <-
           ServerFlight.decode(message, hash: hash),
         {:ok, read} <- HandshakeMachine.update_traffic_state(data.read),
         {:ok, records, write} <-
           HandshakeMachine.maybe_update_write(data.write, request? and not data.write_closed) do
      # The reply KeyUpdate follows every record already protected under the old key.
      data = if records == [], do: data, else: enqueue(data, :control, nil, records)
      {:ok, :connected, %{data | read: read, write: write}}
    else
      {:error, {:fatal_alert, alert, reason}} -> {:error, alert(alert, reason), data}
      {:error, reason} -> {:error, {:alert, :decode_error, reason}, data}
      _ -> unexpected(:invalid_key_update, data)
    end
  end

  # Backpressure lives in arm?/2: the carrier is read only while the buffer is
  # below the cap (or a pending recv still needs bytes), so one carrier delivery
  # may overshoot it and memory stays bounded by the cap plus one carrier read.
  defp buffer(data, bytes),
    do:
      {:ok, :connected,
       %{data | buffer: :queue.in(bytes, data.buffer), size: data.size + byte_size(bytes)}}

  ## Delivery

  defp continue(name, data, actions \\ []) do
    {data, delivered} = deliver(data)
    actions = actions ++ delivered

    cond do
      data.closed and data.size == 0 and :queue.is_empty(data.jobs) ->
        notify_pending(data, {:error, data.close_reason})
        if data.active_terminal, do: send(data.owner, active_terminal(data))
        # stop_and_reply accepts only reply actions; pending timers die with the process.
        {:stop_and_reply, :normal, Enum.filter(actions, &match?({:reply, _, _}, &1)), data}

      arm?(name, data) ->
        case :inet.setopts(data.tcp, active: :once) do
          :ok -> {:next_state, name, %{data | armed: true}, actions}
          {:error, reason} -> fail(name, reason, data)
        end

      true ->
        {:next_state, name, data, actions}
    end
  end

  defp active_terminal(%{close_reason: :closed} = data), do: {:ssl_closed, data.socket}
  defp active_terminal(data), do: {:ssl_error, data.socket, data.close_reason}

  defp arm?(name, data) do
    data.tcp != nil and data.started and not data.armed and not data.closed and
      (name != :connected or data.recv != nil or data.size < @max_plaintext - @rearm_reserve)
  end

  defp deliver(%{recv: %{from: from, length: length}} = data)
       when (length == 0 and data.size > 0) or (length > 0 and data.size >= length) do
    {bytes, data} = take(data, if(length == 0, do: data.size, else: length))
    {%{data | recv: nil}, [{:reply, from, {:ok, bytes}}, {{:timeout, :recv}, :cancel}]}
  end

  # After the peer closed no more plaintext can arrive. An exact-length read the
  # buffer cannot satisfy times out at once and keeps the bytes; the terminal is
  # reported only once the buffer is drained (#158, #163).
  defp deliver(%{recv: %{from: from}, closed: true} = data) do
    result = if data.size > 0, do: {:error, :timeout}, else: {:error, data.close_reason}
    {%{data | recv: nil}, [{:reply, from, result}, {{:timeout, :recv}, :cancel}]}
  end

  # Bytes beyond `active_chunk_size` stay buffered, in order, for the next arm.
  defp deliver(%{recv: nil, active: :once, size: size} = data) when size > 0 do
    {bytes, data} = take(data, chunk_length(size, data.active_chunk_size))
    send(data.owner, {:ssl, data.socket, bytes})
    {%{data | active: false}, []}
  end

  defp deliver(data), do: {data, []}

  defp chunk_length(size, :infinity), do: size
  defp chunk_length(size, limit), do: min(size, limit)

  defp take(data, length) do
    {bytes, buffer} = take(data.buffer, length, [])
    {bytes, %{data | buffer: buffer, size: data.size - length}}
  end

  defp take(buffer, 0, acc), do: {IO.iodata_to_binary(Enum.reverse(acc)), buffer}

  defp take(buffer, length, acc) do
    {{:value, chunk}, buffer} = :queue.out(buffer)

    if byte_size(chunk) <= length do
      take(buffer, length - byte_size(chunk), [chunk | acc])
    else
      <<head::binary-size(^length), tail::binary>> = chunk
      {IO.iodata_to_binary(Enum.reverse([head | acc])), :queue.in_r(tail, buffer)}
    end
  end

  ## Output

  # Post-handshake writes are queued to the writer in protection order, so records,
  # KeyUpdates and close_notify reach the carrier in sequence-number order.
  defp enqueue(data, kind, from, iodata) do
    token = make_ref()
    send(data.writer, {:send, token, data.tcp, iodata, false})
    %{data | jobs: :queue.in(%{token: token, kind: kind, from: from}, data.jobs)}
  end

  defp writing?(data), do: Enum.any?(:queue.to_list(data.jobs), &(&1.kind == :application))

  # After a transport terminal the writer settles its own job; the carrier closes
  # once no job remains, and buffered plaintext stays deliverable meanwhile.
  defp job_done(name, job, result, %{closed: true} = data) do
    actions = settle(job, settled_result(result, data))
    data = if :queue.is_empty(data.jobs), do: close_transport(data), else: data
    {data, granted} = grant_waiters(data)
    continue(name, data, actions ++ granted)
  end

  defp job_done(name, job, :ok, data) do
    {data, granted} = grant_waiters(data)
    continue(name, data, settle(job, job_result(job, data)) ++ granted)
  end

  defp job_done(name, job, {:error, reason}, data),
    do: job_failed(name, reason, %{data | jobs: :queue.in_r(job, data.jobs)})

  defp job_result(%{kind: {:shutdown, how}}, data), do: :gen_tcp.shutdown(data.tcp, how)
  defp job_result(_job, _data), do: :ok

  # A failed or expired job ends the connection like any transport write failure.
  defp job_failed(name, reason, %{closed: true} = data) do
    data = abort_output(data, {:error, reason}) |> close_transport()
    continue(name, data)
  end

  defp job_failed(name, reason, data), do: fail(name, reason, data)

  defp settle(%{from: nil}, _result), do: []

  defp settle(%{kind: :application, from: from}, result),
    do: [{:reply, from, result}, {{:timeout, :write}, :cancel}]

  defp settle(%{from: from}, result), do: [{:reply, from, result}]

  @dead_transport [:closed, :enotconn, :epipe, :econnreset]
  defp settled_result({:error, reason}, data) when reason in @dead_transport,
    do: {:error, data.close_reason}

  defp settled_result(result, _data), do: result

  # Replies to every queued job and reservation; the in-flight output is
  # uncertain, so the carrier later closes with zero linger.
  defp abort_output(data, result) do
    Enum.each(:queue.to_list(data.jobs), fn job -> settle_reply(job, result) end)
    Enum.each(:queue.to_list(data.waiters), fn {from, _} -> :gen_statem.reply(from, result) end)
    aborted = data.output_aborted or not :queue.is_empty(data.jobs)

    %{
      data
      | jobs: :queue.new(),
        waiters: :queue.new(),
        output_aborted: aborted,
        write_closed: true
    }
  end

  defp settle_reply(%{from: nil}, _result), do: :ok
  defp settle_reply(%{from: from}, result), do: :gen_statem.reply(from, result)

  defp grant(from, deadline, data) do
    token = make_ref()
    write_token = %{token: token, owner: elem(from, 0), deadline: deadline}
    {%{data | write_token: write_token}, [{:reply, from, {:ok, token}}]}
  end

  # Waiters are answered in order as their reservation would have been then: the
  # first live one gets the write, later ones see it reserved (:busy).
  defp grant_waiters(data, actions \\ []) do
    case :queue.out(data.waiters) do
      {:empty, _} ->
        {data, Enum.reverse(actions)}

      {{:value, {{pid, _} = from, deadline}}, waiters} ->
        data = %{data | waiters: waiters}

        cond do
          not Process.alive?(pid) ->
            grant_waiters(data, actions)

          data.closed or data.write_closed ->
            grant_waiters(data, [{:reply, from, {:error, :closed}} | actions])

          data.write_token != nil and Process.alive?(data.write_token.owner) ->
            grant_waiters(data, [{:reply, from, {:error, :busy}} | actions])

          deadline != :infinity and Options.remaining(deadline) == 0 ->
            grant_waiters(data, [{:reply, from, {:error, :timeout}} | actions])

          true ->
            {data, granted} = grant(from, deadline, data)
            grant_waiters(data, granted ++ actions)
        end
    end
  end

  defp protect_application(write, cursor, acc) do
    case IodataCursor.next(cursor, @max_fragment) do
      :done ->
        {:ok, Enum.reverse(acc), write}

      {:ok, chunk, cursor} ->
        update? = TrafficState.key_update_required?(write)

        with {:ok, updates, write} <- HandshakeMachine.maybe_update_write(write, update?),
             {:ok, record, write} <- Record.encrypt(write, :application_data, chunk) do
          protect_application(write, cursor, [record, updates | acc])
        end
    end
  end

  # The handshake deadline shortens the carrier send_timeout for a flight write.
  defp bounded_send(tcp, iodata, :infinity), do: :gen_tcp.send(tcp, iodata)

  defp bounded_send(tcp, iodata, deadline) do
    with {:ok, [send_timeout: previous]} <- :inet.getopts(tcp, [:send_timeout]),
         remaining = Options.remaining(deadline),
         :ok <- :inet.setopts(tcp, send_timeout: min_timeout(previous, remaining)),
         :ok <- :gen_tcp.send(tcp, iodata) do
      :inet.setopts(tcp, send_timeout: previous)
    end
  end

  defp min_timeout(:infinity, remaining), do: remaining
  defp min_timeout(previous, remaining), do: min(previous, remaining)

  defp protect(write, type, bytes) do
    with {:ok, records, _write} <- fragments(write, type, bytes, []), do: {:ok, records}
  end

  defp fragments(write, _type, <<>>, acc), do: {:ok, Enum.reverse(acc), write}

  defp fragments(write, type, bytes, acc) do
    size = min(byte_size(bytes), @max_fragment)
    <<chunk::binary-size(^size), rest::binary>> = bytes

    with {:ok, record, write} <- Record.encrypt(write, type, chunk),
         do: fragments(write, type, rest, [record | acc])
  end

  defp plaintext(<<>>), do: []

  defp plaintext(bytes) do
    size = min(byte_size(bytes), @max_fragment)
    <<chunk::binary-size(^size), rest::binary>> = bytes
    [<<22, 3, 3, size::16>>, chunk | plaintext(rest)]
  end

  # While the handshake is pending its deadline also bounds the write, even when
  # the carrier send_timeout is :infinity and the client never reads.
  defp transmit(data, iodata) do
    deadline = if data.handshake_from, do: data.deadline, else: :infinity

    case bounded_send(data.tcp, iodata, deadline) do
      :ok -> :ok
      {:error, reason} -> {:error, reason, data}
    end
  end

  defp close_notify(%{write_closed: true} = data), do: data
  defp close_notify(%{tcp: nil} = data), do: data

  # Behind a queued (uncertain) write no alert is sent; the carrier is aborted.
  defp close_notify(data) do
    _ = send_alert(data, 1, 0)
    %{data | write_closed: true}
  end

  defp send_alert(%{tcp: nil}, _level, _code), do: :ok

  defp send_alert(data, level, code) do
    if :queue.is_empty(data.jobs),
      do: :gen_tcp.send(data.tcp, alert_record(data, level, code)),
      else: :ok
  end

  defp alert_record(%{write: nil}, level, code), do: <<21, 3, 3, 2::16, level, code>>

  # Alerts are best effort, as before: a write state that cannot protect one sends nothing.
  defp alert_record(data, level, code) do
    case Record.encrypt(data.write, :alert, <<level, code>>) do
      {:ok, record, _write} -> record
      {:error, _reason} -> []
    end
  end

  ## Termination

  # As on the client, a write still queued when the peer closes settles as
  # {:error, :closed}; buffered plaintext stays deliverable.
  defp peer_closed(data, actions) do
    Socket.mark_terminal(data.socket, true)
    data = data |> close_notify() |> abort_output({:error, :closed}) |> close_transport()
    continue(:closing, %{data | closed: true}, actions)
  end

  # A transport terminal stops new writes; a queued job settles from the writer.
  defp transport_closed(data) do
    data = %{data | closed: true, write_closed: true}
    if :queue.is_empty(data.jobs), do: close_transport(data), else: data
  end

  defp fail(_name, reason, data) do
    {public, data} = failure(reason, data)
    notify_pending(data, {:error, public})
    if data.active_terminal, do: send(data.owner, {:ssl_error, data.socket, public})
    {:stop, :normal, data}
  end

  defp fail_reply(from, reason, data) do
    {public, data} = failure(reason, data)
    notify_pending(data, {:error, public})
    {:stop_and_reply, :normal, [{:reply, from, {:error, public}}], data}
  end

  defp failure({:alert, alert, reason}, data) do
    _ = if data.write_closed, do: :ok, else: send_alert(data, 2, Map.fetch!(@alerts, alert))
    description = ~c"TLS server: " ++ String.to_charlist(inspect(reason, limit: 8))
    {{:tls_alert, {alert, description}}, %{data | write_closed: true}}
  end

  defp failure({:peer_alert, code}, data),
    do:
      {{:tls_alert, {Map.get(@alert_names, code, :handshake_failure), ~c"Peer terminated TLS"}},
       data}

  defp failure(reason, data), do: {reason, data}

  defp notify_pending(data, result) do
    if data.handshake_from, do: :gen_statem.reply(data.handshake_from, result)
    if data.recv, do: :gen_statem.reply(data.recv.from, result)
    Enum.each(:queue.to_list(data.jobs), &settle_reply(&1, result))
    Enum.each(:queue.to_list(data.waiters), fn {from, _} -> :gen_statem.reply(from, result) end)
  end

  defp close_transport(%{tcp: nil} = data), do: data

  # :gen_tcp.close/1 waits for unsent driver output, so a peer that does not read
  # would hold this process; Port.close/1 leaves the flush to the driver. Output
  # left uncertain by an abort is discarded with zero linger instead.
  defp close_transport(data) do
    _ =
      if data.output_aborted or not :queue.is_empty(data.jobs),
        do: :inet.setopts(data.tcp, linger: {true, 0})

    try do
      Port.close(data.tcp)
    rescue
      ArgumentError -> :ok
    end

    %{data | tcp: nil, armed: false}
  end

  ## Helpers

  defp carrier_setopts(_tcp, []), do: :ok
  defp carrier_setopts(nil, _options), do: {:error, :closed}
  defp carrier_setopts(tcp, options), do: :inet.setopts(tcp, options)

  defp alert(alert, reason) when is_map_key(@alerts, alert), do: {:alert, alert, reason}
  defp alert(alert, reason), do: {:alert, :internal_error, {alert, reason}}

  defp unexpected(reason, data), do: {:error, {:alert, :unexpected_message, reason}, data}

  defp record_alert(reason) when reason in [:authentication_failed, :decryption_failed],
    do: {:alert, :bad_record_mac, reason}

  defp record_alert({:record_length_exceeded, _, _} = reason),
    do: {:alert, :record_overflow, reason}

  defp record_alert(reason), do: {:alert, :decode_error, reason}

  defp reply(from, result), do: {:keep_state_and_data, [{:reply, from, result}]}
end
