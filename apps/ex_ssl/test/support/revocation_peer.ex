defmodule ExSSL.TestSupport.RevocationPeer do
  @moduledoc false
  alias ExSSL.TestSupport.RevocationFixtures

  def start(directory, version, extra \\ []) do
    {:ok, reservation} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(reservation)
    :ok = :gen_tcp.close(reservation)
    {executable, prefix} = RevocationFixtures.openssl()

    args =
      prefix ++
        [
          "s_server",
          "-accept",
          "127.0.0.1:#{port}",
          "-cert",
          "leaf.pem",
          "-cert_chain",
          "intermediate.pem",
          "-key",
          "leaf-key.pem",
          "-WWW",
          "-naccept",
          "1",
          "-no_ticket",
          "-cipher",
          "ECDHE-RSA-AES128-GCM-SHA256",
          if(version == :"tlsv1.2", do: "-tls1_2", else: "-tls1_3")
        ] ++ extra

    handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 16_384},
        args: args,
        cd: directory
      ])

    {:os_pid, pid} = Port.info(handle, :os_pid)
    peer = %{handle: handle, os_pid: pid, port: port}
    IO.puts(JSON.encode!(%{peer_started: %{pid: pid, argv: [executable | args]}}))

    case ready(handle, 128) do
      :ok ->
        peer

      error ->
        stop(peer)
        raise "revocation peer startup failed: #{inspect(error)}"
    end
  end

  def start_tls13(directory, options \\ []) do
    {:ok, listener} =
      :gen_tcp.listen(Keyword.get(options, :port, 0), [
        :binary,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        Process.flag(:sensitive, true)

        try do
          case :gen_tcp.accept(listener, 5_000) do
            {:ok, socket} ->
              try do
                __MODULE__.TLS13.run(socket, directory, options)
              after
                :gen_tcp.close(socket)
              end

            _ ->
              {:error, :peer_accept_failed}
          end
        after
          :gen_tcp.close(listener)
        end
      end)

    %{task: task, listener: listener, port: port}
  end

  def start_tls12(directory, options \\ []) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        Process.flag(:sensitive, true)

        try do
          case :gen_tcp.accept(listener, 5_000) do
            {:ok, socket} ->
              try do
                __MODULE__.TLS12.run(socket, directory, options)
              after
                :gen_tcp.close(socket)
              end

            _ ->
              {:error, :peer_accept_failed}
          end
        after
          :gen_tcp.close(listener)
        end
      end)

    %{task: task, listener: listener, port: port}
  end

  def join_tls13(%{task: task}), do: Task.await(task, 5_000)

  def stop(%{task: task, listener: listener}) do
    _ = if Process.alive?(task.pid), do: Task.shutdown(task, :brutal_kill)
    :gen_tcp.close(listener)
    :ok
  end

  def stop(%{handle: handle, os_pid: pid}) do
    case Port.info(handle, :os_pid) do
      {:os_pid, ^pid} ->
        # The bounded -naccept peer can exit between Port.info and kill. Its
        # exit_status message remains the join regardless of that race.
        _ = System.cmd("/bin/kill", ["-TERM", Integer.to_string(pid)], stderr_to_stdout: true)

        receive do
          {^handle, {:exit_status, _}} -> :ok
        after
          2_000 -> raise "revocation peer failed to stop"
        end

      nil ->
        :ok
    end

    IO.puts(JSON.encode!(%{peer_joined: %{pid: pid}}))
    :ok
  end

  def await_exit(%{handle: handle, os_pid: pid}, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    case await_exit_status(handle, deadline, 256) do
      0 ->
        IO.puts(JSON.encode!(%{peer_exited_before_drain: %{pid: pid, status: 0}}))
        :ok

      _ ->
        raise "revocation peer did not exit successfully before application drain"
    end
  end

  defp await_exit_status(_handle, _deadline, 0), do: :line_limit

  defp await_exit_status(handle, deadline, left) do
    receive do
      {^handle, {:exit_status, status}} -> status
      {^handle, {:data, _}} -> await_exit_status(handle, deadline, left - 1)
    after
      max(0, deadline - System.monotonic_time(:millisecond)) -> :timeout
    end
  end

  def diagnostics(%{handle: handle}), do: diagnostics(handle, 128, [])
  defp diagnostics(_handle, 0, lines), do: Enum.reverse(lines)

  defp diagnostics(handle, left, lines) do
    receive do
      {^handle, {:data, {:eol, line}}} ->
        errors =
          if String.contains?(line, ["error:", "SSL routines", "unexpected eof", "alert"]),
            do: [line | lines],
            else: lines

        diagnostics(handle, left - 1, errors)

      {^handle, {:data, {:noeol, _}}} ->
        diagnostics(handle, left - 1, lines)
    after
      0 -> Enum.reverse(lines)
    end
  end

  defp ready(_, 0), do: {:error, :line_limit}

  defp ready(handle, left) do
    receive do
      {^handle, {:data, {:eol, "ACCEPT" <> _}}} -> :ok
      {^handle, {:data, {:eol, _}}} -> ready(handle, left - 1)
      {^handle, {:exit_status, status}} -> {:error, {:exit, status}}
      {^handle, {:data, {:noeol, _}}} -> {:error, :line_limit}
    after
      5_000 -> {:error, :startup_timeout}
    end
  end
end

defmodule ExSSL.TestSupport.RevocationPeer.TLS13 do
  @moduledoc false
  alias ExSSL.TestSupport.RevocationFixtures
  alias SSL.Crypto.{Finished, KeyExchange, KeySchedule, Signature}
  alias SSL.Protocol.{ClientOffer, HandshakeCore, Record, ServerFlight, Transcript}
  @hrr_random Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
  @suite :tls_aes_128_gcm_sha256

  # A TCP peer with real record epochs and actual ClientHello bytes. It does
  # not call the QUIC server adapter, which has different extension rules.
  def run(socket, directory, options) do
    Process.put(:constructed_peer_stage, :hello)
    hello = client_hello(socket, <<>>, 8)
    {:ok, first} = ClientOffer.from_client_hello(hello)
    transcript = Transcript.append(Transcript.new(:sha256), hello)

    {offer, transcript, retry_nonce?} =
      if options[:hrr] do
        retry =
          message(
            2,
            <<0x0303::16, @hrr_random::binary, byte_size(first.legacy_session_id),
              first.legacy_session_id::binary, 0x1301::16, 0,
              extensions([{43, <<0x0304::16>>}, {51, <<24::16>>}])::binary>>
          )

        :ok = :gen_tcp.send(socket, plaintext(22, retry))
        second_bytes = client_hello(socket, <<>>, 8)
        {:ok, second} = ClientOffer.from_client_hello(second_bytes)

        {second,
         transcript
         |> Transcript.apply_hello_retry_request_rewrite()
         |> Transcript.append(retry)
         |> Transcript.append(second_bytes), nonce(first) == nonce(second)}
      else
        {first, transcript, true}
      end

    group_id = if options[:hrr], do: 24, else: 29
    group = if options[:hrr], do: :secp384r1, else: :x25519
    %{key_exchange: public} = Enum.find(offer.key_shares, &(&1.group == group_id))
    {:ok, pair} = KeyExchange.generate(group)
    random = :crypto.strong_rand_bytes(32)

    server_hello =
      message(
        2,
        <<0x0303::16, random::binary, byte_size(offer.legacy_session_id),
          offer.legacy_session_id::binary, 0x1301::16, 0,
          extensions([
            {43, <<0x0304::16>>},
            {51, <<group_id::16, byte_size(pair.public_key)::16, pair.public_key::binary>>}
          ])::binary>>
      )

    transcript = Transcript.append(transcript, server_hello)
    {:ok, secrets} = HandshakeCore.derive_secrets(pair, public, @suite, transcript)
    ee = message(8, <<0::16>>)
    certificate = certificate(directory, offer, options)
    transcript = transcript |> Transcript.append(ee) |> Transcript.append(certificate)
    [key] = :public_key.pem_decode(File.read!(Path.join(directory, "leaf-key.pem")))
    private_key = :public_key.pem_entry_decode(key)

    {:ok, signature} =
      Signature.sign_server(0x0804, private_key, :sha256, Transcript.digest(transcript))

    signature =
      if options[:corrupt] == :cv, do: :binary.copy(<<0>>, byte_size(signature)), else: signature

    {:ok, cv} = ServerFlight.encode_client_certificate_verify(0x0804, signature)
    transcript = Transcript.append(transcript, cv)

    {:ok, verify_data} =
      Finished.client_verify_data(
        :sha256,
        secrets.server_handshake_secret,
        Transcript.digest(transcript)
      )

    verify_data = if options[:corrupt] == :finished, do: flip(verify_data), else: verify_data
    {:ok, finished} = ServerFlight.encode_finished(verify_data, hash: :sha256)
    transcript = Transcript.append(transcript, finished)
    {:ok, write} = KeySchedule.traffic_state(@suite, secrets.server_handshake_secret)

    messages =
      if options[:fragment],
        do: [ee] ++ split(certificate) ++ [cv, finished],
        else: [ee, certificate, cv, finished]

    messages = Enum.flat_map(messages, &record_chunks/1)

    {records, _} =
      Enum.map_reduce(messages, write, fn bytes, state ->
        {:ok, record, next} = Record.encrypt(state, :handshake, bytes)
        {record, next}
      end)

    records =
      if options[:corrupt] == :aead, do: List.update_at(records, -1, &flip/1), else: records

    Process.put(:constructed_peer_stage, :client_finished)
    compatibility = if offer.legacy_session_id == <<>>, do: [], else: [plaintext(20, <<1>>)]
    :ok = :gen_tcp.send(socket, [plaintext(22, server_hello), compatibility, records])
    {:ok, read} = KeySchedule.traffic_state(@suite, secrets.client_handshake_secret)

    result =
      case protected(socket, read, 8) do
        {:ok, :alert, <<_level, alert>>, _} ->
          {:rejected, alert}

        {:ok, :handshake, client_finished, _} ->
          {:ok, %ServerFlight.Finished{verify_data: received}, <<>>} =
            ServerFlight.decode(client_finished)

          :ok =
            Finished.verify_server(
              :sha256,
              secrets.client_handshake_secret,
              Transcript.digest(transcript),
              received
            )

          Process.put(:constructed_peer_stage, :application)

          {:ok, read_secret} =
            KeySchedule.client_application_traffic_secret(
              :sha256,
              secrets.master_secret,
              Transcript.digest(transcript)
            )

          {:ok, write_secret} =
            KeySchedule.server_application_traffic_secret(
              :sha256,
              secrets.master_secret,
              Transcript.digest(transcript)
            )

          {:ok, read} = KeySchedule.traffic_state(@suite, read_secret)
          {:ok, write} = KeySchedule.traffic_state(@suite, write_secret)

          write =
            if options[:ticket] do
              ticket = :crypto.strong_rand_bytes(32)

              payload =
                message(
                  4,
                  <<3_600::32, 49::32, 1, 0, byte_size(ticket)::16, ticket::binary, 0::16>>
                )

              {:ok, record, next} = Record.encrypt(write, :handshake, payload)
              :ok = :gen_tcp.send(socket, record)
              next
            else
              write
            end

          {:ok, :application_data, "R49 ping", _} = protected(socket, read, 8)
          {:ok, data, write} = Record.encrypt(write, :application_data, "R49 pong")

          if options[:abrupt] do
            :ok = :gen_tcp.send(socket, data)
          else
            {:ok, close, _} = Record.encrypt(write, :alert, <<1, 0>>)
            :ok = :gen_tcp.send(socket, [data, close])
          end

          :authenticated

        {:error, :closed} ->
          :client_closed
      end

    %{
      result: result,
      status_request_count: Enum.count(offer.extension_ids, &(&1 == 5)),
      nonce_present: nonce(offer) != nil,
      retry_nonce_unchanged: retry_nonce?,
      nonce_digest: if(nonce(offer), do: :crypto.hash(:sha256, nonce(offer))),
      key_share_digest: :crypto.hash(:sha256, public),
      sni_extension: List.keyfind(offer.extensions, 0, 0),
      extension_ids: offer.extension_ids
    }
  rescue
    exception -> {:error, Process.get(:constructed_peer_stage), exception.__struct__}
  catch
    _, _ -> {:error, Process.get(:constructed_peer_stage), :peer_fixture_failure}
  end

  defp certificate(directory, offer, options) do
    leaf = File.read!(Path.join(directory, "leaf.der"))

    intermediate =
      File.read!(
        Path.join(directory, Keyword.get(options, :intermediate, "intermediate") <> ".der")
      )

    good = File.read!(Path.join(RevocationFixtures.ocsp_directory!(), "good.ocsp"))
    issuer_good = File.read!(Path.join(RevocationFixtures.ocsp_directory!(), "wrong-target.ocsp"))
    issuer_good = Keyword.get(options, :issuer_response, issuer_good)
    good = Keyword.get(options, :response, good)
    good = if options[:echo_nonce], do: echo_nonce(good, nonce(offer), directory), else: good

    {leaf_extensions, intermediate_extensions} =
      case options[:placement] || :leaf do
        :leaf -> {[status(good)], []}
        :both -> {[status(good)], [status(issuer_good)]}
        :intermediate_only -> {[], [status(issuer_good)]}
        :swapped -> {[status(issuer_good)], [status(good)]}
        :duplicate -> {[status(good), status(good)], []}
        :malformed -> {[{5, <<1, 0::24>>}], []}
        :unsupported -> {[{5, <<2, byte_size(good)::24, good::binary>>}], []}
        :trailing -> {[{5, <<1, byte_size(good)::24, good::binary, 0>>}], []}
        :absent -> {[], []}
      end

    certificates = [
      {leaf, leaf_extensions}
      | List.duplicate(
          {intermediate, intermediate_extensions},
          Keyword.get(options, :chain_length, 2) - 1
        )
    ]

    entries =
      for {der, values} <- certificates,
          do: <<byte_size(der)::24, der::binary, extensions(values)::binary>>

    list = IO.iodata_to_binary(entries)
    message(11, <<0, byte_size(list)::24, list::binary>>)
  end

  def echo_nonce(response, nonce, directory) when is_binary(nonce) do
    {:OCSPResponse, :successful, {:ResponseBytes, oid, bytes}} =
      :public_key.der_decode(:OCSPResponse, response)

    {:BasicOCSPResponse, data, algorithm, _, certificates} =
      :public_key.der_decode(:BasicOCSPResponse, bytes)

    data = put_elem(data, 5, :public_key.ocsp_extensions(nonce))
    [entry] = :public_key.pem_decode(File.read!(Path.join(directory, "intermediate-key.pem")))

    signature =
      :public_key.sign(
        :public_key.der_encode(:ResponseData, data),
        :sha256,
        :public_key.pem_entry_decode(entry)
      )

    basic =
      :public_key.der_encode(
        :BasicOCSPResponse,
        {:BasicOCSPResponse, data, algorithm, signature, certificates}
      )

    :public_key.der_encode(
      :OCSPResponse,
      {:OCSPResponse, :successful, {:ResponseBytes, oid, basic}}
    )
  end

  def nonce(offer) do
    case List.keyfind(offer.extensions, 5, 0) do
      {5, <<1, 0::16, size::16, bytes::binary-size(size)>>} when size > 0 ->
        case Enum.find(:public_key.der_decode(:Extensions, bytes), fn {:Extension, oid, _, _} ->
               oid == {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
             end) do
          {:Extension, _, _, value} -> value
          _ -> nil
        end

      _ ->
        nil
    end
  end

  defp status(bytes), do: {5, <<1, byte_size(bytes)::24, bytes::binary>>}

  defp split(bytes) do
    size = div(byte_size(bytes), 2)
    <<first::binary-size(^size), second::binary>> = bytes
    [first, second]
  end

  defp flip(bytes) do
    size = byte_size(bytes) - 1
    <<prefix::binary-size(^size), last>> = bytes
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end

  defp record_chunks(bytes) when byte_size(bytes) <= 16_384, do: [bytes]

  defp record_chunks(<<part::binary-size(16_384), rest::binary>>),
    do: [part | record_chunks(rest)]

  defp message(type, bytes), do: <<type, byte_size(bytes)::24, bytes::binary>>
  defp plaintext(type, bytes), do: <<type, 0x0303::16, byte_size(bytes)::16, bytes::binary>>

  defp extensions(values) do
    bytes =
      IO.iodata_to_binary(
        for {id, value} <- values, do: <<id::16, byte_size(value)::16, value::binary>>
      )

    <<byte_size(bytes)::16, bytes::binary>>
  end

  defp client_hello(socket, buffer, left) when left > 0 and byte_size(buffer) <= 65_539 do
    case buffer do
      <<1, size::24, _::binary-size(size)>> ->
        buffer

      _ ->
        case record(socket) do
          {:ok, <<20, 0x0303::16, 1::16, 1>>} ->
            client_hello(socket, buffer, left - 1)

          {:ok, <<22, _version::16, _size::16, bytes::binary>>} ->
            client_hello(socket, buffer <> bytes, left - 1)
        end
    end
  end

  defp protected(socket, state, left) when left > 0 do
    case record(socket) do
      {:ok, <<20, 0x0303::16, 1::16, 1>>} -> protected(socket, state, left - 1)
      {:ok, bytes} -> Record.decrypt(state, bytes)
      error -> error
    end
  end

  defp record(socket) do
    with {:ok, <<_type, _version::16, size::16>> = header} when size <= 16_640 <-
           :gen_tcp.recv(socket, 5, 2_000),
         {:ok, bytes} <- :gen_tcp.recv(socket, size, 2_000),
         do: {:ok, header <> bytes}
  end
end

defmodule ExSSL.TestSupport.RevocationPeer.TLS12 do
  @moduledoc false
  alias ExSSL.TestSupport.RevocationPeer.TLS13

  alias ExSSL.TestSupport.RevocationFixtures
  alias SSL.Crypto.TLS12KeySchedule
  alias SSL.Protocol.{ClientOffer, TLS12Codec, TLS12Record}

  def run(socket, directory, options) do
    Process.put(:constructed_peer_stage, :hello)
    hello = hello(socket, <<>>, 8)
    Process.put(:constructed_peer_stage, :hello_parse)
    {:ok, offer} = ClientOffer.from_client_hello(hello)
    Process.put(:constructed_peer_stage, :hello_random)
    <<1, _::24, 3, 3, client_random::binary-size(32), _::binary>> = hello
    server_random = :crypto.strong_rand_bytes(32)
    Process.put(:constructed_peer_stage, :hello_cipher)
    true = 0xC02F in offer.cipher_suites
    Process.put(:constructed_peer_stage, :hello_ems)
    ems = 23 in offer.extension_ids
    true = ems or options[:legacy_master] == true
    Process.put(:constructed_peer_stage, :server_flight)
    status = Keyword.get(options, :status, :good)
    negotiated = status != :not_negotiated

    extensions = server_extensions(ems, negotiated)

    sh =
      message(
        2,
        <<3, 3, server_random::binary, 0, 0xC02F::16, 0, byte_size(extensions)::16,
          extensions::binary>>
      )

    leaf = File.read!(Path.join(directory, "leaf.der"))
    issuer = File.read!(Path.join(directory, "intermediate.der"))
    {:ok, certificate} = TLS12Codec.encode_certificate([leaf, issuer])

    response =
      Keyword.get_lazy(options, :response, fn ->
        File.read!(Path.join(RevocationFixtures.ocsp_directory!(), "good.ocsp"))
      end)

    nonce = TLS13.nonce(offer)

    response =
      if options[:echo_nonce],
        do: TLS13.echo_nonce(response, nonce, directory),
        else: response

    staple = message(22, <<1, byte_size(response)::24, response::binary>>)

    staple = status_message(status, response, staple)

    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    params = <<3, 23::16, byte_size(public), public::binary>>
    [entry] = :public_key.pem_decode(File.read!(Path.join(directory, "leaf-key.pem")))

    signature =
      :public_key.sign(
        client_random <> server_random <> params,
        :sha256,
        :public_key.pem_entry_decode(entry)
      )

    signature = if options[:corrupt] == :ske, do: flip(signature), else: signature
    ske = message(12, <<params::binary, 0x0401::16, byte_size(signature)::16, signature::binary>>)
    done = message(14, <<>>)

    flight = server_flight(status, sh, certificate, staple, ske, done)

    transcript = hello <> IO.iodata_to_binary(flight)
    Process.put(:constructed_peer_stage, :client_key_exchange)

    records = flight_records(options, flight)

    :ok = :gen_tcp.send(socket, records)

    result =
      case record(socket) do
        {:ok, 21, <<_level, alert>>, _} ->
          {:rejected, alert}

        {:ok, 22, <<16, _::24, size, client_public::binary-size(size)>> = exchange, _} ->
          transcript = transcript <> exchange
          premaster = :crypto.compute_key(:ecdh, client_public, private, :secp256r1)
          {:ok, secrets} = derive(ems, premaster, transcript, client_random, server_random)
          {:ok, 20, <<1>>, _} = record(socket)
          {:ok, 22, _, protected_finished} = record(socket)

          {:ok, :handshake, <<20, 12::24, client_verify::binary-size(12)>> = client_finished,
           read} = TLS12Record.decrypt(secrets.write_state, protected_finished)

          {:ok, ^client_verify} =
            TLS12KeySchedule.finished(0xC02F, secrets.master_secret, :client, transcript)

          transcript = transcript <> client_finished

          {:ok, server_verify} =
            TLS12KeySchedule.finished(0xC02F, secrets.master_secret, :server, transcript)

          server_verify =
            if options[:corrupt] == :finished, do: flip(server_verify), else: server_verify

          {:ok, encrypted, write} =
            TLS12Record.encrypt(secrets.read_state, :handshake, message(20, server_verify))

          encrypted = if options[:corrupt] == :aead, do: flip(encrypted), else: encrypted
          Process.put(:constructed_peer_stage, :application)
          :ok = :gen_tcp.send(socket, [plain(20, <<1>>), encrypted])

          case record(socket) do
            {:ok, _, _, wire} ->
              case TLS12Record.decrypt(read, wire) do
                {:ok, :alert, <<_, alert>>, _} ->
                  {:rejected, alert}

                {:ok, :application_data, "R49 ping", _} ->
                  {:ok, data, write} = TLS12Record.encrypt(write, :application_data, "R49 pong")
                  {:ok, close, _} = TLS12Record.encrypt(write, :alert, <<1, 0>>)
                  :ok = :gen_tcp.send(socket, [data, close])
                  :authenticated
              end

            {:error, :closed} ->
              :client_closed
          end

        {:error, :closed} ->
          :client_closed
      end

    %{
      result: result,
      status_request_count: Enum.count(offer.extension_ids, &(&1 == 5)),
      negotiated: negotiated,
      extended_master_secret: ems,
      transcript_includes_status: Enum.any?(flight, &match?(<<22, _::binary>>, &1)),
      sni_extension: List.keyfind(offer.extensions, 0, 0),
      extension_ids: offer.extension_ids,
      nonce_present: nonce != nil,
      nonce_digest: if(nonce, do: :crypto.hash(:sha256, nonce)),
      client_random_digest: :crypto.hash(:sha256, client_random)
    }
  rescue
    exception -> {:error, Process.get(:constructed_peer_stage), exception.__struct__}
  catch
    _, _ -> {:error, Process.get(:constructed_peer_stage), :peer_fixture_failure}
  end

  defp derive(true, premaster, transcript, client_random, server_random),
    do: TLS12KeySchedule.derive(0xC02F, premaster, transcript, client_random, server_random)

  # OTP28 reference does not offer EMS. This explicit test-only mode retains
  # its RFC5246 master secret; candidate tests still require negotiated EMS.
  defp derive(false, premaster, _transcript, client_random, server_random) do
    {:ok, master} =
      TLS12KeySchedule.prf(
        :sha256,
        premaster,
        "master secret",
        client_random <> server_random,
        48
      )

    {:ok,
     <<client_key::binary-size(16), server_key::binary-size(16), client_iv::binary-size(4),
       server_iv::binary-size(4)>>} =
      TLS12KeySchedule.prf(:sha256, master, "key expansion", server_random <> client_random, 40)

    {:ok, write} = TLS12Record.new(:aes_128_gcm, client_key, client_iv)
    {:ok, read} = TLS12Record.new(:aes_128_gcm, server_key, server_iv)
    {:ok, %{master_secret: master, read_state: read, write_state: write}}
  end

  defp hello(_socket, <<1, size::24, _body::binary-size(size)>> = bytes, _), do: bytes

  defp hello(socket, bytes, left) when left > 0 do
    {:ok, 22, more, _} = record(socket)
    hello(socket, bytes <> more, left - 1)
  end

  defp record(socket) do
    with {:ok, <<type, version::16, size::16>> = header} <- :gen_tcp.recv(socket, 5, 3_000),
         true <- version in [0x0301, 0x0303] and size > 0 and size <= 18_432,
         {:ok, body} <- :gen_tcp.recv(socket, size, 3_000) do
      {:ok, type, body, header <> body}
    end
  end

  defp record_chunks(bytes) when byte_size(bytes) <= 16_384, do: [bytes]

  defp record_chunks(<<part::binary-size(16_384), rest::binary>>),
    do: [part | record_chunks(rest)]

  defp message(type, bytes), do: <<type, byte_size(bytes)::24, bytes::binary>>
  defp plain(type, bytes), do: <<type, 3, 3, byte_size(bytes)::16, bytes::binary>>
  defp flip(<<head, rest::binary>>), do: <<Bitwise.bxor(head, 1), rest::binary>>

  defp status_message(status, response, staple) do
    case status do
      :unsupported -> message(22, <<2, byte_size(response)::24, response::binary>>)
      :zero -> message(22, <<1, 0::24>>)
      :truncated -> message(22, <<1, byte_size(response) + 1::24, response::binary>>)
      :trailing -> message(22, <<1, byte_size(response)::24, response::binary, 0>>)
      _ -> staple
    end
  end

  defp server_flight(status, sh, certificate, staple, ske, done) do
    case status do
      value when value in [:not_negotiated, :omitted] -> [sh, certificate, ske, done]
      :before_certificate -> [sh, staple, certificate, ske, done]
      :after_ske -> [sh, certificate, ske, staple, done]
      :duplicate -> [sh, certificate, staple, staple, ske, done]
      _ -> [sh, certificate, staple, ske, done]
    end
  end

  defp flight_records(options, flight) do
    if options[:fragment] do
      Enum.flat_map(flight, fn bytes ->
        size = div(byte_size(bytes), 2)
        <<first::binary-size(^size), second::binary>> = bytes
        Enum.map(record_chunks(first) ++ record_chunks(second), &plain(22, &1))
      end)
    else
      Enum.map(record_chunks(IO.iodata_to_binary(flight)), &plain(22, &1))
    end
  end

  defp server_extensions(ems, negotiated) do
    if(ems, do: <<23::16, 0::16>>, else: <<>>) <>
      <<0xFF01::16, 1::16, 0>> <> if(negotiated, do: <<5::16, 0::16>>, else: <<>>)
  end
end
