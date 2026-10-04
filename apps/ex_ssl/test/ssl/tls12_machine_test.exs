defmodule SSL.TLS12MachineTest do
  use ExUnit.Case, async: false
  alias SSL.Protocol.{ClientOffer, TLS12}

  @tag :integration
  test "configured OTP TLS 1.2 reference peer without EMS is rejected explicitly" do
    dir = Path.join(System.tmp_dir!(), "tls12-machine-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(dir) end)
    fixtures = ExSSL.TestSupport.ClientAuthFixtures.create(dir)

    {:ok, listener} =
      :ssl.listen(0,
        certfile: String.to_charlist(fixtures.server.certificate),
        keyfile: String.to_charlist(fixtures.server.key),
        versions: [:"tlsv1.2"],
        active: false,
        mode: :binary,
        reuseaddr: true
      )

    on_exit(fn -> :ssl.close(listener) end)
    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, transport} = :ssl.transport_accept(listener, 5_000)
        assert {:error, _} = :ssl.handshake(transport, 5_000)
      end)

    {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)
    hello = hello()
    {:ok, offer} = ClientOffer.from_client_hello(hello)
    {:ok, state} = TLS12.new(hello, offer, [fixtures.ca.der], {:dns_id, "exssl.test"}, [])
    :ok = :gen_tcp.send(tcp, <<22, 3, 3, byte_size(hello)::16, hello::binary>>)
    {:ok, <<type, major, minor, len::16>>} = :gen_tcp.recv(tcp, 5, 5_000)
    {:ok, payload} = :gen_tcp.recv(tcp, len, 5_000)
    assert {:ok, %{extensions: extensions}} = SSL.Protocol.TLS12Codec.decode(payload)
    refute {23, <<>>} in extensions

    assert {:error, {:fatal_alert, :handshake_failure, :extended_master_secret_required}} =
             TLS12.feed(state, <<type, major, minor, len::16, payload::binary>>)

    :gen_tcp.close(tcp)
    Task.await(peer, 5_000)
  end

  @tag :integration
  test "independent TLS1.2 engine authenticates OpenSSL ECDHE RSA with EMS" do
    dir = Path.join(System.tmp_dir!(), "tls12-openssl-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(dir) end)
    fixtures = ExSSL.TestSupport.ClientAuthFixtures.create(dir)
    {:ok, reservation} = :gen_tcp.listen(0, [:binary, active: false])
    {:ok, {_, port}} = :inet.sockname(reservation)
    :gen_tcp.close(reservation)

    handle =
      Port.open(
        {:spawn_executable, System.find_executable("openssl")},
        [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          args: [
            "s_server",
            "-accept",
            "127.0.0.1:#{port}",
            "-cert",
            fixtures.server.certificate,
            "-key",
            fixtures.server.key,
            "-tls1_2",
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "-www",
            "-quiet"
          ]
        ]
      )

    try do
      tcp = connect_ready(port, System.monotonic_time(:millisecond) + 5_000)

      try do
        hello = hello()
        {:ok, offer} = ClientOffer.from_client_hello(hello)
        {:ok, state} = TLS12.new(hello, offer, [fixtures.ca.der], {:dns_id, "exssl.test"}, [])
        :ok = :gen_tcp.send(tcp, <<22, 3, 3, byte_size(hello)::16, hello::binary>>)
        {state, []} = drive(tcp, state, :connected)
        {:ok, wire, state} = TLS12.encrypt(state, :application_data, "GET / HTTP/1.0\r\n\r\n")
        :ok = :gen_tcp.send(tcp, wire)
        {_state, [data]} = drive(tcp, state, :data)
        assert data =~ "HTTP/1.0 200"
      after
        :gen_tcp.close(tcp)
      end
    after
      ExSSL.TestSupport.LocalTLSPeer.stop_openssl(%{port_handle: handle})
    end
  end

  defp connect_ready(port, deadline) do
    case :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 100) do
      {:ok, tcp} ->
        tcp

      {:error, :econnrefused} ->
        if System.monotonic_time(:millisecond) >= deadline, do: flunk("OpenSSL startup timeout")

        receive do
        after
          10 -> :ok
        end

        connect_ready(port, deadline)
    end
  end

  defp drive(tcp, state, target) do
    {:ok, <<type, major, minor, len::16>>} = :gen_tcp.recv(tcp, 5, 5_000)
    {:ok, payload} = :gen_tcp.recv(tcp, len, 5_000)

    assert {:ok, next, outbound, events} =
             TLS12.feed(state, <<type, major, minor, len::16, payload::binary>>)

    :ok = :gen_tcp.send(tcp, outbound)
    data = for {:application_data, bytes} <- events, do: bytes

    if (target == :connected and Enum.any?(events, &match?({:connected, _}, &1))) or data != [],
      do: {next, data},
      else: drive(tcp, next, target)
  end

  defp hello do
    extensions =
      [
        {43, <<2, 3, 3>>},
        {10, <<4::16, 0x0017::16, 0x001D::16>>},
        {11, <<1, 0>>},
        {13, <<4::16, 0x0804::16, 0x0403::16>>},
        {23, <<>>},
        {0xFF01, <<0>>}
      ]
      |> Enum.map(fn {id, bytes} -> <<id::16, byte_size(bytes)::16, bytes::binary>> end)
      |> IO.iodata_to_binary()

    body =
      <<3, 3, :crypto.strong_rand_bytes(32)::binary, 0, 2::16, 0xC02F::16, 1, 0,
        byte_size(extensions)::16, extensions::binary>>

    <<1, byte_size(body)::24, body::binary>>
  end
end
