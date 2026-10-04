defmodule SSL.QUIC.Phase1ContractTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog

  @fixtures Path.expand("../fixtures/server_flight", __DIR__)

  defp der(name) do
    [{:Certificate, der, :not_encrypted}] =
      @fixtures |> Path.join(name) |> File.read!() |> :public_key.pem_decode()

    der
  end

  defp client_options(extra \\ []) do
    Keyword.merge(
      [
        cacerts: [der("root.pem")],
        reference_identity: {:dns_id, "example.test"},
        alpn: ["phase1"],
        transport_parameters: <<1, 0>>
      ],
      extra
    )
  end

  defp server_options(extra \\ []) do
    [{type, key, :not_encrypted}] =
      @fixtures |> Path.join("leaf-key.pem") |> File.read!() |> :public_key.pem_decode()

    Keyword.merge(
      [
        cert: [der("leaf.pem")],
        key: {type, key},
        alpn: ["phase1"],
        transport_parameters: <<2, 0>>
      ],
      extra
    )
  end

  test "public handshake actions preserve role authentication milestones and installation order" do
    assert {:ok, client, [{:emit, :initial, client_hello}]} =
             SSL.QUIC.new(:client, client_options())

    assert %{
             phase: :hello,
             receive_level: :initial,
             handshake_complete: false,
             peer_authenticated: false,
             peer_parameters_authenticated: false
           } = SSL.QUIC.info(client)

    assert {:ok, server, []} = SSL.QUIC.new(:server, server_options())
    assert {:ok, server, server_actions} = SSL.QUIC.feed(server, :initial, client_hello)

    assert [
             {:peer_transport_parameters, <<1, 0>>, :unverified},
             {:emit, :initial, <<2, _::binary>>},
             %SSL.QUIC.Secret{level: :handshake, direction: :read},
             %SSL.QUIC.Secret{level: :handshake, direction: :write},
             {:emit, :handshake, <<8, _::binary>>},
             {:emit, :handshake, <<11, _::binary>>},
             {:emit, :handshake, <<15, _::binary>>},
             {:emit, :handshake, <<20, _::binary>>},
             %SSL.QUIC.Secret{level: :application, direction: :write},
             %SSL.QUIC.Secret{level: :application, direction: :read}
           ] = server_actions

    assert %{
             phase: :client_finished,
             receive_level: :handshake,
             handshake_complete: false,
             peer_authenticated: false,
             peer_parameters_authenticated: false
           } = SSL.QUIC.info(server)

    [{:emit, :initial, server_hello}] =
      Enum.filter(server_actions, &match?({:emit, :initial, _}, &1))

    assert {:ok, client, client_hello_actions} = SSL.QUIC.feed(client, :initial, server_hello)

    assert [
             %SSL.QUIC.Secret{level: :handshake, direction: :read},
             %SSL.QUIC.Secret{level: :handshake, direction: :write}
           ] = client_hello_actions

    server_flight = for {:emit, :handshake, bytes} <- server_actions, into: <<>>, do: bytes
    assert {:ok, client, client_actions} = SSL.QUIC.feed(client, :handshake, server_flight)

    assert [
             {:peer_transport_parameters, <<2, 0>>, :unverified},
             %SSL.QUIC.Secret{level: :application, direction: :read},
             {:peer_authenticated, :server},
             {:peer_transport_parameters, <<2, 0>>, :authenticated},
             {:negotiated_alpn, "phase1"},
             {:emit, :handshake, <<20, _::binary>>},
             %SSL.QUIC.Secret{level: :application, direction: :write},
             :handshake_complete
           ] = client_actions

    assert %{
             phase: :connected,
             receive_level: :application,
             handshake_complete: true,
             peer_authenticated: true,
             peer_parameters_authenticated: true,
             alpn: "phase1"
           } =
             SSL.QUIC.info(client)

    [{:emit, :handshake, client_finished}] =
      Enum.filter(client_actions, &match?({:emit, :handshake, _}, &1))

    assert {:ok, server,
            [
              {:peer_transport_parameters, <<1, 0>>, :authenticated},
              {:negotiated_alpn, "phase1"},
              :handshake_complete
            ]} = SSL.QUIC.feed(server, :handshake, client_finished)

    assert %{
             phase: :connected,
             receive_level: :application,
             handshake_complete: true,
             peer_authenticated: false,
             peer_parameters_authenticated: true,
             alpn: "phase1"
           } =
             SSL.QUIC.info(server)
  end

  test "abort terminalizes either role before and after TLS completion without public secret disclosure" do
    for role <- [:client, :server] do
      options = if role == :client, do: client_options(), else: server_options()
      assert {:ok, state, _} = SSL.QUIC.new(role, options)
      aborted = SSL.QUIC.abort(state, :caller_cancelled)

      assert %{role: ^role, phase: :aborted, receive_level: nil, handshake_complete: false} =
               SSL.QUIC.info(aborted)

      assert {:error, %SSL.QUIC.Error{kind: :closed, reason: :terminal}, ^aborted, []} =
               SSL.QUIC.feed(aborted, :initial, <<>>)

      refute inspect(aborted) =~ "secret"
    end

    {client, server} = connected_pair()

    for {role, state} <- [client: client, server: server] do
      aborted = SSL.QUIC.abort(state, :caller_cancelled)

      assert %{role: ^role, phase: :aborted, receive_level: nil, handshake_complete: true} =
               SSL.QUIC.info(aborted)

      assert {:error, %SSL.QUIC.Error{kind: :closed, reason: :terminal}, ^aborted, []} =
               SSL.QUIC.feed(aborted, :application, <<>>)

      refute inspect(aborted) =~ "secret"
    end
  end

  test "public info and error inspection redact secrets while retaining stable classifications" do
    parameter_marker = "phase1-client-parameter-marker"
    identity_marker = "phase1-identity-marker.example"

    assert {:ok, client, _} =
             SSL.QUIC.new(
               :client,
               client_options(
                 transport_parameters: parameter_marker,
                 reference_identity: {:dns_id, identity_marker}
               )
             )

    assert %{role: :client, phase: :hello} = info = SSL.QUIC.info(client)

    assert MapSet.new(Map.keys(info)) ==
             MapSet.new([
               :role,
               :phase,
               :receive_level,
               :handshake_complete,
               :peer_authenticated,
               :cipher_suite,
               :alpn,
               :allowed_algorithms,
               :peer_parameters_authenticated
             ])

    refute inspect(client) =~ "secret"
    refute inspect(client) =~ parameter_marker
    refute inspect(client) =~ identity_marker

    assert {:error,
            %SSL.QUIC.Error{kind: :quic, alert: nil, reason: :wrong_encryption_level} = error,
            failed, [{:error, action_error}]} = SSL.QUIC.feed(client, :handshake, <<1, 0, 0, 0>>)

    assert action_error == error

    assert inspect(error) =~ "wrong_encryption_level"
    refute inspect(error) =~ "State"
    refute inspect(failed) =~ "secret"
    refute inspect(failed) =~ parameter_marker
    refute inspect(failed) =~ identity_marker
  end

  test "fragmented and coalesced legal tickets preserve completion until their cumulative budget is exhausted" do
    {client, _server} = connected_pair(limits: [max_total_handshake_bytes: 60_000])
    ticket = new_session_ticket(15_000)

    fragmented =
      ticket
      |> :binary.bin_to_list()
      |> Enum.reduce(client, fn byte, state ->
        assert {:ok, next, []} = SSL.QUIC.feed(state, :application, <<byte>>)
        next
      end)

    assert %{phase: :connected, handshake_complete: true} = SSL.QUIC.info(fragmented)

    assert {:ok, coalesced, []} = SSL.QUIC.feed(fragmented, :application, ticket <> ticket)
    assert %{phase: :connected, handshake_complete: true} = SSL.QUIC.info(coalesced)

    assert {:error, %SSL.QUIC.Error{} = error, failed, [{:error, error}]} =
             SSL.QUIC.feed(coalesced, :application, ticket <> ticket)

    assert error == %SSL.QUIC.Error{
             kind: :tls,
             alert: :decode_error,
             reason: :handshake_budget_exceeded
           }

    assert %{phase: :failed, handshake_complete: true} = SSL.QUIC.info(failed)
  end

  test "illegal post-handshake messages are terminal after a coalesced legal ticket" do
    {client, _server} = connected_pair()
    ticket = new_session_ticket(1)
    key_update = <<24, 1::24, 0>>

    assert {:error, %SSL.QUIC.Error{kind: :tls, alert: :unexpected_message}, failed,
            [{:error, _}]} = SSL.QUIC.feed(client, :application, ticket <> key_update)

    assert %{phase: :failed, handshake_complete: true} = SSL.QUIC.info(failed)

    assert {:error, %SSL.QUIC.Error{kind: :closed}, ^failed, []} =
             SSL.QUIC.feed(failed, :application, ticket)
  end

  test "ordinary public handshake does not emit logs" do
    log =
      capture_log(fn ->
        {client, server} = connected_pair()
        assert SSL.QUIC.info(client).handshake_complete
        assert SSL.QUIC.info(server).handshake_complete
      end)

    assert log == ""
  end

  defp connected_pair(extra_client_options \\ []) do
    assert {:ok, client, client_actions} =
             SSL.QUIC.new(:client, client_options(extra_client_options))

    assert {:ok, server, []} = SSL.QUIC.new(:server, server_options())
    {server, server_actions} = transfer(server, client_actions)
    {client, client_actions} = transfer(client, server_actions)
    {server, _server_actions} = transfer(server, client_actions)
    {client, server}
  end

  defp transfer(state, actions) do
    Enum.reduce(actions, {state, []}, fn
      {:emit, level, bytes}, {current, emitted} ->
        assert {:ok, next, next_actions} = SSL.QUIC.feed(current, level, bytes)
        {next, emitted ++ next_actions}

      _, result ->
        result
    end)
  end

  defp new_session_ticket(ticket_size) do
    ticket = :binary.copy(<<1>>, ticket_size)
    body = <<3600::32, 0::32, 1, 7, ticket_size::16, ticket::binary, 0::16>>
    <<4, byte_size(body)::24, body::binary>>
  end
end
