defmodule QuicHttp3.ConnectionErrorTest do
  # Global call tracing observes the frames the real peer decrypts and decodes.
  use ExUnit.Case, async: false
  @moduletag :integration

  alias QuicHttp3.{Frame, Session}

  setup do
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, server} = Quic.listen(tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]])
    on_exit(fn -> QuicHttp3.TestStop.quietly(server) end)
    opts = [tls: [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]]
    %{server: server, opts: opts}
  end

  test "the peer receives CONNECTION_CLOSE carrying the detected HTTP/3 error code", %{
    server: server,
    opts: opts
  } do
    {ip, port} = Quic.local(server)
    {:ok, session} = Session.new()
    {:ok, session} = Session.connect(session, ip, port, opts)
    endpoint = session.connection.endpoint
    on_exit(fn -> QuicHttp3.TestStop.quietly(endpoint) end)
    connection = session.connection.handle
    assert_receive {:quic_ready, ^connection, %{alpn: "h3"}}, 2_000
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    {:ok, session} = Session.open(session)

    :erlang.trace_pattern({Quic.Codec, :decode_frames, :_}, [{:_, [], [{:return_trace}]}], [
      :global
    ])

    on_exit(fn -> :erlang.trace_pattern({Quic.Codec, :decode_frames, :_}, false, [:global]) end)
    1 = :erlang.trace(accepted.id, true, [:call])

    # A control stream whose first frame is not SETTINGS is H3_MISSING_SETTINGS.
    {:ok, control} = Quic.open_stream(accepted, :uni)
    {:ok, _} = Quic.send_stream(control, <<0>> <> Frame.encode!(:data, "x"), false)

    assert {:http3_error, :connection, 0x10A, :settings_must_be_first} =
             poll_error(session, System.monotonic_time(:millisecond) + 2_000)

    assert {0x10A, "settings_must_be_first"} = await_application_close(2_000)
  end

  defp poll_error(session, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case Session.poll(session, 128) do
      {:ok, session, _events} -> poll_error(session, deadline)
      {:error, _session, reason} -> reason
    end
  end

  defp await_application_close(timeout) do
    receive do
      {:trace, _pid, :return_from, {Quic.Codec, :decode_frames, _}, {:ok, frames, _rest}} ->
        case Enum.find(frames, &match?(%{type: :application_close}, &1)) do
          %{error_code: code, reason: reason} -> {code, reason}
          nil -> await_application_close(timeout)
        end

      {:trace, _pid, _kind, _mfa} ->
        await_application_close(timeout)

      {:trace, _pid, _kind, _mfa, _value} ->
        await_application_close(timeout)
    after
      timeout -> flunk("the peer decoded no APPLICATION_CLOSE frame")
    end
  end
end
