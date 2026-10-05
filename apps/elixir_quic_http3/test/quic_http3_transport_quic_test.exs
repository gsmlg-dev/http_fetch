defmodule QuicHttp3.Transport.QuicTest do
  use ExUnit.Case, async: true

  alias QuicHttp3.Transport.Quic, as: Adapter

  defmodule Ops do
    def client(opts), do: send_call(:client, [opts])
    def connect(endpoint, remote, opts), do: send_call(:connect, [endpoint, remote, opts])
    def stop_endpoint(endpoint), do: send_call(:stop_endpoint, [endpoint])
    def attach(handle, consumer, opts), do: send_call(:attach, [handle, consumer, opts])
    def ready(handle), do: send_call(:ready, [handle])
    def open_stream(handle, kind, opts), do: send_call(:open_stream, [handle, kind, opts])

    def send_stream(stream, bytes, fin, opts),
      do: send_call(:send_stream, [stream, bytes, fin, opts])

    def read(stream, max, opts), do: send_call(:read, [stream, max, opts])
    def events(handle, max, opts), do: send_call(:events, [handle, max, opts])
    def reset_stream(stream, code, opts), do: send_call(:reset_stream, [stream, code, opts])
    def stop_stream(stream, code, opts), do: send_call(:stop_stream, [stream, code, opts])
    def close(handle, code, reason, opts), do: send_call(:close, [handle, code, reason, opts])
    def send_datagram(handle, bytes, opts), do: send_call(:send_datagram, [handle, bytes, opts])
    def read_datagrams(handle, max, opts), do: send_call(:read_datagrams, [handle, max, opts])

    defp send_call(name, args) do
      send(Process.get(:owner), {name, args})
      Process.get({:result, name}, :ok)
    end
  end

  setup do
    Process.put(:owner, self())
    endpoint = self()
    handle = make_ref()
    Process.put({:result, :client}, {:ok, endpoint})
    Process.put({:result, :connect}, {:ok, handle})
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls/root.pem", __DIR__)
    [{:Certificate, ca, :not_encrypted}] = :public_key.pem_decode(File.read!(fixture))
    Process.put(:tls, cacerts: [ca], reference_identity: {:dns_id, "example.test"})
    {:ok, endpoint: endpoint, handle: handle}
  end

  test "configures h3 ALPN and bounded datagrams", ctx do
    endpoint = ctx.endpoint
    assert {:ok, connection} = connect({127, 0, 0, 1}, 443, ops: Ops)
    assert connection.endpoint == ctx.endpoint
    assert connection.handle == ctx.handle
    assert_received {:client, [opts]}
    assert opts[:datagram] == [max_frame_size: 1200, max_items: 64, max_buffer_bytes: 65_536]

    assert opts[:profile].tls.extensions
           |> Enum.find_value(fn
             {:alpn, value} -> value
             _ -> nil
           end) == ["h3"]

    assert_received {:connect, [^endpoint, {{127, 0, 0, 1}, 443}, [ref: _ref]]}
  end

  test "delegates streams, datagrams and lifecycle without rewriting failures", _ctx do
    ref = make_ref()
    stream = make_ref()
    Process.put({:result, :open_stream}, {:ok, stream})
    Process.put({:result, :send_stream}, {:blocked, :credit})
    Process.put({:result, :read}, {:unknown, ref})
    Process.put({:result, :send_datagram}, {:error, :datagram_unsupported})
    Process.put({:result, :read_datagrams}, {:ok, ["d"]})
    Process.put({:result, :close}, {:error, :closed})
    assert {:ok, connection} = connect({127, 0, 0, 1}, 443, ops: Ops)
    assert {:ok, stream} = Adapter.open_stream(connection, :uni, [])
    assert {:blocked, :credit} = Adapter.send_stream(stream, "x", false, [])
    assert {:unknown, ^ref} = Adapter.read(stream, 1, [])
    assert {:error, :datagram_unsupported} = Adapter.send_datagram(connection, "d", [])
    assert {:ok, ["d"]} = Adapter.read_datagrams(connection, 1, [])
    assert {:error, :closed} = Adapter.close(connection, 1, <<>>, [])
  end

  test "rejects invalid bounds before operations" do
    assert {:error, :invalid_write} =
             Adapter.send_stream(%Adapter.Stream{}, String.duplicate("x", 16_385), false, [])

    assert {:error, :invalid_read_limit} = Adapter.read(%Adapter.Stream{}, 0, [])
    assert {:error, :invalid_event_limit} = Adapter.events(%Adapter{}, 129, [])
    assert {:error, :invalid_datagram_limit} = Adapter.read_datagrams(%Adapter{}, 0, [])
  end

  test "custom ALPN and invalid profile options" do
    assert {:error, :invalid_h3_alpn} = connect({127, 0, 0, 1}, 443, alpn: ["my-h3"], ops: Ops)

    assert {:error, :invalid_h3_alpn} =
             connect({127, 0, 0, 1}, 443, alpn: [], ops: Ops)

    assert {:error, :invalid_datagram_options} =
             connect({127, 0, 0, 1}, 443, datagram: :disabled, ops: Ops)
  end

  test "stops an internally owned endpoint when connect fails" do
    Process.put({:result, :connect}, {:blocked, :handshake})
    Process.put({:result, :stop_endpoint}, :ok)

    assert {:blocked, :handshake} = connect({127, 0, 0, 1}, 443, ops: Ops)
    assert_received {:stop_endpoint, [_endpoint]}
  end

  defp connect(remote, port, opts) do
    Adapter.connect(remote, port, Keyword.put_new(opts, :tls, Process.get(:tls)))
  end

  test "rejects malformed remote values without starting an endpoint" do
    for remote <- [:not_an_address, nil, 123, %{}, [], ~c"localhost", {}, {256, 0, 0, 1}] do
      assert {:error, :invalid_remote} = connect(remote, 443, ops: Ops)
    end

    refute_received {:client, _}
    refute_received {:connect, _}
  end
end
