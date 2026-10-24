defmodule HTTP.R47MultiClientIdentityWebSocketTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F
  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Close, Message, Open}

  setup_all do
    directory = Path.join(System.tmp_dir!(), "r47-wss-#{System.unique_integer([:positive])}")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  for version <- ["tls12", "tls13"] do
    test "#{version} ordinary WSS selects the exact later identity and delivers frame bytes", %{
      fixtures: m
    } do
      version = unquote(version)

      {result, events} =
        F.with_peer(m, [version: version, hint: "client-a", application: "wss"], fn port ->
          socket =
            WebSocket.new("wss://127.0.0.1:#{port}/r47", [],
              tls_backend: :ex_ssl,
              ssl: F.options(m, ["p256-b", "rsa2048-a"], version)
            )

          try do
            assert_receive {WebSocket, ^socket, %Open{}}, 3_000
            assert_receive {WebSocket, ^socket, %Message{data: "r47-wss-ok"}}, 3_000
            assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 3_000
            :received
          after
            if Process.alive?(socket.pid), do: WebSocket.close(socket)
          end
        end)

      assert result == :received
      F.assert_authenticated(m, events, "rsa2048-a", 0x0804, version)

      assert [%{"application" => "wss", "request_exact" => true, "response_written" => true}] =
               Enum.filter(events, &(&1["event"] == "http"))
    end
  end
end
