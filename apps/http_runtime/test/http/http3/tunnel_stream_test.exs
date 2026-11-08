defmodule HTTP.HTTP3.TunnelStreamTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP3.Stream
  alias HTTP.Runtime.Stream, as: ByteStream

  @trust_anchor_der Base.decode64!(
                      """
                      MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBleF9z
                      c2wtVGVzdC1Sb290MB4XDTI2MDkxMDA4MTIyNVoXDTM2MDkwNzA4MTIyNVowGzEZ
                      MBcGA1UEAwwQZXhfc3NsLVRlc3QtUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEP
                      ADCCAQoCggEBALchanJ7iECLuLQCyqF63X2XqxWenDFQpSB/9Qc8M01ee3tqXg/D
                      IatfELc5CMzXGuGkWBlzVc3wlzL//vzfZMA5jY6uDfI9n/mVlsH4hbCt7cjMbhHH
                      qYlp84niS3RSKBzuzoNP+n9fe24pfOlbRnOR1gBng7ByRDoGQsoSZx4DU3KCYuUp
                      oDUkTfyGX40KFuUME36IcF1/LlYM5d/PTjN/TLGG5jtmqh4Be5pGQlSLpu88JzGm
                      EtQ+0YuXcQ9KBYBFP/g6gXt5VxATSFxbn4phj7fK26eoJp9sPAZLIAo26aDKjs3p
                      mqe55DehYSubDA76ug6SAWaX+KoWp5xLOKECAwEAAaNmMGQwHwYDVR0jBBgwFoAU
                      hdlS4cW2w9qjB9P3WyBJCTazRMowEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8B
                      Af8EBAMCAQYwHQYDVR0OBBYEFIXZUuHFtsPaowfT91sgSQk2s0TKMA0GCSqGSIb3
                      DQEBCwUAA4IBAQAzE5L9eZQyel0/1PDsnhxK3CtNlsgV+9b4vfEDN9an6FPQeEhW
                      PBiok05Zj0Vidydr3JTyJ1LCyzG/pXzG4l+jPkz7P9LD8yWgGlKb1lA2cMtsf8bN
                      mnsJ0/SZoVT6XfnWxYOGgRdYr07iuurzxHHtclfU7zV0U3adEXm4btIu2T+gJXDB
                      Mol55IeSxwAmUNp7z4vLssA+Hw2EPVVKZC2Y3SFEsbbUAVP5S1zjFw+q9AK4miVZ
                      kte6jgtTfdHL8mZcyrIyFxFh91XEJZVNoGUqUd2KFqAKJXlmX0rPED2pgsqJNxW+
                      ZXyKoINVpC5VCv3l5WlLzjwONpj4JussZD1r
                      """,
                      ignore: :whitespace
                    )

  defmodule Backend do
    use GenServer
    def start_link({parent, mode}), do: GenServer.start_link(__MODULE__, {parent, mode})
    def init({parent, mode}), do: {:ok, %{parent: parent, mode: mode}}
    def handle_call({:reserve, _, _}, _, state), do: {:reply, {:ok, self(), make_ref()}, state}

    def handle_call({:release, _}, _, state) do
      send(state.parent, :released)
      {:reply, :ok, state}
    end

    def handle_call({:open, _, :stream, subscriber, generation, _}, _, state) do
      ref = make_ref()

      {:reply, {:ok, ref},
       Map.merge(state, %{subscriber: subscriber, generation: generation, ref: ref}),
       {:continue, :headers}}
    end

    def handle_call({:cancel, _}, _, state) do
      send(state.parent, :cancelled)
      {:reply, :ok, state}
    end

    def handle_continue(:headers, state) do
      send(state.subscriber, {:http3, state.generation, state.ref, {:headers, 200, []}})
      {:noreply, state}
    end

    def handle_cast({:write, _, _, _, recipient, ref}, state) do
      send(state.parent, :write_admitted)
      if state.mode == :done, do: send(recipient, {:http3_write, ref, :done})
      {:noreply, state}
    end
  end

  defp request do
    %HTTP.Request{
      method: :connect,
      url: URI.parse("https://example.test/ws"),
      transport_options: [ssl: [cacerts: [@trust_anchor_der]]]
    }
  end

  test "an unresolved tunnel write expires with its original public ref and releases its lease" do
    backend = start_supervised!({Backend, {self(), :blocked}})

    assert {:ok, stream, generation} =
             Stream.start(request(), self(),
               pool: backend,
               purpose: :extended_connect,
               protocol: "websocket",
               write_timeout: 30
             )

    monitor = Process.monitor(stream)
    assert_receive {:http_runtime, ^generation, ^stream, {:opened, _}}, 1_000
    assert_receive {:http_runtime, ^generation, ^stream, {:headers, [{":status", "200"}], []}}
    ref = ByteStream.write(stream, "payload")
    assert_receive :write_admitted

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:write, ^ref, {:error, {:indeterminate_operation, ^ref}}}},
                   500

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:error, {:indeterminate_operation, ^ref}}},
                   500

    assert_receive :cancelled
    assert_receive :released
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}
    refute_receive :write_admitted, 0
  end

  test "tunnel purpose and timeouts are finite before starting a worker" do
    assert {:error, :invalid_stream_purpose} = Stream.start(request(), self(), purpose: :other)

    for {key, reason} <- [
          opening_timeout: :invalid_opening_timeout,
          write_timeout: :invalid_write_timeout,
          max_write_bytes: :invalid_max_write_bytes
        ] do
      assert {:error, ^reason} =
               Stream.start(request(), self(), [
                 {key, :infinity},
                 purpose: :extended_connect,
                 protocol: "websocket"
               ])
    end

    assert {:error, :webtransport_network_not_ready} =
             Stream.start(request(), self(),
               purpose: :extended_connect,
               protocol: "webtransport-h3"
             )
  end
end
