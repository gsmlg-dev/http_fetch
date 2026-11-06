defmodule Hell.TransportOptionsTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  @certfile Path.expand("../support/cert.pem", __DIR__)
  @keyfile Path.expand("../support/key.pem", __DIR__)
  @cacertfile Path.expand("../support/ca.pem", __DIR__)

  defmodule CaptureData do
    use Hell.Handler

    @impl Hell.Handler
    def handle_data(data, _socket, test_pid) do
      send(test_pid, {:received, data})
      {:close, test_pid}
    end
  end

  for {transport, client, required_options} <- [
        {Hell.Transports.TCP, :gen_tcp, []},
        {Hell.Transports.SSL, :ssl, [certfile: @certfile, keyfile: @keyfile]}
      ],
      mode_options <- [[:list], [:binary], [mode: :list]] do
    test "#{inspect(transport)} receives binaries with #{inspect(mode_options)}" do
      {:ok, server} =
        start_supervised(
          {Hell,
           port: 0,
           num_acceptors: 1,
           transport_module: unquote(transport),
           transport_options: unquote(mode_options ++ required_options),
           handler_module: CaptureData,
           handler_options: self()}
        )

      {:ok, {_address, port}} = Hell.listener_info(server)

      client_options =
        if unquote(client) == :ssl do
          [:binary, active: false, verify: :verify_peer, cacertfile: @cacertfile]
        else
          [:binary, active: false]
        end

      {:ok, client} = unquote(client).connect(~c"localhost", port, client_options, 5_000)
      on_exit(fn -> unquote(client).close(client) end)
      :ok = unquote(client).send(client, "hello")
      assert_receive {:received, "hello"}, 1_000
    end
  end

  test "TCP preserves distinct raw socket options" do
    {level, keepalive, broadcast} =
      case :os.type() do
        {:unix, :linux} -> {1, 9, 6}
        {:unix, :darwin} -> {0xFFFF, 0x0008, 0x0020}
      end

    enabled = <<1::native-32>>
    options = [{:raw, level, keepalive, enabled}, {:raw, level, broadcast, enabled}]
    {:ok, listener} = Hell.Transports.TCP.listen(0, options)
    on_exit(fn -> Hell.Transports.TCP.close(listener) end)

    assert {:ok,
            [
              {:raw, ^level, ^keepalive, <<keepalive_enabled::native-32>>},
              {:raw, ^level, ^broadcast, <<broadcast_enabled::native-32>>}
            ]} = Hell.Transports.TCP.getopts(listener, options)

    # Darwin returns the enabled option's bitmask; Linux returns 1.
    assert keepalive_enabled != 0
    assert broadcast_enabled != 0
  end

  test "TCP and SSL omit the nodelay default only for Unix domain sockets" do
    unix_path =
      Path.join(
        System.tmp_dir!(),
        "hell_#{System.unique_integer([:positive])}.sock"
      )

    on_exit(fn -> File.rm(unix_path) end)

    for {transport, backend, required_options} <- transports() do
      [
        ip_unix_options,
        ifaddr_unix_options,
        explicit_ip_options,
        explicit_ifaddr_options,
        ip_options
      ] =
        traced_listen_options(transport, backend, [
          [ip: {:local, unix_path}] ++ required_options,
          [ifaddr: {:local, unix_path}] ++ required_options,
          [ip: {:local, unix_path}, nodelay: false] ++ required_options,
          [ifaddr: {:local, unix_path}, nodelay: false] ++ required_options,
          required_options
        ])

      refute :proplists.is_defined(:nodelay, ip_unix_options)
      refute :proplists.is_defined(:nodelay, ifaddr_unix_options)
      assert :proplists.get_value(:nodelay, explicit_ip_options) == false
      assert :proplists.get_value(:nodelay, explicit_ifaddr_options) == false
      assert :proplists.get_value(:nodelay, ip_options) == true
    end
  end

  defp transports do
    [
      {Hell.Transports.TCP, :gen_tcp, []},
      {Hell.Transports.SSL, :ssl, [certfile: @certfile, keyfile: @keyfile]}
    ]
  end

  defp traced_listen_options(transport, backend, options_list) do
    Code.ensure_loaded!(backend)

    task =
      Task.async(fn ->
        receive do
          :listen ->
            Enum.each(options_list, fn options ->
              try do
                case transport.listen(0, options) do
                  {:ok, socket} -> transport.close(socket)
                  {:error, _reason} -> :ok
                end
              rescue
                ArgumentError -> :ok
              end
            end)
        end
      end)

    :erlang.trace_pattern({backend, :listen, 2}, true, [])
    :erlang.trace(task.pid, true, [:call])
    send(task.pid, :listen)
    task_pid = task.pid

    try do
      resolved_options =
        Enum.map(options_list, fn _options ->
          assert_receive {:trace, ^task_pid, :call, {^backend, :listen, [0, options]}},
                         1_000

          options
        end)

      Task.await(task)
      resolved_options
    after
      :erlang.trace_pattern({backend, :listen, 2}, false, [])
    end
  end
end
