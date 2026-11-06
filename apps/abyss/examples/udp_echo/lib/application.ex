defmodule AbyssUDPExample.Handler do
  use Abyss.Handler
  @impl true
  def handle_data({ip, port, bytes}, state) do
    :ok = Abyss.Transport.UDP.send(state.socket, ip, port, bytes)
    {:close, state}
  end
end

defmodule AbyssUDPExample do
  use Application

  def start(_type, _args) do
    Supervisor.start_link(
      [
        {Abyss, handler_module: AbyssUDPExample.Handler, port: 0, num_listeners: 1}
      ],
      strategy: :one_for_one,
      name: __MODULE__.Supervisor
    )
  end

  def verify do
    false = Code.ensure_loaded?(Quic)

    {:error, :quic_backend_unavailable} =
      Abyss.QUIC.start_link(
        handler: AbyssUDPExample.Handler,
        alpn: ["missing-engine"],
        tls: []
      )

    [{_, server, _, _}] = Supervisor.which_children(__MODULE__.Supervisor)
    pool = Abyss.Server.listener_pool_pid(server)
    [{_, listener, _, _}] = Supervisor.which_children(pool)
    {:ok, {_ip, port}} = Abyss.Listener.listener_info_cached(listener)
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "ordinary-udp")
    {:ok, {_, ^port, "ordinary-udp"}} = :gen_udp.recv(socket, 0, 2000)
    :gen_udp.close(socket)
    IO.puts("UDP_WITHOUT_QUIC_PASS")
  end
end
