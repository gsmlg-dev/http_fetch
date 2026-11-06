defmodule AbyssEchoExample.Application do
  use Application

  def start(_type, _args) do
    cert_path = System.fetch_env!("QUIC_CERT")
    key_path = System.fetch_env!("QUIC_KEY")
    [{:Certificate, cert, :not_encrypted}] = :public_key.pem_decode(File.read!(cert_path))
    [{type, key, :not_encrypted}] = :public_key.pem_decode(File.read!(key_path))

    children = [
      {Abyss.QUIC,
       name: AbyssEchoExample.Listener,
       ip: {127, 0, 0, 1},
       port: String.to_integer(System.get_env("QUIC_PORT", "0")),
       alpn: ["abyss-echo-v1"],
       tls: [cert: [cert], key: {type, key}],
       handler: AbyssEchoExample.Handler}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
