defmodule HTTP.Transport.NestedTLS do
  @moduledoc false

  # OTP's documented cb_info transport boundary composes two independent TLS
  # sessions. The outer socket remains owned by the inner TLS receiver; there
  # is no plaintext relay, extra socket, retry or alternate backend.
  @callback_info {__MODULE__, :ssl, :ssl_closed, :ssl_error, :ssl_passive}

  def upgrade({:cancellable_ssl, outer, tcp}, host, opts, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    tls_opts =
      host
      |> HTTP.Transport.SSL.ssl_options(Keyword.get(opts, :ssl, []))
      |> Keyword.merge(
        mode: :binary,
        packet: :raw,
        active: false,
        cb_info: @callback_info,
        handshake: :hello
      )

    result =
      case :ssl.connect(outer, tls_opts, remaining(deadline)) do
        {:ok, inner, _extensions} ->
          with :ok <- HTTP.RequestLifecycle.track_tls(opts, inner),
               {:ok, inner} <- :ssl.handshake_continue(inner, [], remaining(deadline)),
               do: {:ok, {:cancellable_ssl, inner, tcp}}

        {:error, _} = error ->
          HTTP.RequestLifecycle.unconfirmed_tls(Keyword.get(opts, :request_lifecycle))
          error
      end

    if match?({:error, _}, result), do: HTTP.Transport.SSL.abort({:cancellable_ssl, outer, tcp})
    result
  end

  def send(socket, bytes), do: :ssl.send(socket, bytes)
  def recv(socket, length, timeout), do: :ssl.recv(socket, length, timeout)
  def setopts(socket, opts), do: :ssl.setopts(socket, opts)
  def getopts(socket, opts), do: :ssl.getopts(socket, opts)
  def peername(socket), do: :ssl.peername(socket)
  def sockname(socket), do: :ssl.sockname(socket)
  def getstat(socket, opts), do: :ssl.getstat(socket, opts)
  def controlling_process(socket, owner), do: :ssl.controlling_process(socket, owner)
  def shutdown(socket, direction), do: :ssl.shutdown(socket, direction)
  def close(socket), do: :ssl.close(socket)

  def port(socket) do
    with {:ok, {_address, port}} <- :ssl.sockname(socket), do: {:ok, port}
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
