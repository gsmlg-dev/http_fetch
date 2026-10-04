defmodule ExSSL.TestSupport.OpenSSLPeer do
  @moduledoc false

  @startup_timeout 5_000
  @line_limit 524_288
  @script Path.expand("openssl_peer.py", __DIR__)

  @type peer :: %{port: :inet.port_number(), handle: port(), os_pid: pos_integer()}
  @type starting_peer :: %{port: nil, handle: port(), os_pid: pos_integer()}

  @spec start(keyword()) :: {:ok, peer()} | {:error, term()}
  def start(options) when is_list(options) do
    with {:ok, args} <- arguments(options),
         python when is_binary(python) <- System.find_executable("python3") do
      handle =
        Port.open({:spawn_executable, python}, [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          {:line, @line_limit},
          args: ["-B", @script | args]
        ])

      {:os_pid, os_pid} = Port.info(handle, :os_pid)
      peer = %{port: nil, handle: handle, os_pid: os_pid}

      case event(peer, "ready", @startup_timeout) do
        {:ok, %{"port" => port}} when is_integer(port) and port in 1..65_535 ->
          {:ok, %{peer | port: port}}

        error ->
          stop(peer)
          {:error, {:startup_failed, error}}
      end
    else
      nil -> {:error, :python3_missing}
      {:error, _} = error -> error
    end
  end

  def start(_), do: {:error, :invalid_options}

  @spec event(peer() | starting_peer(), binary(), timeout()) :: {:ok, map()} | {:error, term()}
  def event(%{handle: handle}, expected, timeout) when is_binary(expected) do
    receive do
      {^handle, {:data, {:eol, line}}} ->
        case decode(line) do
          {:ok, %{"kind" => ^expected} = message} -> {:ok, message}
          {:ok, %{"kind" => "failure"} = message} -> {:error, message}
          {:ok, message} -> {:error, {:unexpected_peer_event, message}}
          {:error, _} = error -> error
        end

      {^handle, {:data, {:noeol, _chunk}}} ->
        {:error, :peer_event_too_long}

      {^handle, {:exit_status, status}} ->
        {:error, {:peer_exit, status}}
    after
      timeout -> {:error, :peer_event_timeout}
    end
  end

  @spec stop(peer() | starting_peer()) :: :ok
  def stop(%{handle: handle, os_pid: os_pid}) do
    case Port.info(handle, :os_pid) do
      {:os_pid, ^os_pid} ->
        _ = System.cmd("kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)

        receive do
          {^handle, {:exit_status, _}} -> :ok
        after
          2_000 -> raise "OpenSSL test peer did not terminate"
        end

      nil ->
        :ok
    end
  end

  defp decode(line) do
    {:ok, :json.decode(line)}
  rescue
    _ -> {:error, :invalid_peer_event}
  end

  defp arguments(options) do
    allowed = [
      :certfile,
      :keyfile,
      :cafile,
      :min_version,
      :max_version,
      :cipher,
      :alpn,
      :verify,
      :mode,
      :max_connections,
      :delay_ms,
      :group,
      :restart_context,
      :abrupt_close
    ]

    if Keyword.keyword?(options) and Enum.all?(Keyword.keys(options), &(&1 in allowed)) and
         is_binary(options[:certfile]) and is_binary(options[:keyfile]) do
      {:ok,
       [
         "--certfile",
         options[:certfile],
         "--keyfile",
         options[:keyfile],
         "--min-version",
         version(Keyword.get(options, :min_version, :tls12)),
         "--max-version",
         version(Keyword.get(options, :max_version, :tls12)),
         "--cipher",
         Keyword.get(options, :cipher, "ECDHE-RSA-AES128-GCM-SHA256"),
         "--verify",
         Atom.to_string(Keyword.get(options, :verify, :none)),
         "--mode",
         Atom.to_string(Keyword.get(options, :mode, :echo)),
         "--max-connections",
         Integer.to_string(Keyword.get(options, :max_connections, 1)),
         "--delay-ms",
         Integer.to_string(Keyword.get(options, :delay_ms, 0)),
         "--restart-context",
         to_string(Keyword.get(options, :restart_context, false)),
         "--abrupt-close",
         to_string(Keyword.get(options, :abrupt_close, false))
       ] ++
         optional("--group", options[:group]) ++
         optional("--cafile", options[:cafile]) ++ optional("--alpn", alpn(options[:alpn]))}
    else
      {:error, :invalid_options}
    end
  end

  defp version(:tls12), do: "tls12"
  defp version(:tls13), do: "tls13"
  defp version(_), do: "invalid"
  defp alpn(nil), do: nil
  defp alpn(protocols), do: Enum.join(protocols, ",")
  defp optional(_key, nil), do: []
  defp optional(key, value), do: [key, value]
end
