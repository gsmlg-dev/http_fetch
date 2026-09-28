defmodule HTTP.OwnerMonitor do
  @moduledoc false

  # The connection can be blocked inside transport.connect/4 or a passive
  # Upgrade receive. A DOWN message in its own mailbox cannot interrupt those
  # calls, so a linked monitor enforces the owner's lifetime independently.
  @spec start(pid(), pid()) :: pid()
  def start(connection, owner) do
    spawn_link(fn ->
      connection_ref = Process.monitor(connection)
      owner_ref = Process.monitor(owner)

      receive do
        {:DOWN, ^owner_ref, :process, ^owner, _reason} ->
          Process.exit(connection, :shutdown)

        {:DOWN, ^connection_ref, :process, ^connection, _reason} ->
          :ok
      end
    end)
  end
end
