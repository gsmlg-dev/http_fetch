defmodule SSL.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    :ok = warm_os_trust_store()
    SSL.Supervisor.start_link()
  end

  # Default peer verification reads the OS trust store through
  # `:public_key.cacerts_get/0`, which loads and caches it on first use. Load it
  # here, synchronously, so the first request never pays the cold load inside its
  # own deadline (#165). A host without an OS store must still boot; its requests
  # keep the lazy path's failure.
  defp warm_os_trust_store do
    _ = :public_key.cacerts_get()
    :ok
  rescue
    _ -> :ok
  end
end
