defmodule Hell.ProcessLabel do
  @moduledoc false
  # Provides compile-time conditional support for Process.set_label/1
  # which was introduced in Elixir 1.17.0 and OTP 27.
  @supports_labels Version.match?(System.version(), ">= 1.17.0") and
                     String.to_integer(System.otp_release()) >= 27

  @type config() :: Hell.ServerConfig.t() | Hell.HandlerConfig.t()

  if @supports_labels do
    @doc """
    Sets a process label if the current Elixir version supports it (>= 1.17).
    """
    @spec set(atom(), config(), term()) ::
            :ok
    def set(name, %Hell.ServerConfig{} = config, state) when is_atom(name) do
      Process.set_label({:hell, name, {{config.port, config.handler_module}, state}})
    end

    def set(name, %Hell.HandlerConfig{} = config, state) when is_atom(name) do
      Process.set_label({:hell, name, {config.handler_module, state}})
    end

    @doc """
    Sets a process label if the current Elixir version supports it (>= 1.17).
    """
    @spec set(atom(), term()) :: :ok
    def set(name, %Hell.ServerConfig{} = config) when is_atom(name) do
      Process.set_label({:hell, name, {config.port, config.handler_module}})
    end

    def set(name, state) when is_atom(name) do
      Process.set_label({:hell, name, state})
    end
  else
    @doc """
    No-op on Elixir versions < 1.17 that don't support Process.set_label/1.
    """
    @spec set(atom(), config(), term()) :: :ok
    def set(_, _, _) do
      :ok
    end

    @doc """
    No-op on Elixir versions < 1.17 that don't support Process.set_label/1.
    """
    @spec set(atom(), term()) :: :ok
    def set(_, _) do
      :ok
    end
  end
end
