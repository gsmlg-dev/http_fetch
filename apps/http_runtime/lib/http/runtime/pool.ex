defmodule HTTP.Runtime.Pool do
  @moduledoc """
  Supervises an explicitly selected, immutable HTTP/1 and HTTP/2 pool family.

      {HTTP.Runtime.Pool,
       name: "api",
       http1: [max_idle_per_key: 1, max_idle: 8],
       http2: [max_connections: 1, max_streams: 16]}

      HTTP.fetch(url, pool: "api")

  `reference/1` captures a generation for reuse across requests. Names are atoms
  or strings registered without converting external strings into atoms. Families
  restart together: old references fail with `:stale_pool` and never fall back.
  HTTP/1 selection enables reuse. Explicit `http1_reuse: false`, retention above
  the instance policy, managed scopes, HTTP/3 and automatic negotiation are
  rejected before dialing. HTTP/2 selection requires reusable pool identities.

  `start_link/1` raises `ArgumentError` for unknown keys or invalid policy values,
  naming the `{:invalid_pool_option, key, why}` reason.
  """
  use Supervisor
  alias HTTP.HTTP2.PoolKey

  def start_link(opts) do
    case policy(opts) do
      {:ok, policy} ->
        options =
          case Keyword.get(opts, :name) do
            nil -> []
            name -> [name: {:via, Registry, {__MODULE__.Registry, name}}]
          end

        Supervisor.start_link(__MODULE__, policy, options)

      {:error, reason} ->
        HTTP.Runtime.Options.raise_invalid!(__MODULE__, reason)
    end
  end

  def child_spec(opts) do
    %{
      id: {__MODULE__, Keyword.get(opts, :name, make_ref())},
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor
    }
  end

  @impl true
  def init(policy) do
    {:ok, _} = Registry.register(__MODULE__.Registry, {:family, self()}, nil)

    children =
      HTTP.Pool.child_specs(policy) ++
        [{HTTP.Runtime.Pool.Identity, policy}]

    Supervisor.init(children, strategy: :one_for_all)
  end

  @doc "Resolves a family name or supervisor PID into a generation-bound reference."
  def reference(%HTTP.Pool{} = ref) do
    with :ok <- HTTP.Pool.validate(ref), do: {:ok, ref}
  end

  def reference(server) when is_atom(server) or is_binary(server) do
    case Registry.lookup(__MODULE__.Registry, server) do
      [{pid, _}] -> reference(pid)
      [] -> {:error, :unknown_pool}
    end
  end

  def reference(server) when is_pid(server) do
    case Registry.lookup(__MODULE__.Registry, {:family, server}) do
      [{^server, _}] -> reference_family(server)
      [] -> {:error, :invalid_pool}
    end
  end

  def reference(_), do: {:error, :invalid_pool}

  defp reference_family(server) do
    children = Supervisor.which_children(server)

    with {_, h1, _, _} when is_pid(h1) <- List.keyfind(children, HTTP.HTTP1.Pool, 0),
         {_, h2, _, _} when is_pid(h2) <- List.keyfind(children, HTTP.HTTP2.Pool, 0),
         {_, identity, _, _} when is_pid(identity) <-
           List.keyfind(children, HTTP.Runtime.Pool.Identity, 0),
         {generation, policy} <- GenServer.call(identity, :identity) do
      ref = %HTTP.Pool{
        instance: identity,
        generation: generation,
        http1: h1,
        http2: h2,
        policy: policy
      }

      with :ok <- HTTP.Pool.validate(ref), do: {:ok, ref}
    else
      _ -> {:error, :stale_pool}
    end
  catch
    :exit, _ -> {:error, :stale_pool}
  end

  @doc false
  def prepare(request, init) do
    case request.transport_options[:pool_binding] do
      %HTTP.Pool{} = ref ->
        with :ok <- HTTP.Pool.validate(ref), do: {:ok, request}

      nil ->
        prepare_selection(request, init, request.transport_options[:pool])
    end
  end

  defp prepare_selection(request, _init, nil), do: {:ok, request}

  defp prepare_selection(request, init, selected) do
    opts = request.transport_options

    with :ok <- compatible(opts),
         {:ok, ref} <- reference(selected),
         {:ok, opts} <- bind_options(opts, init, ref),
         request = %{request | transport_options: opts},
         :ok <- reusable_identity(request) do
      {:ok, request}
    end
  end

  defp compatible(opts) do
    cond do
      opts[:transport_scope] != nil ->
        {:error, {:invalid_pool_option, :transport_scope, :conflict}}

      Keyword.get(opts, :http_version, :http1) not in [:http1, :http2, :h2c] ->
        {:error, {:invalid_pool_option, :http_version, :unsupported}}

      opts[:http2_reuse] == false and opts[:http_version] in [:http2, :h2c] ->
        {:error, {:invalid_pool_option, :http2_reuse, :conflict}}

      true ->
        :ok
    end
  end

  defp bind_options(opts, init, ref) do
    bound = Keyword.merge(opts, pool_binding: ref, http1_pool: ref.http1, http2_pool: ref.http2)

    if Keyword.get(opts, :http_version, :http1) == :http1 do
      h1 = ref.policy.http1
      size = explicit(init, :http1_pool_size) || h1[:max_idle_per_key]
      idle = explicit(init, :http1_idle_timeout) || h1[:idle_timeout]

      cond do
        explicit(init, :http1_reuse) == false ->
          {:error, {:invalid_pool_option, :http1_reuse, :conflict}}

        not is_integer(size) or size < 1 or size > h1[:max_idle_per_key] ->
          {:error, {:invalid_pool_option, :http1_pool_size, :above_instance_limit}}

        not is_integer(idle) or idle < 1 or idle > h1[:idle_timeout] ->
          {:error, {:invalid_pool_option, :http1_idle_timeout, :above_instance_limit}}

        true ->
          {:ok,
           Keyword.merge(bound,
             http1_reuse: true,
             http1_pool_size: size,
             http1_idle_timeout: idle
           )}
      end
    else
      {:ok, bound}
    end
  end

  defp reusable_identity(request) do
    opts = request.transport_options

    request =
      if opts[:http_version] == :http1 do
        %{request | transport_options: Keyword.put(opts, :http2_scope, opts[:http1_scope])}
      else
        request
      end

    protocol = if request.url.scheme == "https", do: :h2, else: :h2c

    case PoolKey.build(request, Keyword.get(opts, :http2_profile, :native_v1), protocol) do
      {:ok, _} -> :ok
      {:ok, :non_reusable, _} -> {:error, {:invalid_pool_option, :identity, :non_reusable}}
      {:error, _} = error -> error
    end
  end

  defp explicit(init, key) when is_list(init), do: Keyword.get(init, key)

  defp explicit(init, key) when is_map(init) do
    camel =
      case key do
        :http1_reuse -> "http1Reuse"
        :http1_pool_size -> "http1PoolSize"
        :http1_idle_timeout -> "http1IdleTimeout"
      end

    Map.get(init, key, Map.get(init, Atom.to_string(key), Map.get(init, camel)))
  end

  defp policy(opts) when is_list(opts) do
    if Keyword.keyword?(opts) and
         length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) do
      case Enum.find(Keyword.keys(opts), &(&1 not in [:name, :http1, :http2])) do
        nil ->
          name = Keyword.get(opts, :name)

          if is_nil(name) or is_atom(name) or is_binary(name),
            do: HTTP.Pool.policy(Keyword.drop(opts, [:name])),
            else: {:error, {:invalid_pool_option, :name, :expected_atom_or_string}}

        key ->
          {:error, {:invalid_pool_option, key, :unknown}}
      end
    else
      {:error, {:invalid_pool_option, :options, :expected_keyword}}
    end
  end

  defp policy(_), do: {:error, {:invalid_pool_option, :options, :expected_keyword}}
end

defmodule HTTP.Runtime.Pool.Identity do
  @moduledoc false
  use GenServer
  def start_link(policy), do: GenServer.start_link(__MODULE__, policy)
  @impl true
  def init(policy), do: {:ok, {make_ref(), policy}}
  @impl true
  def handle_call(:identity, _from, identity), do: {:reply, identity, identity}
end
