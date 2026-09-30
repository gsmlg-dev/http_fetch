defmodule HTTP.HTTP2.WireProfile do
  @moduledoc """
  Versioned, finite HTTP/2 wire configuration.

  A profile keeps wire-order-sensitive values as lists. `compile/1` is the only
  boundary at which external maps are accepted; unknown keys and unsupported
  combinations are rejected instead of being silently ignored.
  """

  @enforce_keys [:id, :revision, :settings, :connection_initial_window, :pseudo_headers]
  defstruct id: nil,
            revision: 1,
            source: :synthetic,
            evidence: :synthetic,
            settings: [],
            connection_initial_window: 65_535,
            stream_initial_window: 65_535,
            receive_window_target: 65_535,
            receive_window_threshold: 32_767,
            receive_window_increment: 32_767,
            pseudo_headers: [":method", ":scheme", ":authority", ":path"],
            regular_headers: :input,
            default_user_agent: :append,
            hpack: %{
              huffman: :never,
              indexing: :literal,
              sensitive: ["authorization", "cookie", "set-cookie"]
            },
            priority: :none,
            max_header_fragment: 16_384,
            max_data_frame: 16_384,
            padding: :none,
            push: :disabled

  @type t :: %__MODULE__{regular_headers: :input | :lexicographic | :reverse_input}

  # These factories intentionally expose the stable `t()` contract. Dialyzer
  # otherwise infers each literal profile as a narrower singleton struct and
  # reports the public contract as a supertype.
  @dialyzer {:nowarn_function, native_v1: 0, synthetic_test_v1: 0, synthetic_test_v2: 0}
  @allowed [
    :id,
    :revision,
    :source,
    :evidence,
    :settings,
    :connection_initial_window,
    :stream_initial_window,
    :receive_window_target,
    :receive_window_threshold,
    :receive_window_increment,
    :pseudo_headers,
    :regular_headers,
    :default_user_agent,
    :hpack,
    :priority,
    :max_header_fragment,
    :max_data_frame,
    :padding,
    :push
  ]
  @settings_defaults %{1 => 4096, 2 => 0, 3 => 100, 4 => 65_535, 5 => 16_384, 6 => 0, 8 => 0}

  @spec native_v1() :: t()
  def native_v1 do
    %__MODULE__{
      id: "native_v1",
      revision: 2,
      settings: [{2, 0}],
      connection_initial_window: 65_535,
      pseudo_headers: [":method", ":scheme", ":authority", ":path"],
      source: :native,
      evidence: :engine_verified
    }
  end

  @spec synthetic_test_v1() :: t()
  def synthetic_test_v1 do
    %__MODULE__{
      id: "synthetic_test_v1",
      revision: 2,
      settings: [{4, 131_072}, {1, 8192}, {2, 0}],
      connection_initial_window: 131_071,
      stream_initial_window: 131_072,
      pseudo_headers: [":method", ":path", ":scheme", ":authority"],
      regular_headers: :lexicographic,
      hpack: %{
        huffman: :always,
        indexing: :literal,
        sensitive: ["authorization", "cookie", "set-cookie"]
      },
      priority: :legacy,
      source: :synthetic,
      evidence: :synthetic
    }
  end

  @spec synthetic_test_v2() :: t()
  def synthetic_test_v2 do
    %__MODULE__{
      id: "synthetic_test_v2",
      revision: 2,
      settings: [{5, 32_768}, {4, 65_535}, {2, 0}],
      connection_initial_window: 65_535,
      pseudo_headers: [":method", ":authority", ":scheme", ":path"],
      regular_headers: :reverse_input,
      hpack: %{
        huffman: :never,
        indexing: :never,
        sensitive: ["authorization", "cookie", "set-cookie"]
      },
      priority: :rfc9218,
      source: :synthetic,
      evidence: :synthetic
    }
  end

  @spec compile(t() | map() | atom() | binary()) :: {:ok, t()} | {:error, term()}
  def compile(%__MODULE__{} = profile), do: validate(profile)

  def compile(profile) when profile in [:native_v1, "native_v1", "native-v1"],
    do: {:ok, native_v1()}

  def compile(profile)
      when profile in [:synthetic_test_v1, "synthetic_test_v1", "synthetic-test-v1"],
      do: {:ok, synthetic_test_v1()}

  def compile(profile)
      when profile in [:synthetic_test_v2, "synthetic_test_v2", "synthetic-test-v2"],
      do: {:ok, synthetic_test_v2()}

  def compile(options) when is_map(options) do
    unknown = Map.keys(options) -- @allowed

    cond do
      not Map.has_key?(options, :id) ->
        {:error, :missing_id}

      unknown != [] ->
        {:error, {:unknown_fields, Enum.sort(unknown)}}

      true ->
        options = Map.put_new(options, :revision, 1)
        options = Map.put_new(options, :source, :synthetic)
        options = Map.put_new(options, :evidence, :synthetic)
        options = Map.put_new(options, :settings, [{2, 0}])
        options = Map.put_new(options, :connection_initial_window, 65_535)
        options = Map.put_new(options, :stream_initial_window, 65_535)

        options =
          Map.put_new(options, :pseudo_headers, [":method", ":scheme", ":authority", ":path"])

        validate(struct(__MODULE__, options))
    end
  end

  def compile(_), do: {:error, :invalid_profile}

  @spec validate(t()) :: {:ok, t()} | {:error, term()}
  def validate(%__MODULE__{} = p) do
    with :ok <- validate_identity(p),
         :ok <- validate_settings(p.settings),
         :ok <- validate_windows(p),
         :ok <- validate_headers(p),
         :ok <- validate_strategies(p),
         :ok <- validate_hpack(p.hpack) do
      {:ok, p}
    end
  end

  @spec digest(t() | map()) :: {:ok, binary()} | {:error, term()}
  def digest(profile) do
    with {:ok, profile} <- compile(profile) do
      canonical = Map.from_struct(profile) |> Map.to_list()
      {:ok, Base.encode16(:crypto.hash(:sha256, :erlang.term_to_binary(canonical)), case: :lower)}
    end
  end

  @spec settings_payload(t() | map()) :: {:ok, binary()} | {:error, term()}
  def settings_payload(profile) do
    with {:ok, p} <- compile(profile) do
      {:ok, for({id, value} <- p.settings, into: <<>>, do: <<id::16, value::32>>)}
    end
  end

  @spec initial_window_increment(t() | map()) :: {:ok, non_neg_integer()} | {:error, term()}
  def initial_window_increment(profile) do
    with {:ok, p} <- compile(profile),
         increment when increment >= 0 <- p.connection_initial_window - 65_535 do
      {:ok, increment}
    else
      _ -> {:error, :invalid_connection_window}
    end
  end

  @spec order_headers(t(), [{String.t(), String.t()}], [{String.t(), String.t()}]) ::
          [{String.t(), String.t()}]
  @spec order_headers(
          t(),
          [{String.t(), String.t()}],
          [{String.t(), String.t()}],
          :request | :extended_connect
        ) :: [{String.t(), String.t()}]
  def order_headers(%__MODULE__{} = p, pseudo, regular, purpose \\ :request)
      when purpose in [:request, :extended_connect] do
    pseudo_map = Map.new(pseudo)

    pseudo_order =
      if purpose == :extended_connect,
        do: Enum.flat_map(p.pseudo_headers, &extended_pseudo_order/1),
        else: p.pseudo_headers

    ordered_pseudo =
      Enum.flat_map(pseudo_order, fn name ->
        if Map.has_key?(pseudo_map, name), do: [{name, pseudo_map[name]}], else: []
      end)

    regular =
      case p.regular_headers do
        :lexicographic -> Enum.sort_by(regular, &elem(&1, 0))
        :reverse_input -> Enum.reverse(regular)
        :input -> regular
      end

    ordered_pseudo ++ regular
  end

  defp extended_pseudo_order(":method"), do: [":method", ":protocol"]
  defp extended_pseudo_order(name), do: [name]

  defp validate_identity(%{id: id, revision: revision, source: source, evidence: evidence})
       when is_binary(id) and byte_size(id) in 1..128 and is_integer(revision) and revision > 0 and
              ((source == :native and evidence == :engine_verified) or
                 (source == :synthetic and evidence == :synthetic)),
       do: :ok

  defp validate_identity(_), do: {:error, :invalid_identity}

  defp validate_settings(settings) when is_list(settings) do
    ids = for {id, _} <- settings, do: id

    if length(ids) == length(settings) and ids == Enum.uniq(ids) and
         Enum.all?(settings, &valid_setting?/1) and {2, 0} in settings do
      :ok
    else
      {:error, :invalid_settings}
    end
  end

  defp validate_settings(_), do: {:error, :invalid_settings}

  defp valid_setting?({id, value})
       when is_integer(id) and id in [1, 2, 3, 4, 5, 6, 8] and is_integer(value) and
              value in 0..4_294_967_295 do
    case id do
      2 -> value == 0
      4 -> value <= 2_147_483_647
      5 -> value in 16_384..16_777_215
      8 -> value in [0, 1]
      _ -> true
    end
  end

  defp valid_setting?(_), do: false

  defp validate_windows(%{
         connection_initial_window: c,
         stream_initial_window: s,
         receive_window_target: t,
         receive_window_threshold: threshold,
         receive_window_increment: increment,
         settings: settings
       })
       when c in 65_535..1_048_576 and s in 0..1_048_576 and t == 65_535 and
              threshold == 32_767 and increment == 32_767 do
    if s == settings |> Map.new() |> Map.get(4, 65_535),
      do: :ok,
      else: {:error, :inconsistent_stream_window}
  end

  defp validate_windows(_), do: {:error, :invalid_window}

  defp validate_headers(%{pseudo_headers: p}) when is_list(p) do
    if p == Enum.uniq(p) and
         Enum.sort(p) == Enum.sort([":method", ":scheme", ":authority", ":path"]) do
      :ok
    else
      {:error, :invalid_pseudo_header_order}
    end
  end

  defp validate_headers(_), do: {:error, :invalid_pseudo_header_order}

  defp validate_strategies(%{
         regular_headers: r,
         priority: priority,
         push: push,
         padding: padding,
         default_user_agent: user_agent,
         max_header_fragment: header_max,
         max_data_frame: data_max
       })
       when r in [:input, :lexicographic, :reverse_input] and
              priority in [:none, :legacy, :rfc9218] and push == :disabled and
              padding == :none and user_agent == :append and
              is_integer(header_max) and header_max in 1..65_536 and
              is_integer(data_max) and data_max in 1..16_384,
       do: :ok

  defp validate_strategies(_), do: {:error, :unsupported_profile_strategy}

  defp validate_hpack(%{huffman: huffman, indexing: indexing, sensitive: sensitive} = hpack)
       when huffman in [:never, :always] and indexing in [:literal, :never, :incremental] and
              is_list(sensitive) do
    if Enum.sort(Map.keys(hpack)) == [:huffman, :indexing, :sensitive] and
         length(sensitive) <= 64 and
         Enum.all?(sensitive, fn name ->
           is_binary(name) and byte_size(name) in 1..256 and String.valid?(name) and
             String.downcase(name) == name
         end),
       do: :ok,
       else: {:error, :invalid_hpack_strategy}
  end

  defp validate_hpack(_), do: {:error, :invalid_hpack_strategy}

  def settings_defaults, do: @settings_defaults
end
