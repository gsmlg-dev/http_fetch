defmodule HTTP.WebSocket.Options do
  @moduledoc false

  @default_timeout 30_000
  @default_connect_timeout 30_000
  @default_max_message_size 16 * 1024 * 1024
  @default_max_send_queue 16 * 1024 * 1024

  @string_keys %{
    "owner" => :owner,
    "headers" => :headers,
    "timeout" => :timeout,
    "connect_timeout" => :connect_timeout,
    "opening_timeout" => :opening_timeout,
    "idle_timeout" => :idle_timeout,
    "close_timeout" => :close_timeout,
    "binary_type" => :binary_type,
    "ssl" => :ssl,
    "socket_opts" => :socket_opts,
    "unix_socket" => :unix_socket,
    "max_message_size" => :max_message_size,
    "max_send_queue" => :max_send_queue,
    "max_send_frames" => :max_send_frames,
    "max_control_frames" => :max_control_frames,
    "max_frame_parts" => :max_frame_parts,
    "tls_backend" => :tls_backend,
    "tlsBackend" => :tls_backend,
    "openingTimeout" => :opening_timeout,
    "idleTimeout" => :idle_timeout,
    "closeTimeout" => :close_timeout,
    "maxMessageSize" => :max_message_size,
    "maxSendQueue" => :max_send_queue,
    "maxSendFrames" => :max_send_frames,
    "maxControlFrames" => :max_control_frames,
    "maxFrameParts" => :max_frame_parts
  }

  defstruct uri: nil,
            url: nil,
            protocols: [],
            owner: nil,
            binary_type: :blob,
            headers: [],
            timeout: @default_timeout,
            connect_timeout: @default_connect_timeout,
            ssl: [],
            socket_opts: [],
            tls_backend: :ssl,
            max_message_size: @default_max_message_size,
            max_send_queue: @default_max_send_queue,
            http_version: :http1,
            http2_profile: nil,
            http2_scope: nil,
            http2_reuse: true,
            unix_socket: nil,
            delivery: :legacy,
            max_queue_bytes: 2 * @default_max_message_size + 7,
            max_queue_events: 64,
            opening_timeout: @default_timeout,
            idle_timeout: :infinity,
            close_timeout: 5_000,
            max_send_frames: 64,
            max_control_frames: 16,
            max_frame_parts: 16_384,
            ref: nil

  @type t :: %__MODULE__{
          uri: URI.t(),
          url: String.t(),
          protocols: [String.t()],
          owner: pid(),
          binary_type: :blob | :array_buffer,
          headers: [{String.t(), String.t()}],
          timeout: timeout(),
          connect_timeout: timeout(),
          ssl: keyword(),
          socket_opts: keyword(),
          tls_backend: HTTP.TLSBackend.t(),
          max_message_size: pos_integer(),
          max_send_queue: pos_integer(),
          http_version: :http1 | :http2 | :h2c | :auto,
          http2_profile: HTTP.HTTP2.WireProfile.t() | nil,
          http2_scope: atom() | binary() | nil,
          http2_reuse: boolean(),
          unix_socket: binary() | nil,
          delivery: :legacy | :ack,
          max_queue_bytes: pos_integer(),
          max_queue_events: pos_integer(),
          opening_timeout: timeout(),
          idle_timeout: timeout(),
          close_timeout: timeout(),
          max_send_frames: pos_integer(),
          max_control_frames: pos_integer(),
          max_frame_parts: pos_integer(),
          ref: reference()
        }

  @spec new(String.t() | URI.t(), String.t() | [String.t()], keyword() | map()) ::
          {:ok, t()} | {:error, term()}
  def new(url, protocols \\ [], init \\ []) do
    with {:ok, uri} <- normalize_url(url),
         {:ok, protocols} <- normalize_protocols(protocols),
         {:ok, init} <- normalize_init(init),
         {:ok, init} <- HTTP.Runtime.Options.validate(uri, init),
         :ok <- validate_limits(init),
         :ok <- validate_delivery_capacity(init) do
      {:ok,
       %__MODULE__{
         uri: uri,
         url: URI.to_string(uri),
         protocols: protocols,
         owner: Keyword.get(init, :owner, self()),
         binary_type: Keyword.get(init, :binary_type, :blob),
         headers: Keyword.get(init, :headers, []),
         timeout: Keyword.get(init, :timeout, @default_timeout),
         connect_timeout: Keyword.get(init, :connect_timeout, @default_connect_timeout),
         ssl: Keyword.get(init, :ssl, []),
         socket_opts: Keyword.get(init, :socket_opts, []),
         tls_backend: Keyword.fetch!(init, :tls_backend),
         max_message_size: Keyword.get(init, :max_message_size, @default_max_message_size),
         max_send_queue: Keyword.get(init, :max_send_queue, @default_max_send_queue),
         http_version: Keyword.fetch!(init, :http_version),
         http2_profile: Keyword.get(init, :http2_profile),
         http2_scope: Keyword.get(init, :http2_scope),
         http2_reuse: Keyword.get(init, :http2_reuse, true),
         unix_socket: Keyword.get(init, :unix_socket),
         delivery: Keyword.fetch!(init, :delivery),
         max_queue_bytes: Keyword.fetch!(init, :max_queue_bytes),
         max_queue_events: Keyword.get(init, :max_queue_events, 64),
         opening_timeout:
           Keyword.get(init, :opening_timeout, Keyword.get(init, :timeout, @default_timeout)),
         idle_timeout: Keyword.get(init, :idle_timeout, :infinity),
         close_timeout: Keyword.get(init, :close_timeout, 5_000),
         max_send_frames: Keyword.get(init, :max_send_frames, 64),
         max_control_frames: Keyword.get(init, :max_control_frames, 16),
         max_frame_parts: Keyword.get(init, :max_frame_parts, 16_384),
         ref: Keyword.get(init, :ref, make_ref())
       }}
    end
  end

  defp normalize_url(%URI{} = uri), do: normalize_uri(uri)

  defp normalize_url(url) when is_binary(url) do
    url
    |> URI.parse()
    |> normalize_uri()
  end

  defp normalize_url(_url), do: {:error, :invalid_url}

  defp normalize_uri(%URI{fragment: fragment}) when is_binary(fragment),
    do: {:error, :fragment_not_allowed}

  defp normalize_uri(%URI{userinfo: userinfo}) when not is_nil(userinfo),
    do: {:error, :invalid_url}

  defp normalize_uri(%URI{scheme: scheme, host: host, port: port} = uri) when is_binary(host) do
    case normalize_scheme(scheme) do
      {:ok, scheme} ->
        if host != "" and String.valid?(host) and
             not Enum.any?(:binary.bin_to_list(host), &(&1 <= 32 or &1 == 127)) and
             (is_nil(port) or (is_integer(port) and port in 1..65_535)) and
             valid_target?(uri.path) and valid_target?(uri.query),
           do: {:ok, %{uri | scheme: scheme}},
           else: {:error, :invalid_url}

      {:error, _reason} = error ->
        error
    end
  end

  defp normalize_uri(%URI{scheme: scheme}), do: {:error, {:unsupported_scheme, scheme}}

  defp normalize_scheme("ws"), do: {:ok, "ws"}
  defp normalize_scheme("wss"), do: {:ok, "wss"}
  defp normalize_scheme("http"), do: {:ok, "ws"}
  defp normalize_scheme("https"), do: {:ok, "wss"}
  defp normalize_scheme(scheme), do: {:error, {:unsupported_scheme, scheme}}

  defp normalize_protocols(nil), do: {:ok, []}
  defp normalize_protocols(""), do: {:ok, []}
  defp normalize_protocols(protocol) when is_binary(protocol), do: normalize_protocols([protocol])

  defp normalize_protocols(protocols) when is_list(protocols) do
    with :ok <- validate_protocols(protocols),
         :ok <- reject_duplicate_protocols(protocols) do
      {:ok, protocols}
    end
  end

  defp normalize_protocols(_protocols), do: {:error, :invalid_protocols}

  defp validate_protocols(protocols) do
    if Enum.all?(protocols, &valid_protocol?/1) do
      :ok
    else
      {:error, :invalid_protocol}
    end
  end

  defp valid_protocol?(protocol) when is_binary(protocol) and byte_size(protocol) > 0 do
    protocol
    |> :binary.bin_to_list()
    |> Enum.all?(&valid_token_char?/1)
  end

  defp valid_protocol?(_protocol), do: false

  defp valid_token_char?(char) when char < 33 or char > 126, do: false
  defp valid_token_char?(char), do: char not in ~c"()<>@,;:\\\"/[]?={} \t"

  defp reject_duplicate_protocols(protocols) do
    if Enum.uniq(protocols) == protocols do
      :ok
    else
      {:error, :duplicate_protocol}
    end
  end

  defp normalize_init(init) when is_map(init) do
    init
    |> Enum.map(fn {key, value} -> {normalize_key(key), value} end)
    |> normalize_init()
  end

  defp normalize_init(init) when is_list(init) do
    if Enum.all?(init, fn
         {key, _value} -> is_atom(key) or is_binary(key)
         _ -> false
       end) do
      init
      |> Enum.map(fn {key, value} -> {normalize_key(key), value} end)
      |> HTTP.Runtime.Options.normalize_keys()
      |> normalize_options()
    else
      {:error, :invalid_options}
    end
  end

  defp normalize_init(_init), do: {:error, :invalid_options}

  defp normalize_options(init) do
    with {:ok, headers} <- normalize_headers(Keyword.get(init, :headers, [])),
         {:ok, binary_type} <- normalize_binary_type(Keyword.get(init, :binary_type, :blob)),
         {:ok, owner} <- normalize_owner(Keyword.get(init, :owner, self())),
         {:ok, ssl} <- normalize_keyword(Keyword.get(init, :ssl, []), :invalid_ssl_options),
         {:ok, socket_opts} <-
           normalize_keyword(Keyword.get(init, :socket_opts, []), :invalid_socket_options),
         {:ok, tls_backend} <- HTTP.TLSBackend.resolve(Keyword.get(init, :tls_backend)) do
      {:ok,
       init
       |> Keyword.put(:headers, headers)
       |> Keyword.put(:binary_type, binary_type)
       |> Keyword.put(:owner, owner)
       |> Keyword.put(:ssl, ssl)
       |> Keyword.put(:socket_opts, socket_opts)
       |> Keyword.put(:tls_backend, tls_backend)
       |> Keyword.put_new(:max_queue_bytes, 2 * valid_message_limit(init) + 7)}
    end
  end

  defp normalize_key(key) when is_binary(key), do: Map.get(@string_keys, key, key)
  defp normalize_key(key), do: key

  defp normalize_headers(%HTTP.Headers{headers: headers}), do: normalize_headers(headers)

  defp normalize_headers(headers) when is_map(headers) do
    headers
    |> Map.to_list()
    |> normalize_headers()
  end

  defp normalize_headers(headers) when is_list(headers) do
    headers =
      Enum.map(headers, fn {name, value} ->
        name = to_string(name)
        value = to_string(value)

        if not valid_protocol?(name) or not String.valid?(value) or
             Enum.any?(:binary.bin_to_list(value), &((&1 < 32 and &1 != 9) or &1 == 127)),
           do: raise(ArgumentError, "invalid header")

        {HTTP.Headers.normalize_name(name), value}
      end)

    {:ok, headers}
  rescue
    _error -> {:error, :invalid_headers}
  end

  defp normalize_headers(_headers), do: {:error, :invalid_headers}

  defp normalize_binary_type(type) when type in [:blob, :array_buffer], do: {:ok, type}
  defp normalize_binary_type(_type), do: {:error, :invalid_binary_type}

  defp normalize_owner(owner) when is_pid(owner), do: {:ok, owner}
  defp normalize_owner(_owner), do: {:error, :invalid_owner}

  defp normalize_keyword(value, _error) when is_list(value), do: {:ok, value}
  defp normalize_keyword(_value, error), do: {:error, error}
  defp valid_target?(nil), do: true

  defp valid_target?(value) when is_binary(value),
    do:
      String.valid?(value) and not Enum.any?(:binary.bin_to_list(value), &(&1 <= 32 or &1 == 127))

  defp valid_target?(_value), do: false

  defp valid_message_limit(init) do
    case Keyword.get(init, :max_message_size, @default_max_message_size) do
      value when is_integer(value) and value > 0 -> value
      _ -> @default_max_message_size
    end
  end

  defp validate_limits(init) do
    limits = [
      max_message_size: @default_max_message_size,
      max_send_queue: @default_max_send_queue,
      max_send_frames: 64,
      max_control_frames: 16,
      max_frame_parts: 16_384
    ]

    timeouts = [
      timeout: @default_timeout,
      connect_timeout: @default_connect_timeout,
      opening_timeout: Keyword.get(init, :timeout, @default_timeout),
      idle_timeout: :infinity,
      close_timeout: 5_000
    ]

    Enum.reduce_while(limits ++ timeouts, :ok, fn {key, default}, :ok ->
      value = Keyword.get(init, key, default)

      if (is_integer(value) and value > 0) or
           (Keyword.has_key?(timeouts, key) and value == :infinity),
         do: {:cont, :ok},
         else: {:halt, {:error, {:invalid_option, key}}}
    end)
  end

  defp validate_delivery_capacity(init) do
    if init[:delivery] == :ack and init[:max_queue_bytes] < valid_message_limit(init) + 7,
      do: {:error, :message_limit_exceeds_delivery_limit},
      else: :ok
  end
end
