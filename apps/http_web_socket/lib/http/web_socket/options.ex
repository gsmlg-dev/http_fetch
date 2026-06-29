defmodule HTTP.WebSocket.Options do
  @moduledoc false

  @default_timeout 30_000
  @default_connect_timeout 30_000
  @default_max_message_size 16 * 1024 * 1024
  @default_max_send_queue 16 * 1024 * 1024

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
            max_message_size: @default_max_message_size,
            max_send_queue: @default_max_send_queue,
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
          max_message_size: pos_integer(),
          max_send_queue: pos_integer(),
          ref: reference()
        }

  @spec new(String.t() | URI.t(), String.t() | [String.t()], keyword() | map()) ::
          {:ok, t()} | {:error, term()}
  def new(url, protocols \\ [], init \\ []) do
    with {:ok, uri} <- normalize_url(url),
         {:ok, protocols} <- normalize_protocols(protocols),
         {:ok, init} <- normalize_init(init) do
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
         max_message_size: Keyword.get(init, :max_message_size, @default_max_message_size),
         max_send_queue: Keyword.get(init, :max_send_queue, @default_max_send_queue),
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

  defp normalize_uri(%URI{scheme: scheme, host: host} = uri) when is_binary(host) do
    case normalize_scheme(scheme) do
      {:ok, scheme} -> {:ok, %{uri | scheme: scheme}}
      {:error, _reason} = error -> error
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
    |> String.to_charlist()
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

  defp normalize_init(init) when is_map(init), do: init |> Map.to_list() |> normalize_init()

  defp normalize_init(init) when is_list(init) do
    with {:ok, headers} <- normalize_headers(Keyword.get(init, :headers, [])),
         {:ok, binary_type} <- normalize_binary_type(Keyword.get(init, :binary_type, :blob)),
         {:ok, owner} <- normalize_owner(Keyword.get(init, :owner, self())),
         {:ok, ssl} <- normalize_keyword(Keyword.get(init, :ssl, []), :invalid_ssl_options),
         {:ok, socket_opts} <-
           normalize_keyword(Keyword.get(init, :socket_opts, []), :invalid_socket_options) do
      {:ok,
       init
       |> Keyword.put(:headers, headers)
       |> Keyword.put(:binary_type, binary_type)
       |> Keyword.put(:owner, owner)
       |> Keyword.put(:ssl, ssl)
       |> Keyword.put(:socket_opts, socket_opts)}
    end
  end

  defp normalize_init(_init), do: {:error, :invalid_options}

  defp normalize_headers(%HTTP.Headers{headers: headers}), do: normalize_headers(headers)

  defp normalize_headers(headers) when is_map(headers) do
    headers
    |> Map.to_list()
    |> normalize_headers()
  end

  defp normalize_headers(headers) when is_list(headers) do
    headers =
      Enum.map(headers, fn {name, value} ->
        {HTTP.Headers.normalize_name(to_string(name)), to_string(value)}
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
end
