defmodule HTTP.ProtocolClient.OptionsTest do
  use ExUnit.Case, async: true
  alias HTTP.ProtocolClient

  test "unsupported routes fail before connecting" do
    for url <- ["https://127.0.0.1:9", "http://user:secret@127.0.0.1:9", "http://127.0.0.1:9#x"] do
      assert {:error, :invalid_url} = ProtocolClient.connect(url, [])
    end
  end

  test "unknown keys and nonfinite or malformed options raise ArgumentError before connecting" do
    for {options, reason} <- [
          {[timeout: :infinity], {:invalid_option, :timeout}},
          {[protocol: :http3], {:invalid_option, :protocol}},
          {[settings: [initial_window_size: -1]], {:invalid_option, :settings}},
          {[settings: [enable_push: 1]], {:invalid_option, :settings}},
          {[settings: [:invalid]], {:invalid_option, :settings}},
          {[settings: :invalid], {:invalid_option, :settings}},
          {[:bad], :invalid_options},
          {:bad, :invalid_options}
        ] do
      assert_raise ArgumentError,
                   "invalid HTTP.ProtocolClient options: #{inspect(reason)}",
                   fn -> ProtocolClient.connect("http://127.0.0.1:9", options) end
    end

    for key <- [:unknown, :tls_backend] do
      assert_raise ArgumentError, "unknown HTTP.ProtocolClient option: #{inspect(key)}", fn ->
        ProtocolClient.connect("http://127.0.0.1:9", [{key, true}])
      end
    end
  end
end
