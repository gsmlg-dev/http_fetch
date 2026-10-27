defmodule HTTP.ProtocolClient.OptionsTest do
  use ExUnit.Case, async: true
  alias HTTP.ProtocolClient

  test "unsupported routes and nonfinite or malformed settings fail before connecting" do
    for {url, options} <- [
          {"https://127.0.0.1:9", []},
          {"http://user:secret@127.0.0.1:9", []},
          {"http://127.0.0.1:9", [timeout: :infinity]},
          {"http://127.0.0.1:9", [settings: [initial_window_size: -1]]},
          {"http://127.0.0.1:9", [settings: [enable_push: 1]]},
          {"http://127.0.0.1:9", [settings: [:invalid]]},
          {"http://127.0.0.1:9", [unknown: true]}
        ] do
      assert {:error, :invalid_options} = ProtocolClient.connect(url, options)
    end
  end
end
