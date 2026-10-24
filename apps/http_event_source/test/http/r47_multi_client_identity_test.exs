defmodule HTTP.R47MultiClientIdentityEventSourceTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F
  alias HTTP.EventSource
  alias HTTP.EventSource.Event.{Message, Open}

  setup_all do
    directory = Path.join(System.tmp_dir!(), "r47-sse-#{System.unique_integer([:positive])}")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  for version <- ["tls12", "tls13"] do
    test "#{version} ordinary SSE selects the exact later identity and delivers event bytes", %{
      fixtures: m
    } do
      version = unquote(version)

      {result, events} =
        F.with_peer(m, [version: version, hint: "client-a", application: "sse"], fn port ->
          source =
            EventSource.new("https://127.0.0.1:#{port}/r47",
              tls_backend: :ex_ssl,
              http_version: :http1,
              ssl: F.options(m, ["p256-b", "rsa2048-a"], version)
            )

          try do
            assert_receive {EventSource, ^source, %Open{}}, 3_000

            assert_receive {EventSource, ^source,
                            %Message{data: "r47-sse-ok", last_event_id: "r47"}},
                           3_000

            :received
          after
            EventSource.close(source)
          end
        end)

      assert result == :received
      F.assert_authenticated(m, events, "rsa2048-a", 0x0804, version)

      assert [%{"application" => "sse", "request_exact" => true, "response_written" => true}] =
               Enum.filter(events, &(&1["event"] == "http"))
    end
  end
end
