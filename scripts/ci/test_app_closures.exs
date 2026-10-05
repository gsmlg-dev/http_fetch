# Run with `elixir scripts/ci/test_app_closures.exs`; no dependency build is needed.
Mix.start()
Code.require_file("../../mix.exs", __DIR__)
ExUnit.start()

defmodule AppClosuresTest do
  use ExUnit.Case

  @closures %{
    "ex_ssl" => ~w(ex_ssl)a,
    "elixir_quic" => ~w(ex_ssl elixir_quic)a,
    "http_core" => ~w(ex_ssl elixir_quic http_core)a,
    "http_runtime" => ~w(ex_ssl elixir_quic http_core http_runtime)a,
    "elixir_quic_http3" => ~w(ex_ssl elixir_quic http_core elixir_quic_http3)a,
    "http_fetch" => ~w(ex_ssl elixir_quic http_core http_runtime http_fetch)a,
    "http_web_socket" => ~w(ex_ssl elixir_quic http_core http_runtime http_web_socket)a,
    "http_event_source" => ~w(ex_ssl elixir_quic http_core http_runtime http_event_source)a,
    "http_web_transport" => ~w(ex_ssl elixir_quic http_core http_web_transport)a
  }

  setup do
    original_app = System.get_env("HTTP_FETCH_CI_APP")
    original_env = Mix.env()

    on_exit(fn ->
      if original_app,
        do: System.put_env("HTTP_FETCH_CI_APP", original_app),
        else: System.delete_env("HTTP_FETCH_CI_APP")

      Mix.env(original_env)
    end)
  end

  test "production and development closures contain only runtime dependencies" do
    for env <- [:dev, :prod], {app, expected} <- @closures do
      Mix.env(env)
      System.put_env("HTTP_FETCH_CI_APP", app)
      assert HttpFetch.Umbrella.MixProject.project()[:apps] == expected
    end
  end

  test "test closures add fetch only for consumers that exercise shared HTTP traffic" do
    Mix.env(:test)

    for {app, runtime} <- @closures do
      System.put_env("HTTP_FETCH_CI_APP", app)

      expected =
        if app in ["http_web_socket", "http_event_source"],
          do: MapSet.new([:http_fetch | runtime]),
          else: MapSet.new(runtime)

      assert MapSet.new(HttpFetch.Umbrella.MixProject.project()[:apps]) == expected
    end
  end

  test "Dialyzer analyzes the selected owner and defaults to all umbrella paths when unset" do
    for {app, _closure} <- @closures do
      System.put_env("HTTP_FETCH_CI_APP", app)
      options = HttpFetch.Umbrella.MixProject.project()[:dialyzer]

      expected =
        Path.join([
          Mix.Project.build_path(build_path: "_build", build_per_environment: true),
          "lib",
          app,
          "ebin"
        ])

      assert options[:paths] == [expected]
      assert options[:ignore_warnings] == ".dialyzer_ignore.exs"
      assert options[:flags] == [:unmatched_returns, :error_handling, :underspecs]
    end

    System.delete_env("HTTP_FETCH_CI_APP")
    assert HttpFetch.Umbrella.MixProject.project()[:dialyzer][:paths] == nil
  end

  test "unselected umbrella remains unrestricted and unknown apps fail clearly" do
    System.delete_env("HTTP_FETCH_CI_APP")
    assert HttpFetch.Umbrella.MixProject.project()[:apps] == nil
    System.put_env("HTTP_FETCH_CI_APP", "unknown")

    assert_raise RuntimeError, ~s(invalid HTTP_FETCH_CI_APP: "unknown"), fn ->
      HttpFetch.Umbrella.MixProject.project()
    end
  end
end
