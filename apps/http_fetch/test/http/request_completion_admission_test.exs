defmodule HTTP.RequestCompletionAdmissionTest do
  use ExUnit.Case, async: true

  alias HTTP.{FetchOptions, Request, RequestCompletion}

  for version <- [:http1, :http2, :h2c] do
    test "plaintext #{version} completion is admitted" do
      options =
        FetchOptions.new(
          http_version: unquote(version),
          redirect: :manual
        )

      request = %Request{url: URI.parse("http://example.test/")}
      handle = RequestCompletion.new(options, request)

      try do
        assert %RequestCompletion{unsupported: nil, tracker: tracker} = handle
        assert is_pid(tracker)
        assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
      after
        if is_pid(handle.tracker) and Process.alive?(handle.tracker),
          do: GenServer.stop(handle.tracker)
      end
    end
  end

  test "plaintext selection retains the unsupported scope boundary" do
    options = FetchOptions.new(redirect: :manual)
    request = %Request{url: URI.parse("http://example.test/")}
    options = %{options | transport_scope: :not_integrated}

    assert {:error, {:unsupported_completion, :tls_backend}} =
             options |> RequestCompletion.new(request) |> RequestCompletion.await(0)
  end
end
