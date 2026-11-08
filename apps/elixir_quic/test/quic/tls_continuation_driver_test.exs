defmodule Quic.TLSContinuationDriverTest do
  use ExUnit.Case, async: true
  alias Quic.TLSDriver

  defmodule Provider do
    def new(_, _) do
      request = %SSL.QUIC.Request{
        id: :request,
        operation: :lookup,
        identity: "ticket",
        context: "partition"
      }

      {:ok, :pending, [{:session_lookup, request}]}
    end

    def info(_), do: %{receive_level: :initial}
    def feed(:pending, _, _), do: raise("feed while continuation pending")
    def feed(state, :initial, bytes), do: {:ok, state, [{:negotiated_alpn, bytes}]}
    def continue(:pending, :request, :miss), do: {:ok, :ready, []}
    def abort(_, _), do: :aborted
  end

  test "pending authority retains contiguous CRYPTO and resumes it exactly once" do
    {:ok, state, [{:session_lookup, _}]} = TLSDriver.new(:server, adapter: Provider)
    {:ok, state, []} = TLSDriver.feed(state, :initial, 0, "retained")
    assert state.future_bytes == 8
    {:ok, next, [{:negotiated_alpn, "retained"}]} = TLSDriver.continue(state, :request, :miss)
    assert next.future_bytes == 0
    assert next.continuation == nil

    assert {:error, %{reason: :invalid_continuation}, ^next, []} =
             TLSDriver.continue(next, :request, :miss)

    assert {:ok, _, []} = TLSDriver.feed(next, :initial, 0, "retained")
  end

  test "pending bytes use the independent future-CRYPTO bound and abort releases request" do
    {:ok, state, _} = TLSDriver.new(:server, adapter: Provider, max_crypto_bytes: 4)
    assert {:error, %{reason: _}, _, []} = TLSDriver.feed(state, :initial, 0, "12_345")
    assert TLSDriver.abort(state, :owner_down).continuation == nil
  end
end
