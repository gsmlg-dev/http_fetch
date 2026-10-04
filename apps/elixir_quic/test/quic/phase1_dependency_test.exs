defmodule Quic.Phase1DependencyTest do
  use ExUnit.Case, async: true

  test "normal application startup includes the pinned TLS runtime" do
    {:ok, applications} = :application.get_key(:elixir_quic, :applications)
    assert :ex_ssl in applications
    assert :ex_ssl in Enum.map(Application.started_applications(), &elem(&1, 0))
    assert Code.ensure_loaded?(SSL.QUIC)
  end
end
