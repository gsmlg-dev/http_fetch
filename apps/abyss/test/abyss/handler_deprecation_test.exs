defmodule Abyss.HandlerDeprecationTest do
  # Not async: the warning is once per VM, tracked in :persistent_term.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  @key {Abyss.ServerConfig, :handler_module_deprecation_warned}

  test "handler_module logs a one-time deprecation warning" do
    :persistent_term.erase(@key)

    log =
      capture_log(fn ->
        Abyss.ServerConfig.new(handler_module: Abyss.TestHandler)
        Abyss.ServerConfig.new(handler_module: Abyss.TestHandler)
      end)

    assert [_one] = Regex.scan(~r/:handler_module.*deprecated/, log)
  end

  test "datagram_handler does not warn" do
    :persistent_term.erase(@key)

    assert capture_log(fn ->
             Abyss.ServerConfig.new(datagram_handler: Abyss.Test.SendAccountingHandler)
           end) == ""
  end

  test "use Abyss.Handler is deprecated at compile time" do
    {_result, diagnostics} =
      Code.with_diagnostics(fn ->
        Code.compile_string("defmodule Abyss.DeprecatedUse do\n  use Abyss.Handler\nend")
      end)

    assert Enum.any?(diagnostics, &(&1.message =~ "use Abyss.Handler is deprecated"))
  after
    :code.purge(Abyss.DeprecatedUse)
    :code.delete(Abyss.DeprecatedUse)
  end
end
