defmodule SSL.CompatibilityHarnessTest do
  use ExUnit.Case, async: true

  alias SSL.Test.Compatibility

  test "enumerates the OTP reference and ex_ssl facade without running a socket scenario" do
    assert [otp: :ssl, ex_ssl: SSL] = Compatibility.implementations()
  end
end
