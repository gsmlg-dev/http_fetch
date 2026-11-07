defmodule HTTP.Test.VerificationError do
  @moduledoc "Raised when fixture expectations, callbacks or cleanup fail verification."
  defexception [:message, failures: []]
end
