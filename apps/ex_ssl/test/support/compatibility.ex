defmodule SSL.Test.Compatibility do
  @moduledoc false

  @implementations [otp: :ssl, ex_ssl: SSL]

  @spec implementations() :: [{:otp, :ssl} | {:ex_ssl, SSL}, ...]
  def implementations, do: @implementations
end
