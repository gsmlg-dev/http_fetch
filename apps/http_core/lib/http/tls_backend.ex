defmodule HTTP.TLSBackend do
  @moduledoc false

  @type t :: :ssl | :ex_ssl

  @spec resolve(term()) :: {:ok, t()} | {:error, :invalid_tls_backend}
  def resolve(value \\ nil)

  def resolve(nil), do: normalize(Application.get_env(:http_core, :tls_backend, :ssl))
  def resolve(value), do: normalize(value)

  @spec transport(t()) :: HTTP.Transport.SSL | HTTP.Transport.ExSSL
  def transport(:ssl), do: HTTP.Transport.SSL
  def transport(:ex_ssl), do: HTTP.Transport.ExSSL

  defp normalize(value) when value in [:ssl, "ssl"], do: {:ok, :ssl}
  defp normalize(value) when value in [:ex_ssl, "ex_ssl"], do: {:ok, :ex_ssl}
  defp normalize(_value), do: {:error, :invalid_tls_backend}
end
