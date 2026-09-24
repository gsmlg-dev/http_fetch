defmodule HTTP.HTTP2.ProfileCapture do
  @moduledoc "Builds and validates provenance manifests for HTTP/2 captures."

  @required ~w(product version platform captured_at tool origin protocol connection_context fixture_digest license matched_fields known_differences)a
  @sources [:synthetic, :reference_derived, :captured_verified]
  @protocols [:h2, :h2c]
  @contexts [:cold, :reused]

  @spec build_manifest(binary(), map()) :: {:ok, map()} | {:error, term()}
  def build_manifest(fixture, attrs) when is_binary(fixture) and is_map(attrs) do
    attrs = Map.put(attrs, :fixture_digest, digest(fixture))
    validate_manifest(attrs)
  end

  def build_manifest(_, _), do: {:error, :invalid_capture_input}

  @spec validate_manifest(map()) :: {:ok, map()} | {:error, term()}
  def validate_manifest(manifest) when is_map(manifest) do
    with :ok <- required_fields(manifest),
         :ok <- validate_source(manifest),
         :ok <- validate_protocol(manifest),
         :ok <- validate_context(manifest),
         :ok <- validate_digest(manifest),
         :ok <- validate_lists(manifest) do
      {:ok, Map.put_new(manifest, :version_schema, 1)}
    end
  end

  def validate_manifest(_), do: {:error, :invalid_manifest}

  @spec digest(binary()) :: String.t()
  def digest(fixture) when is_binary(fixture),
    do: Base.encode16(:crypto.hash(:sha256, fixture), case: :lower)

  defp required_fields(manifest) do
    case Enum.find(@required, &(not Map.has_key?(manifest, &1))) do
      nil -> :ok
      field -> {:error, {:missing_manifest_field, field}}
    end
  end

  defp validate_source(%{source: source}) when source in @sources, do: :ok
  defp validate_source(_), do: {:error, {:invalid_manifest_field, :source}}

  defp validate_protocol(%{protocol: protocol}) when protocol in @protocols, do: :ok
  defp validate_protocol(_), do: {:error, {:invalid_manifest_field, :protocol}}

  defp validate_context(%{connection_context: context}) when context in @contexts, do: :ok
  defp validate_context(_), do: {:error, {:invalid_manifest_field, :connection_context}}

  defp validate_digest(%{fixture_digest: digest})
       when is_binary(digest) and byte_size(digest) == 64 do
    if digest =~ ~r/\A[0-9a-f]{64}\z/, do: :ok, else: {:error, :invalid_fixture_digest}
  end

  defp validate_digest(_), do: {:error, :invalid_fixture_digest}

  defp validate_lists(%{matched_fields: matched, known_differences: differences})
       when is_list(matched) and is_list(differences),
       do: :ok

  defp validate_lists(_), do: {:error, :invalid_manifest_fields}
end
