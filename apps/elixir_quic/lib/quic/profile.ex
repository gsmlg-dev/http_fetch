defmodule Quic.Profile do
  @moduledoc """
  Capability-checked client wire policy for Quic.

  A profile contains ordered policy only. `SSL.ClientHello.Materializer` keeps
  the ClientHello random and key shares fresh for every materialization.
  Profile names describe local policy and are not browser identities or hash
  targets.
  """

  alias SSL.ClientHello.{Materializer, Profile, RecordPolicy, WireProfile}

  @type name :: :ordered | :compact
  @type t :: %{
          name: name(),
          tls: WireProfile.t(),
          transport_parameters: binary(),
          cid_length: 8..20,
          max_packet_size: pos_integer()
        }

  @spec compile(name(), keyword()) :: {:ok, t()} | {:error, term()}
  def compile(name, opts \\ [])

  def compile(name, opts) when name in [:ordered, :compact] and is_list(opts) do
    tp = Keyword.get(opts, :transport_parameters, <<>>)
    alpn = Keyword.get(opts, :alpn, ["ex-quic"])

    with :ok <- validate_transport_parameters(tp),
         :ok <- validate_alpn(alpn),
         {:ok, profile} <- validate_wire(name, tp, alpn),
         {:ok, cid_length} <- cid_length(Keyword.get(opts, :cid_length, default_cid(name))),
         {:ok, max_packet_size} <- packet_size(Keyword.get(opts, :max_packet_size, 1_350)) do
      {:ok,
       %{
         name: name,
         tls: profile,
         transport_parameters: tp,
         cid_length: cid_length,
         max_packet_size: max_packet_size
       }}
    else
      {:error, _} = error -> error
    end
  end

  def compile(name, _opts), do: {:error, {:invalid_profile, name}}

  @doc "Return the two built-in legal policy variants."
  def builtins do
    {:ok, ordered} = compile(:ordered)
    {:ok, compact} = compile(:compact)
    %{ordered: ordered, compact: compact}
  end

  @doc "Materialize one profile with fresh per-connection random values."
  def materialize(%{tls: profile}, context \\ %{}) when is_map(context) do
    Materializer.materialize(profile, capabilities(), context)
  end

  @doc "Convert the current public ex_ssl capability report to profile capabilities."
  def capabilities do
    caps = SSL.QUIC.capabilities()

    %{
      versions: [0x0304],
      ciphers: Enum.map(caps.cipher_suites, & &1.id),
      groups: Enum.map(caps.groups, & &1.id),
      signature_algorithms: Enum.map(caps.signatures, & &1.id),
      certificate_signature_algorithms: Enum.map(caps.signatures, & &1.id),
      raw_extensions: [57],
      record_modes: [:none]
    }
  end

  defp validate_wire(name, transport_parameters, alpn) do
    profile = %WireProfile{
      session_id: :empty,
      record: %RecordPolicy{mode: :none},
      cipher_suites: if(name == :ordered, do: [0x1301, 0x1302], else: [0x1302, 0x1301]),
      extensions: [
        {:supported_versions, [0x0304]},
        {:supported_groups, if(name == :ordered, do: [0x001D, 0x0017], else: [0x0017, 0x001D])},
        {:signature_algorithms, [0x0403, 0x0804]},
        {:signature_algorithms_cert, [0x0403, 0x0804]},
        {:alpn, alpn},
        {:key_share, [0x001D]},
        {:raw, 57, transport_parameters}
      ]
    }

    case Profile.validate(profile, capabilities()) do
      {:ok, validated} -> {:ok, validated}
      {:error, reason} -> {:error, {:invalid_profile, reason}}
    end
  end

  defp validate_transport_parameters(tp) when is_binary(tp) and byte_size(tp) <= 65_000,
    do: :ok

  defp validate_transport_parameters(_), do: {:error, {:invalid_profile, :transport_parameters}}

  defp validate_alpn(alpn) when is_list(alpn) and alpn != [] do
    if Enum.all?(alpn, &(is_binary(&1) and byte_size(&1) in 1..255)) and
         Enum.sum(Enum.map(alpn, &byte_size/1)) + length(alpn) <= 65_535,
       do: :ok,
       else: {:error, {:invalid_profile, :alpn}}
  end

  defp validate_alpn(_), do: {:error, {:invalid_profile, :alpn}}

  defp cid_length(value) when is_integer(value) and value in 8..20, do: {:ok, value}
  defp cid_length(_), do: {:error, {:invalid_profile, :cid_length}}

  defp packet_size(value) when is_integer(value) and value >= 1200 and value <= 65_527,
    do: {:ok, value}

  defp packet_size(_), do: {:error, {:invalid_profile, :max_packet_size}}
  defp default_cid(:ordered), do: 8
  defp default_cid(:compact), do: 16
end
