defmodule SSL.Protocol.Resumption do
  @moduledoc "Pure TLS 1.3 resumption ticket binder construction over exact ClientHello bytes."

  alias SSL.Crypto.{HKDF, KeySchedule}
  alias SSL.Protocol.ClientOffer
  alias SSL.SessionTicket

  @age_modulus 0x1_0000_0000

  @spec psk_extension(SessionTicket.t(), integer()) :: {:ok, binary()} | {:error, atom()}
  def psk_extension(ticket, now_ms) when is_integer(now_ms) do
    with :ok <- SessionTicket.validate(ticket),
         :ok <- valid_age(ticket, now_ms) do
      age = rem(now_ms - ticket.issued_at + ticket.age_add, @age_modulus)
      identity = <<byte_size(ticket.ticket)::16, ticket.ticket::binary, age::32>>
      binder_length = byte_size(ticket.psk)
      binder = :binary.copy(<<0>>, binder_length)

      {:ok,
       <<byte_size(identity)::16, identity::binary, binder_length + 1::16, binder_length,
         binder::binary>>}
    end
  end

  def psk_extension(_ticket, _now_ms), do: {:error, :invalid_time}

  @spec bind(binary(), SessionTicket.t(), binary()) :: {:ok, binary()} | {:error, atom()}
  def bind(encoded_client_hello, ticket, prefix \\ <<>>)

  def bind(encoded_client_hello, ticket, prefix)
      when is_binary(encoded_client_hello) and is_binary(prefix) do
    with :ok <- SessionTicket.validate(ticket),
         {:ok, offer} <- ClientOffer.from_client_hello(encoded_client_hello),
         :ok <- validate_offer(offer),
         {:ok, partial} <- truncated_client_hello(encoded_client_hello, offer, ticket),
         {:ok, early} <- KeySchedule.early_secret(ticket.hash, ticket.psk),
         binder_key when is_binary(binder_key) <-
           HKDF.derive_secret(ticket.hash, early, "res binder", :crypto.hash(ticket.hash, <<>>)),
         {:ok, finished_key} <- KeySchedule.finished_key(ticket.hash, binder_key),
         {:ok, binder} <-
           KeySchedule.finished_verify_data(
             ticket.hash,
             finished_key,
             :crypto.hash(ticket.hash, [prefix, partial])
           ) do
      {:ok, <<partial::binary, byte_size(binder) + 1::16, byte_size(binder), binder::binary>>}
    else
      {:error, _} = error -> error
    end
  end

  def bind(_encoded_client_hello, _ticket, _prefix), do: {:error, :invalid_input}

  defp valid_age(ticket, now_ms) do
    if now_ms >= ticket.issued_at and now_ms < ticket.expires_at,
      do: :ok,
      else: {:error, :expired}
  end

  defp validate_offer(offer) do
    cond do
      offer.psk_count != 1 -> {:error, :invalid_psk_count}
      offer.psk_key_exchange_modes != [1] -> {:error, :invalid_psk_mode}
      0x0304 not in offer.offered_versions -> {:error, :invalid_version}
      offer.key_shares == [] -> {:error, :missing_key_share}
      true -> :ok
    end
  end

  defp truncated_client_hello(encoded, offer, ticket) do
    binder_length = byte_size(ticket.psk)

    case List.last(offer.extensions) do
      {41, payload} ->
        extension_size = byte_size(payload) + 4
        encoded_size = byte_size(encoded)

        case encoded do
          <<_head::binary-size(^encoded_size - ^extension_size), 41::16, payload_size::16,
            ^payload::binary-size(payload_size)>> ->
            case payload do
              <<identity_size::16, identity::binary-size(identity_size), binders_size::16,
                ^binder_length, binder::binary-size(^binder_length)>>
              when binders_size == binder_length + 1 ->
                truncate_identity(
                  identity,
                  ticket,
                  binder,
                  binder_length,
                  encoded,
                  encoded_size,
                  binders_size
                )

              _ ->
                {:error, :invalid_binder_placeholder}
            end

          _ ->
            {:error, :invalid_psk_extension}
        end

      _ ->
        {:error, :pre_shared_key_not_last}
    end
  end

  defp truncate_identity(
         identity,
         ticket,
         binder,
         binder_length,
         encoded,
         encoded_size,
         binders_size
       ) do
    case identity do
      <<ticket_size::16, offered::binary-size(ticket_size), _age::32>> ->
        cond do
          offered != ticket.ticket ->
            {:error, :ticket_identity_mismatch}

          binder != :binary.copy(<<0>>, binder_length) ->
            {:error, :invalid_binder_placeholder}

          true ->
            {:ok, binary_part(encoded, 0, encoded_size - 2 - binders_size)}
        end

      _ ->
        {:error, :ticket_identity_mismatch}
    end
  end
end
