defmodule HTTP.H3.WebTransport.Draft17 do
  @moduledoc "Explicit draft-17 codecs. These primitives do not advertise runtime interoperability."
  alias HTTP.H3.{Capsule, Settings, Varint}
  @max_session_id 4_611_686_018_427_387_900

  def client_settings do
    [
      {Settings.wt_enabled_draft17(), 1},
      {Settings.h3_datagram(), 1},
      {Settings.wt_initial_max_streams_uni(), 0},
      {Settings.wt_initial_max_streams_bidi(), 0},
      {Settings.wt_initial_max_data(), 0}
    ]
  end

  def validate_server_settings(settings) do
    with :ok <- Settings.validate(settings),
         {:ok, settings} <- Settings.normalize(settings) do
      Enum.reduce_while(
        [
          {Settings.wt_enabled_draft17(), :webtransport_draft17_not_enabled},
          {Settings.h3_datagram(), :h3_datagram_disabled},
          {Settings.enable_connect_protocol(), :extended_connect_disabled}
        ],
        :ok,
        fn {id, reason}, :ok ->
          if List.keyfind(settings, id, 0) == {id, 1},
            do: {:cont, :ok},
            else: {:halt, {:error, reason}}
        end
      )
    end
  end

  def prefix(kind, session_id) when kind in [:uni, :bidi] do
    if valid_session_id?(session_id) do
      {:ok, Varint.encode!(if(kind == :uni, do: 0x54, else: 0x41)) <> Varint.encode!(session_id)}
    else
      {:error, :invalid_session_id}
    end
  end

  def decode_prefix(kind, bytes) when kind in [:uni, :bidi] and is_binary(bytes) do
    expected = if kind == :uni, do: 0x54, else: 0x41

    with {:ok, ^expected, rest} <- Varint.decode(bytes),
         {:ok, id, payload} <- Varint.decode(rest) do
      if valid_session_id?(id), do: {:ok, id, payload}, else: {:error, :invalid_session_id}
    else
      :more -> :more
      {:ok, _, _} -> {:error, :invalid_webtransport_prefix}
    end
  end

  def application_error(code) when is_integer(code) and code in 0..0xFFFFFFFF,
    do: {:ok, 0x52E4A40FA8DB + code + div(code, 0x1E)}

  def application_error(_), do: {:error, :invalid_application_error}

  def decode_application_error(code)
      when is_integer(code) and code in 0x52E4A40FA8DB..0x52E5AC983162 do
    if rem(code - 0x21, 0x1F) == 0 do
      {:error, :reserved_http3_error}
    else
      shifted = code - 0x52E4A40FA8DB
      {:ok, shifted - div(shifted, 0x1F)}
    end
  end

  def decode_application_error(_), do: {:error, :not_application_error}

  def close_capsule(code, reason)
      when is_integer(code) and code in 0..0xFFFFFFFF and is_binary(reason) do
    if byte_size(reason) <= 1024 and String.valid?(reason),
      do: Capsule.encode(0x2843, <<code::32, reason::binary>>),
      else: {:error, :invalid_close_reason}
  end

  def close_capsule(_, _), do: {:error, :invalid_close_code}

  def decode_capsule({:capsule, 0x2843, <<code::32, reason::binary>>}) do
    if byte_size(reason) <= 1024 and String.valid?(reason),
      do: {:ok, {:close, code, reason}},
      else: {:error, :invalid_close_reason}
  end

  def decode_capsule({:capsule, 0x2843, _}), do: {:error, :invalid_close_capsule}
  def decode_capsule({:capsule, 0x78AE, <<>>}), do: {:ok, :drain}
  def decode_capsule({:capsule, 0x78AE, _}), do: {:error, :invalid_drain_capsule}
  def decode_capsule({:capsule, _, _}), do: :ignore

  def valid_session_id?(id),
    do: is_integer(id) and id >= 0 and id <= @max_session_id and rem(id, 4) == 0
end
