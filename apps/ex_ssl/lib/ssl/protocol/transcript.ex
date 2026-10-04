defmodule SSL.Protocol.Transcript do
  @moduledoc """
  Immutable storage and hashing for exact encoded TLS handshake messages.

  Messages are retained as reversed iodata chunks so appending does not flatten
  or repeatedly copy the transcript.
  """

  @type hash :: :sha256 | :sha384
  @type t :: %__MODULE__{
          hash: hash(),
          messages: [iodata()],
          length: non_neg_integer()
        }

  @enforce_keys [:hash]
  defstruct hash: nil, messages: [], length: 0

  @spec new(hash()) :: %SSL.Protocol.Transcript{
          hash: :sha256 | :sha384,
          length: 0,
          messages: []
        }
  def new(hash) when hash in [:sha256, :sha384], do: %__MODULE__{hash: hash}

  @spec append(t(), iodata()) :: t()
  def append(%__MODULE__{} = transcript, encoded_handshake) do
    %{
      transcript
      | messages: [encoded_handshake | transcript.messages],
        length: transcript.length + :erlang.iolist_size(encoded_handshake)
    }
  end

  @spec digest(t()) :: binary()
  def digest(%__MODULE__{hash: hash, messages: messages}) do
    :crypto.hash(hash, Enum.reverse(messages))
  end

  @spec checkpoint(t()) :: t()
  def checkpoint(%__MODULE__{} = transcript), do: transcript

  @spec apply_hello_retry_request_rewrite(t()) :: %SSL.Protocol.Transcript{
          hash: :sha256 | :sha384,
          length: non_neg_integer(),
          messages: [<<_::32, _::_*8>>, ...]
        }
  def apply_hello_retry_request_rewrite(%__MODULE__{} = transcript) do
    client_hello_hash = digest(transcript)
    hash_length = byte_size(client_hello_hash)
    message_hash = <<254, hash_length::24, client_hello_hash::binary>>

    %{transcript | messages: [message_hash], length: byte_size(message_hash)}
  end
end
