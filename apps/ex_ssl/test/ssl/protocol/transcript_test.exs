defmodule SSL.Protocol.TranscriptTest do
  use ExUnit.Case, async: true

  alias SSL.Protocol.Transcript

  test "appends exact encoded handshake iodata without flattening and digests in wire order" do
    client_hello = [<<1, 0, 0, 3>>, "abc"]
    server_hello = [<<2, 0, 0, 3>>, "def"]

    transcript =
      :sha256
      |> Transcript.new()
      |> Transcript.append(client_hello)
      |> Transcript.append(server_hello)

    assert %Transcript{
             hash: :sha256,
             messages: [^server_hello, ^client_hello],
             length: 14
           } = transcript

    assert Transcript.digest(transcript) ==
             Base.decode16!("5BF53862CBD11FCA4C1308918E02E4E39B0F13AD1C44B58411B5041DF7294754")
  end

  test "checkpoint preserves an immutable transcript prefix" do
    transcript = Transcript.new(:sha384) |> Transcript.append(<<1, 0, 0, 1, 42>>)
    checkpoint = Transcript.checkpoint(transcript)
    continued = Transcript.append(transcript, <<2, 0, 0, 0>>)

    assert checkpoint == transcript

    assert Transcript.digest(checkpoint) ==
             Base.decode16!(
               "B1AACD30F77EE4F637B468D114AA3C151BAD5E5004695329B5F67047AAE494FFF218E5E36BEE38BC04F55BB749FEC1C1"
             )

    refute Transcript.digest(checkpoint) == Transcript.digest(continued)
    assert checkpoint.length == 5
    assert continued.length == 9
  end

  test "HelloRetryRequest rewrite replaces ClientHello1 with RFC 9846 message_hash" do
    transcript = Transcript.new(:sha256) |> Transcript.append(<<1, 0, 0, 3, "abc">>)
    rewritten = Transcript.apply_hello_retry_request_rewrite(transcript)

    client_hello_hash =
      Base.decode16!("6F50D04EBCCFC92FAB762E6ECE797DE3C0C6D62E02FEB988D8DFFE69A81566D4")

    synthetic_message = <<254, 0, 0, 32, client_hello_hash::binary>>

    assert rewritten.messages == [synthetic_message]
    assert rewritten.length == 36

    assert Transcript.digest(rewritten) ==
             Base.decode16!("A01F26F23DA0A041EA9CCBD2439F7E94383FE23B49F600CA73826E196D5FEA14")

    assert transcript.messages == [<<1, 0, 0, 3, "abc">>]
  end
end
