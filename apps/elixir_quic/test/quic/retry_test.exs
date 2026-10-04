defmodule Quic.RetryTest do
  use ExUnit.Case, async: true
  alias Quic.Retry

  @key :binary.copy(<<42>>, 32)
  @remote {{127, 0, 0, 1}, 44_300}
  @original <<1, 2, 3, 4, 5, 6, 7, 8>>
  @cid <<8, 7, 6, 5, 4, 3, 2, 1>>

  test "tokens authenticate address, both CIDs, expiry and endpoint key" do
    token = Retry.issue(@key, @remote, @original, @cid, -10_000)
    assert {:ok, @original} = Retry.verify(@key, @remote, @cid, token, -5_000, 5_000)

    for {key, remote, cid, now} <- [
          {:binary.copy(<<43>>, 32), @remote, @cid, -5_000},
          {@key, {{127, 0, 0, 2}, 44_300}, @cid, -5_000},
          {@key, {{127, 0, 0, 1}, 44_301}, @cid, -5_000},
          {@key, @remote, @original, -5_000},
          {@key, @remote, @cid, -4_999},
          {@key, @remote, @cid, -10_001}
        ] do
      assert {:error, :invalid_retry_token} = Retry.verify(key, remote, cid, token, now, 5_000)
    end

    for index <- 0..(byte_size(token) - 1) do
      <<prefix::binary-size(^index), byte, suffix::binary>> = token
      modified = prefix <> <<Bitwise.bxor(byte, 1)>> <> suffix

      assert {:error, :invalid_retry_token} =
               Retry.verify(@key, @remote, @cid, modified, -5_000, 5_000)
    end

    for malformed <- [<<>>, <<1>>, :binary.copy(<<0>>, 4096), token <> <<0>>] do
      assert {:error, :invalid_retry_token} =
               Retry.verify(@key, @remote, @cid, malformed, -5_000, 5_000)
    end
  end

  test "IPv6 addresses and signed monotonic time are supported" do
    remote = {{0, 0, 0, 0, 0, 0, 0, 1}, 443}
    token = Retry.issue(@key, remote, @original, @cid, -100)
    assert {:ok, @original} = Retry.verify(@key, remote, @cid, token, 0, 100)
    assert {:error, :invalid_retry_token} = Retry.verify(@key, @remote, @cid, token, 0, 100)
  end
end
