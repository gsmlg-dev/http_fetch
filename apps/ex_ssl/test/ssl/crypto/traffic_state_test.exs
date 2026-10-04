defmodule SSL.Crypto.TrafficStateTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias SSL.Crypto.TrafficState

  test "nonce XORs the static IV with the left-padded uint64 sequence number" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: Base.decode16!("AABBCCDDEEFF001122334455"),
      sequence: 0x0102030405060708,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    expected_nonce = Base.decode16!("AABBCCDDEFFD03152735435D")

    assert state.generation == 0
    assert {:ok, ^expected_nonce} = TrafficState.nonce(state)
  end

  test "nonce rejects IVs shorter than the uint64 sequence number" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: <<0::56>>,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    assert {:error, {:invalid_iv, :too_short}} = TrafficState.nonce(state)
  end

  test "nonce rejects IV lengths unsupported by the declared TLS 1.3 suites" do
    for iv <- [<<0::64>>, <<0::104>>] do
      state = %TrafficState{
        secret: <<1>>,
        key: <<2>>,
        iv: iv,
        cipher_suite: :tls_aes_128_gcm_sha256
      }

      assert {:error, {:invalid_iv, :wrong_length}} = TrafficState.nonce(state)
    end
  end

  test "nonce accepts the final uint64 sequence and rejects underflow or overflow" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: <<0::96>>,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    assert {:ok, <<0::32, 0xFFFFFFFFFFFFFFFF::64>>} =
             TrafficState.nonce(%{state | sequence: 0xFFFFFFFFFFFFFFFF})

    assert {:error, {:invalid_sequence, :out_of_range}} =
             TrafficState.nonce(%{state | sequence: -1})

    assert {:error, {:invalid_sequence, :out_of_range}} =
             TrafficState.nonce(%{state | sequence: 0x10000000000000000})
  end

  test "advances without wrapping and reports sequence exhaustion" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: <<0::96>>,
      sequence: 7,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    assert {:ok, %TrafficState{sequence: 8}} = TrafficState.advance(state)

    assert {:error, :sequence_exhausted} =
             TrafficState.advance(%{state | sequence: 0xFFFFFFFFFFFFFFFF})

    assert {:error, {:invalid_sequence, :out_of_range}} =
             TrafficState.advance(%{state | sequence: -1})

    assert {:error, :invalid_traffic_state} = TrafficState.advance(nil)
  end

  test "tracks cipher-specific encryption limits and reserves the final record for KeyUpdate" do
    aes = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: <<0::96>>,
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    assert TrafficState.encryption_limit(:tls_aes_128_gcm_sha256) == 23_726_566
    assert TrafficState.encryption_limit(:tls_aes_256_gcm_sha384) == 23_726_566
    assert TrafficState.encryption_limit(:tls_chacha20_poly1305_sha256) == 0xFFFFFFFFFFFFFFFF

    aes_limit = TrafficState.encryption_limit(:tls_aes_128_gcm_sha256)
    assert aes_limit * aes_limit <= 1 <<< 49
    assert (aes_limit + 1) * (aes_limit + 1) > 1 <<< 49

    final = %{aes | sequence: aes_limit - 1}
    exhausted = %{aes | sequence: aes_limit}

    assert TrafficState.may_encrypt?(final)
    assert TrafficState.key_update_required?(final)
    refute TrafficState.may_encrypt?(exhausted)
    assert TrafficState.key_update_required?(exhausted)
  end

  test "allows write epochs through the RFC generation maximum without allowing another update" do
    state = %TrafficState{
      secret: <<1>>,
      key: <<2>>,
      iv: <<0::96>>,
      generation: TrafficState.maximum_write_generation(),
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    assert TrafficState.valid_write_generation?(state)
    refute TrafficState.may_update_write?(state)
    refute TrafficState.valid_write_generation?(%{state | generation: state.generation + 1})
  end

  test "inspection redacts traffic secrets and derived key material" do
    state = %TrafficState{
      secret: "unique traffic secret",
      key: "unique traffic key",
      iv: "unique traffic iv",
      cipher_suite: :tls_aes_128_gcm_sha256
    }

    inspected = inspect(state)

    refute inspected =~ "unique traffic secret"
    refute inspected =~ "unique traffic key"
    refute inspected =~ "unique traffic iv"
    refute inspected =~ "secret:"
    refute inspected =~ "key:"
    refute inspected =~ "iv:"
  end
end
