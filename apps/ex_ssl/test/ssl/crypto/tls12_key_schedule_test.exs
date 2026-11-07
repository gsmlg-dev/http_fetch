defmodule SSL.Crypto.TLS12KeyScheduleTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.TLS12KeySchedule, as: Schedule

  @premaster :binary.list_to_bin(Enum.to_list(1..48))
  @client_random :binary.list_to_bin(Enum.to_list(0..31))
  @server_random :binary.list_to_bin(Enum.to_list(32..63))
  @transcript "client hello|server hello|server key exchange|client key exchange"

  test "RFC 5246 P_hash matches independently computed SHA-256 and SHA-384 vectors" do
    assert {:ok,
            <<
              "bfc72aea54e12f176b7549dc7d0082fecd2be093284636015f9149017f433669",
              "e453c27d2993bfb7cd5abd8c655edc7a7ab65b8e3f9f5272de648904d9fdc2474",
              "b294e1428cd414c44924ed42bfae63a"
            >>} = Schedule.prf(:sha256, "secret", "test label", "seed", 80) |> hex_result()

    assert {:ok,
            <<
              "cdd47dc0124953e293a71e0f3fcc02ab44f08334cb2ca2136fafc00d82a403080",
              "ec07bb017728d8d7e2ad075878bed7a570ac06c916c38dd683e4a4e7b66d85d",
              "d7b95c7042f5d4dc37cdea5d01e2a8bc"
            >>} = Schedule.prf(:sha384, "secret", "test label", "seed", 80) |> hex_result()

    assert {:ok, <<>>} = Schedule.prf(:sha256, "secret", "", "", 0)
  end

  test "RFC 7627 EMS and RFC 5246 key block split use exact transcript bytes" do
    assert {:ok, %{master_secret: master, read_state: read, write_state: write}} =
             Schedule.derive(0xC02F, @premaster, @transcript, @client_random, @server_random)

    assert Base.encode16(master, case: :lower) ==
             "50e8a9ee24bb777f308c786191355c881cecbc3f466df685c7d8a52647e4ec97b11cbf097442c7fae6bf58f9d8a3d578"

    assert Base.encode16(write.key <> read.key <> write.iv <> read.iv, case: :lower) ==
             "87fd6c5ebd127019e8f9c7eadd5dd3921827b2ab24333a9f06d63193babab45f8078a69cc59a87f2"

    assert write.cipher == :aes_128_gcm
    assert read.sequence == 0

    assert {:ok, client} = Schedule.finished(0xC02F, master, :client, @transcript)
    assert {:ok, server} = Schedule.finished(0xC02F, master, :server, @transcript)
    assert Base.encode16(client, case: :lower) == "f21f308fec58c24b1d0d5307"
    assert Base.encode16(server, case: :lower) == "ef533619c5bcec7e08e8cca1"

    assert {:ok, %{master_secret: master384, write_state: write384}} =
             Schedule.derive(0xC030, @premaster, @transcript, @client_random, @server_random)

    assert Base.encode16(master384, case: :lower) ==
             "978167e242599f3bfc434e30eba717126a3e9a02a6303661f1fba987d07158697e7b1ae7985176710a2d864ff45f2a7c"

    assert Base.encode16(write384.key, case: :lower) ==
             "c174c12cadfc3337225364b10e126ce3a0d83bf16f9a2fe211d53ddf95b29cc7"

    assert write384.cipher == :aes_256_gcm

    assert {:ok, changed} =
             Schedule.derive(
               0xC02F,
               @premaster,
               @transcript <> "!",
               @client_random,
               @server_random
             )

    refute changed.master_secret == master
  end

  test "RFC 5246 legacy master, key block and Finished match independent HMAC vectors" do
    # Computed independently with Python hashlib/hmac using RFC 5246 P_hash.
    for {suite, expected_master, expected_block, expected_client, expected_server} <- [
          {0xC02F,
           "1558f81526261ccdd21b5a75eaa62dffd6d35b2d08025e2cd4553282093c0cb5fbc0fd0599d257a4804a4322e0ccc6fb",
           "640e8c5ce6178c5e8553b7d8bb0305504c5908f5f7f22200688d36658911d99e0899d22ea494b4bb",
           "ca17b152ba1add72fe86b245", "46d4f1f79593e22dbf8e6a97"},
          {0xC030,
           "39e12e7924dda99905dd1fa8a1d5bcef6c29283c19dadd57548db50950aa0abb1975f805b796b3518d708c5efde4a414",
           "0a139f44f10c3fb1fce464dc0dcf4f4b3b901173a523d4315c570cf0ba92534d70b523c2a8088ae6b58a6a50594b8254e30e74c796877833a593c4f6c6bf3552d58f378af96b6be8",
           "fd73b506c2955f715e9bb696", "bf22198bd4a7b54afff788fe"}
        ] do
      assert {:ok, %{master_secret: master, read_state: read, write_state: write}} =
               Schedule.derive_legacy(suite, @premaster, @client_random, @server_random)

      assert Base.encode16(master, case: :lower) == expected_master

      assert Base.encode16(write.key <> read.key <> write.iv <> read.iv, case: :lower) ==
               expected_block

      assert write.sequence == 0
      assert read.sequence == 0

      assert {:ok, client} = Schedule.finished(suite, master, :client, @transcript)
      assert {:ok, server} = Schedule.finished(suite, master, :server, @transcript)
      assert Base.encode16(client, case: :lower) == expected_client
      assert Base.encode16(server, case: :lower) == expected_server

      assert {:ok, ems} =
               Schedule.derive(suite, @premaster, @transcript, @client_random, @server_random)

      refute ems.master_secret == master
    end
  end

  test "legacy derivation enforces the same premaster, random and suite bounds" do
    for premaster <- [<<>>, nil, :binary.copy(<<0>>, 4097)] do
      assert {:error, :invalid_premaster_secret} =
               Schedule.derive_legacy(0xC02F, premaster, @client_random, @server_random)
    end

    for random <- [<<>>, <<0::248>>, <<0::264>>, nil] do
      assert {:error, {:invalid_random, :client_random}} =
               Schedule.derive_legacy(0xC02F, @premaster, random, @server_random)

      assert {:error, {:invalid_random, :server_random}} =
               Schedule.derive_legacy(0xC02F, @premaster, @client_random, random)
    end

    for suite <- [0x002F, 0x1301, nil] do
      assert {:error, {:unsupported_cipher_suite, ^suite}} =
               Schedule.derive_legacy(suite, @premaster, @client_random, @server_random)
    end
  end

  test "only the four bounded ECDHE GCM suites are offered" do
    for {id, key_exchange, key_length} <- [
          {0xC02F, :rsa, 16},
          {0xC030, :rsa, 32},
          {0xC02B, :ecdsa, 16},
          {0xC02C, :ecdsa, 32}
        ] do
      assert {:ok, %{id: ^id, key_exchange: ^key_exchange, key_length: ^key_length}} =
               Schedule.suite(id)
    end

    for id <- [0x002F, 0x0035, 0x1301, 0xC02D, nil] do
      assert {:error, {:unsupported_cipher_suite, ^id}} = Schedule.suite(id)
    end
  end

  test "invalid PRF, EMS, and Finished inputs fail explicitly" do
    assert {:error, :invalid_prf_input} = Schedule.prf(:sha1, "secret", "x", "y", 12)
    assert {:error, :invalid_prf_input} = Schedule.prf(:sha256, <<>>, "x", "y", 12)
    assert {:error, :invalid_prf_input} = Schedule.prf(:sha256, "secret", "x", "y", 1_048_577)

    assert {:error, :invalid_premaster_secret} =
             Schedule.derive(0xC02F, <<>>, @transcript, @client_random, @server_random)

    assert {:error, {:invalid_random, :client_random}} =
             Schedule.derive(0xC02F, @premaster, @transcript, <<0>>, @server_random)

    assert {:error, :invalid_transcript} =
             Schedule.derive(
               0xC02F,
               @premaster,
               :binary.copy(<<0>>, 1_048_577),
               @client_random,
               @server_random
             )

    assert {:error, :invalid_master_secret} =
             Schedule.finished(0xC02F, <<0>>, :server, @transcript)

    assert {:error, :invalid_finished_role} =
             Schedule.finished(0xC02F, <<0::384>>, :other, @transcript)
  end

  defp hex_result({:ok, data}), do: {:ok, Base.encode16(data, case: :lower)}
end
