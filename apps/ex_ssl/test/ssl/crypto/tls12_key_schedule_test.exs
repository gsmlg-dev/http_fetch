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
