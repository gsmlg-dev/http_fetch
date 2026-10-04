defmodule SSL.Crypto.KeyScheduleTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.KeySchedule
  alias SSL.Crypto.TrafficState

  @early_secret Base.decode16!("33AD0A1C607EC03B09E6CD9893680CE210ADF300AA1F2660E1B22E10F170F92A")
  @shared_secret Base.decode16!(
                   "8BD4054FB55B9D63FDFBACF9F04B9F0D35E6D63F537563EFD46272900F89492D"
                 )
  @hello_hash Base.decode16!("860C06EDC07858EE8E78F0E7428C58EDD6B43F2CA3E6E95F02ED063CF0E1CAD8")
  @handshake_secret Base.decode16!(
                      "1DC826E93606AA6FDC0AADC12F741B01046AA6B99F691ED221A9F0CA043FBEAC"
                    )
  @client_handshake Base.decode16!(
                      "B3EDDB126E067F35A780B3ABF45E2D8F3B1A950738F52E9600746A0E27A55A21"
                    )
  @server_handshake Base.decode16!(
                      "B67B7D690CC16C4E75E54213CB2D37B4E9C912BCDED9105D42BEFD59D391AD38"
                    )
  @master_secret Base.decode16!(
                   "18DF06843D13A08BF2A449844C5F8A478001BC4D4C627984D5A41DA8D0402919"
                 )
  @server_finished_key Base.decode16!(
                         "008D3B66F816EA559F96B537E885C31FC068BF492C652F01F288A1D8CDC19FC8"
                       )
  @server_finished_hash Base.decode16!(
                          "9608102A0F1CCC6DB6250B7B7E417B1A000EAADA3DAAE4777A7686C9FF83DF13"
                        )
  @client_application Base.decode16!(
                        "9E40646CE79A7F9DC05AF8889BCE6552875AFA0B06DF0087F792EBB7C17504A5"
                      )
  @server_application Base.decode16!(
                        "A11AF9F05531F856AD47116B45A950328204B4F44BFB6B3A4B4F1F3FCB631643"
                      )
  @exporter_master Base.decode16!(
                     "FE22F881176EDA18EB8F44529E6792C50C9A3F89452F68D8AE311B4309D3CF50"
                   )
  @resumption_hash Base.decode16!(
                     "209145A96EE8E2A122FF810047CC952684658D6049E86429426DB87C54AD143D"
                   )
  @resumption_master Base.decode16!(
                       "7DF235F2031D2A051287D02B0241B0BFDAF86CC856231F2D5ABA46C434EC196C"
                     )

  test "TLS1.2 suites cannot enter the TLS1.3 key schedule" do
    assert {:error, {:unsupported_cipher_suite, 0xC02F}} =
             KeySchedule.traffic_state(0xC02F, <<0::256>>)
  end

  test "derives the RFC 8448 early, handshake, and master secrets" do
    assert {:ok, @early_secret} = KeySchedule.early_secret(:sha256, nil)

    assert {:ok, derived} = KeySchedule.derived_secret(:sha256, @early_secret)
    assert derived == hex("6F2615A108C702C5678F54FC9DBAB69716C076189C48250CEBEAC3576C3611BA")

    assert {:ok, @handshake_secret} =
             KeySchedule.handshake_secret(:sha256, @early_secret, @shared_secret)

    assert {:ok, @master_secret} = KeySchedule.master_secret(:sha256, @handshake_secret)
  end

  test "derives the RFC 8448 handshake traffic secrets and Finished key" do
    assert {:ok, @client_handshake} =
             KeySchedule.client_handshake_traffic_secret(
               :sha256,
               @handshake_secret,
               @hello_hash
             )

    assert {:ok, @server_handshake} =
             KeySchedule.server_handshake_traffic_secret(
               :sha256,
               @handshake_secret,
               @hello_hash
             )

    assert {:ok, @server_finished_key} =
             KeySchedule.finished_key(:sha256, @server_handshake)
  end

  test "derives RFC 8448 application, exporter, and resumption secrets" do
    assert {:ok, @client_application} =
             KeySchedule.client_application_traffic_secret(
               :sha256,
               @master_secret,
               @server_finished_hash
             )

    assert {:ok, @server_application} =
             KeySchedule.server_application_traffic_secret(
               :sha256,
               @master_secret,
               @server_finished_hash
             )

    assert {:ok, @exporter_master} =
             KeySchedule.exporter_master_secret(
               :sha256,
               @master_secret,
               @server_finished_hash
             )

    assert {:ok, @resumption_master} =
             KeySchedule.resumption_master_secret(
               :sha256,
               @master_secret,
               @resumption_hash
             )

    expected_resumption_secret = expected_resumption_secret()

    assert {:ok, ^expected_resumption_secret} =
             KeySchedule.resumption_secret(:sha256, @resumption_master, <<0, 0>>)
  end

  test "derives RFC 8448 traffic keys and IV into a redacted traffic state" do
    assert {:ok,
            %TrafficState{
              cipher_suite: :tls_aes_128_gcm_sha256,
              key: expected_key,
              iv: expected_iv,
              secret: @client_application,
              sequence: 0,
              generation: 0
            } = state} =
             KeySchedule.traffic_state(:tls_aes_128_gcm_sha256, @client_application)

    assert expected_key == hex("17422DDA596ED5D9ACD890E3C63F5051")
    assert expected_iv == hex("5B78923DEE08579033E523D9")
    refute inspect(state) =~ Base.encode16(@client_application)
    refute inspect(state) =~ Base.encode16(expected_key)
  end

  test "traffic update matches an independent OpenSSL 3 HKDF vector" do
    assert {:ok, updated} = KeySchedule.traffic_update(:sha256, @client_application)
    assert updated == hex("FCDFCC72725AAEE48BF64E4FD8B749CDBDBAB39D90DA0B26E2245CA6EA167207")
  end

  test "supports the SHA-384 schedule and AES-256 traffic material" do
    early =
      hex(
        "7EE8206F5570023E6DC7519EB1073BC4E791AD37B5C382AA10BA18E2357E7169" <>
          "71F9362F2C2FE2A76BFD78DFEC4EA9B5"
      )

    shared =
      hex(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" <>
          "202122232425262728292A2B2C2D2E2F"
      )

    expected_handshake =
      hex(
        "DEB1BECD84738BDCBF73BDD28BD2209D2FE51B84986A4FBB63D7E3902C00A7D8" <>
          "67DB2D8E1AF869B952DCAB5D7F482CAB"
      )

    expected_client =
      hex(
        "B28105AA0A7002EDCBEF60D60A0B22138408CB331854BFB60F619C8D931993D5" <>
          "B9C128C73485EA3377FCA537758F22B1"
      )

    assert {:ok, ^early} = KeySchedule.early_secret(:sha384, nil)
    assert {:ok, ^expected_handshake} = KeySchedule.handshake_secret(:sha384, early, shared)

    assert {:ok, ^expected_client} =
             KeySchedule.client_handshake_traffic_secret(
               :sha384,
               expected_handshake,
               empty_sha384()
             )

    assert {:ok, %TrafficState{key: key, iv: iv}} =
             KeySchedule.traffic_state(:tls_aes_256_gcm_sha384, expected_client)

    assert byte_size(key) == 32
    assert byte_size(iv) == 12

    assert {:ok, %TrafficState{key: chacha_key, iv: chacha_iv}} =
             KeySchedule.traffic_state(
               :tls_chacha20_poly1305_sha256,
               @client_application
             )

    assert byte_size(chacha_key) == 32
    assert byte_size(chacha_iv) == 12
  end

  test "calculates Finished verify_data with the suite hash" do
    transcript_hash = :crypto.hash(:sha256, "server flight")
    assert {:ok, finished_key} = KeySchedule.finished_key(:sha256, @server_handshake)

    assert {:ok, verify_data} =
             KeySchedule.finished_verify_data(:sha256, finished_key, transcript_hash)

    assert verify_data == :crypto.mac(:hmac, :sha256, finished_key, transcript_hash)
    assert byte_size(verify_data) == 32
  end

  test "rejects unsupported hashes, suites, and malformed inputs without raising" do
    assert {:error, :unsupported_hash} = KeySchedule.early_secret(:sha512, nil)
    assert {:error, {:invalid_input, :psk}} = KeySchedule.early_secret(:sha256, false)

    assert {:error, {:invalid_secret_length, :early_secret, 32}} =
             KeySchedule.handshake_secret(:sha256, <<0>>, <<1>>)

    assert {:error, {:invalid_input, :shared_secret}} =
             KeySchedule.handshake_secret(:sha256, @early_secret, nil)

    assert {:error, {:invalid_input, :empty_shared_secret}} =
             KeySchedule.handshake_secret(:sha256, @early_secret, <<>>)

    assert {:error, {:invalid_transcript_hash_length, 32}} =
             KeySchedule.client_handshake_traffic_secret(:sha256, @handshake_secret, <<0>>)

    assert {:error, {:invalid_input, :transcript_hash}} =
             KeySchedule.server_application_traffic_secret(:sha256, @master_secret, nil)

    assert {:error, {:invalid_secret_length, :traffic_secret, 48}} =
             KeySchedule.traffic_state(:tls_aes_256_gcm_sha384, <<0::256>>)

    assert {:error, {:unsupported_cipher_suite, :tls_aes_128_ccm_sha256}} =
             KeySchedule.traffic_state(:tls_aes_128_ccm_sha256, <<0::256>>)

    assert {:error, {:invalid_input, :ticket_nonce}} =
             KeySchedule.resumption_secret(:sha256, @resumption_master, nil)
  end

  defp expected_resumption_secret do
    hex("4ECD0EB6EC3B4D87F5D6028F922CA4C5851A277FD41311C9E62D2C9492E1C4F3")
  end

  defp empty_sha384 do
    hex(
      "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA" <>
        "274EDebFE76F65FBD51AD2F14898B95B"
    )
  end

  defp hex(value), do: Base.decode16!(String.upcase(value))
end
