defmodule SSL.VerifyFunInteropTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F

  setup_all do
    dir = Path.join(System.tmp_dir!(), "r44-interop-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(dir) end)
    File.mkdir_p!(dir)
    {:ok, fixtures: F.create(dir)}
  end

  test "independent TLS12 EMS and TLS13 peers exchange exact HTTP with all callback forms", %{
    fixtures: m
  } do
    for version <- ["tls12", "tls13"], form <- [:tuple3, :tuple4, :legacy1] do
      callback = callback(form, :accept)

      options =
        F.options(m, [], version)
        |> Keyword.put(:cacerts, [])
        |> Keyword.put(:verify_fun, callback)

      {result, events} = F.exchange(m, options, version: version, auth: "none")
      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, nil, nil, version)
    end
  end

  test "trusted valid_peer rejection is reached and independent peers see zero HTTP", %{
    fixtures: m
  } do
    for version <- ["tls12", "tls13"], mode <- [:verify_peer, :verify_none] do
      parent = self()
      ref = make_ref()

      verify = fn _, event, state ->
        send(parent, {ref, event, state})
        if event == :valid_peer, do: {:fail, "R44_PRIVATE_REJECT"}, else: {:valid, state + 1}
      end

      options = F.options(m, [], version) ++ [verify: mode, verify_fun: {verify, 0}]
      {result, events} = F.exchange(m, options, version: version, auth: "none")
      assert {:error, {:tls_alert, _}} = result
      assert_receive {^ref, :valid_peer, _}, 1_000
      refute Enum.any?(events, &(&1["event"] == "http"))
      refute inspect(result) =~ "R44_PRIVATE_REJECT"
    end
  end

  test "hostname callback override is exercised by both independent TLS versions", %{fixtures: m} do
    for version <- ["tls12", "tls13"] do
      parent = self()
      ref = make_ref()

      verify = fn _, event, state ->
        send(parent, {ref, event})
        {:valid, state + 1}
      end

      options =
        F.options(m, [], version)
        |> Keyword.put(:server_name_indication, ~c"wrong.example.test")
        |> Keyword.put(:verify_fun, {verify, 0})

      {result, events} = F.exchange(m, options, version: version, auth: "none")
      assert result == {:ok, F.response()}
      assert_receive {^ref, {:bad_cert, :hostname_check_failed}}, 1_000
      refute_receive {^ref, :valid_peer}, 0
      F.assert_authenticated(m, events, nil, nil, version)
    end
  end

  @tag :tmp_dir
  test "prepared file snapshot calls no callback at preparation and resets on both attaches", %{
    fixtures: m,
    tmp_dir: dir
  } do
    parent = self()
    ref = make_ref()

    extensions =
      m["server"]["der_b64"]
      |> Base.decode64!()
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> elem(10)

    assert [
             {:Extension, {2, 5, 29, 17}, _, _} = san,
             {:Extension, {2, 5, 29, 14}, _, _} = ski,
             {:Extension, {2, 5, 29, 35}, _, _} = aki
           ] =
             Enum.filter(
               extensions,
               &(elem(&1, 1) in [{2, 5, 29, 17}, {2, 5, 29, 14}, {2, 5, 29, 35}])
             )

    expected_events = [
      {{:extension, san}, 0},
      {{:extension, ski}, 1},
      {{:extension, aki}, 2},
      {:valid_peer, 3}
    ]

    verify = fn _, event, state ->
      send(parent, {ref, event, state})
      {:valid, state + 1}
    end

    path = Path.join(dir, "snapshot-ca.pem")
    File.cp!(m["roots"]["server-root"]["cert"], path)

    options =
      F.options(m, [])
      |> Keyword.delete(:cacerts)
      |> Keyword.merge(cacertfile: path, verify_fun: {verify, 0}, session_tickets: :auto)

    assert {:ok, prepared} = SSL.prepare_upgrade(options)
    refute_receive {^ref, _, _}, 0
    File.write!(path, "replaced after preparation")

    for _ <- 1..2 do
      {result, events} = F.exchange(m, prepared, [auth: "none", version: "tls13"], :prepared)
      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, nil, nil, "tls13")

      for {expected_event, expected_state} <- expected_events do
        assert_receive {^ref, event, state}, 1_000
        assert {event, state} == {expected_event, expected_state}
      end

      refute_receive {^ref, _, _}, 0
    end
  end

  test "raise throw exit and malformed returns remain marker-free through public logging", %{
    fixtures: m
  } do
    for behavior <- [:raise, :throw, :exit, :malformed] do
      verify = fn _, _, _ ->
        case behavior do
          :raise -> raise "R44_PRIVATE_EXCEPTION"
          :throw -> throw("R44_PRIVATE_EXCEPTION")
          :exit -> exit("R44_PRIVATE_EXCEPTION")
          :malformed -> {:private, "R44_PRIVATE_EXCEPTION"}
        end
      end

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {result, events} =
            F.exchange(m, F.options(m, []) ++ [verify_fun: {verify, :private}], auth: "none")

          assert {:error, {:tls_alert, _}} = result
          refute inspect(result) =~ "R44_PRIVATE_EXCEPTION"
          refute Enum.any?(events, &(&1["event"] == "http"))
        end)

      refute log =~ "R44_PRIVATE_EXCEPTION"
    end
  end

  defp callback(:tuple3, :accept), do: {fn _, _, state -> {:valid, state + 1} end, 0}

  defp callback(:tuple4, :accept) do
    {fn cert, der, _, state ->
       assert der == :public_key.pkix_encode(:OTPCertificate, cert, :otp)
       {:valid, state + 1}
     end, 0}
  end

  defp callback(:legacy1, :accept), do: fn [_ | _] -> true end
end
