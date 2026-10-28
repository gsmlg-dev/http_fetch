defmodule SSL.TLS12SessionOptionsTest do
  use ExUnit.Case, async: true

  alias SSL.Options

  test "pre-TLS13 reuse controls preserve opt-in true, false and save semantics" do
    for mode <- [true, false, :save] do
      assert {:ok, options} =
               Options.normalize(~c"example.test",
                 verify: :verify_none,
                 cacerts: [],
                 versions: [:"tlsv1.2"],
                 reuse_sessions: mode
               )

      assert options.reuse_sessions == mode
      assert options.reuse_session == nil
    end

    assert {:ok, options} = Options.normalize(~c"example.test", verify: :verify_none, cacerts: [])
    assert options.reuse_sessions == false
  end

  test "saved IDs are bounded and opaque OTP serialized sessions are explicitly rejected" do
    id = :binary.copy(<<1>>, 32)

    assert {:ok, options} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               versions: [:"tlsv1.2"],
               reuse_session: id
             )

    assert options.reuse_session == id
    data = <<"EXSSL12", 1, 0::256>>

    assert {:ok, opaque} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               versions: [:"tlsv1.2"],
               reuse_session: {id, data}
             )

    assert opaque.reuse_session == {id, data}

    for value <- [<<>>, :binary.copy(<<1>>, 33), {id, "opaque-secret"}, :invalid] do
      assert {:error, {:options, {:reuse_session, :unsupported_or_invalid}}} =
               Options.normalize(~c"example.test",
                 verify: :verify_none,
                 cacerts: [],
                 reuse_session: value
               )
    end

    assert {:error, {:options, {:reuse_sessions, :tls12_required}}} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               reuse_sessions: true
             )

    assert {:error, {:options, {:reuse_session, :tls12_required}}} =
             Options.normalize(~c"example.test",
               verify: :verify_none,
               cacerts: [],
               reuse_session: id
             )

    for value <- [:auto, :disabled, nil, 1] do
      assert {:error, {:options, {:reuse_sessions, :unsupported_or_invalid}}} =
               Options.normalize(~c"example.test",
                 verify: :verify_none,
                 cacerts: [],
                 reuse_sessions: value
               )
    end
  end
end
