defmodule SSL.VerifyFunResumptionTest do
  use ExUnit.Case, async: false

  test "callback auto tickets bypass partition and cache before serializing policy" do
    callback =
      {fn _, _, _ -> raise "must not run during ticket preparation" end,
       %{private: fn -> :private end}}

    assert {:ok, options} =
             SSL.Options.normalize("example.test",
               verify_fun: callback,
               cacerts: [],
               session_tickets: :auto
             )

    assert options.session_tickets == :auto

    for {module, function, arity} <- [
          {SSL.ResumptionContext, :partition, 2},
          {SSL.TicketCache, :checkout, 1},
          {SSL.TicketCache, :put, 2}
        ] do
      assert {:module, ^module} = Code.ensure_loaded(module)
      assert 1 = :erlang.trace_pattern({module, function, arity}, true, [:local, :call_count])
    end

    try do
      assert {:ok, %{session_tickets: :disabled} = prepared, nil, nil} =
               SSL.ResumptionContext.prepare(options, fn -> raise "endpoint inspected" end)

      assert prepared.verify_fun == callback
      refute List.keymember?(prepared.profile.extensions, :pre_shared_key, 0)

      assert prepared.profile.extensions ==
               Enum.reject(options.profile.extensions, &match?({:pre_shared_key, _}, &1))

      assert {:ok, materialized} =
               SSL.ClientHello.Materializer.materialize(
                 prepared.profile,
                 SSL.Options.capabilities(),
                 prepared.context
               )

      refute List.keymember?(materialized.client_hello.extensions, 0x0029, 0)

      for mfa <- [
            {SSL.ResumptionContext, :partition, 2},
            {SSL.TicketCache, :checkout, 1},
            {SSL.TicketCache, :put, 2}
          ] do
        assert {:call_count, 0} = :erlang.trace_info(mfa, :call_count)
      end
    after
      for mfa <- [
            {SSL.ResumptionContext, :partition, 2},
            {SSL.TicketCache, :checkout, 1},
            {SSL.TicketCache, :put, 2}
          ] do
        :erlang.trace_pattern(mfa, false, [:local, :call_count])
      end
    end
  end
end
