ExUnit.start()

defmodule QuicHttp3.Session do
  def ready(_session) do
    case Process.get(:no_otp_readiness_results, [:ready]) do
      [result] ->
        result

      [result | rest] ->
        Process.put(:no_otp_readiness_results, rest)
        result
    end
  end
end

source = System.get_env("NO_OTP_CONSUMER_SOURCE", Path.expand("no_otp_consumer.exs", __DIR__))

{:defmodule, _, [_, [do: {:__block__, _, definitions}]]} =
  source |> File.read!() |> Code.string_to_quoted!()

# Compile the production readiness boundary with a single-VM Session double.
# All receive/deadline logic comes directly from the consumer source.
helpers =
  for {:defp, metadata, [{name, _, _} = head, body]} <- definitions,
      name in [:wait_ready, :h3_closed_reason, :remaining, :now] do
    {if(name == :wait_ready, do: :def, else: :defp), metadata, [head, body]}
  end

Code.compile_quoted(
  quote do
    defmodule NoOTP.ConsumerReadiness do
      alias QuicHttp3.Session
      unquote_splicing(helpers)
    end
  end
)

defmodule NoOTP.ConsumerReadinessTest do
  use ExUnit.Case, async: false

  defp session(results) do
    Process.put(:no_otp_readiness_results, results)
    %{connection: %{handle: %{id: self(), generation: make_ref()}}}
  end

  defp deadline, do: System.monotonic_time(:millisecond) + 100

  test "ready and explicit provider errors retain their result" do
    for value <- [:ready, {:error, :deadline_expired}, {:error, :not_connected}] do
      assert NoOTP.ConsumerReadiness.wait_ready(session([value]), deadline()) == value
    end
  end

  test "closed readiness retains the matching public TLS identity reason" do
    session = session([{:error, :closed}])
    reason = {:tls, :tls, :certificate_unknown, :hostname_mismatch}
    send(self(), {:quic_closed, session.connection.handle, reason})
    assert NoOTP.ConsumerReadiness.wait_ready(session, deadline()) == {:error, reason}
  end

  test "pending readiness retains the eventual correlated error" do
    session = session([:pending, {:error, :closed}])
    reason = {:tls, :tls, :unknown_ca, :path_validation_failed}
    send(self(), {:quic_closed, session.connection.handle, reason})
    assert NoOTP.ConsumerReadiness.wait_ready(session, deadline()) == {:error, reason}
  end

  test "foreign and stale-generation public close events remain in the mailbox" do
    session = session([{:error, :closed}])
    actual = session.connection.handle
    stale = %{actual | generation: make_ref()}
    foreign = %{id: make_ref(), generation: actual.generation}
    reason = {:tls, :tls, :certificate_unknown, :hostname_mismatch}
    send(self(), {:quic_closed, stale, :stale_reason})
    send(self(), {:quic_closed, foreign, :foreign_reason})
    send(self(), {:quic_closed, actual, reason})
    assert NoOTP.ConsumerReadiness.wait_ready(session, deadline()) == {:error, reason}
    assert_receive {:quic_closed, ^stale, :stale_reason}, 0
    assert_receive {:quic_closed, ^foreign, :foreign_reason}, 0
  end

  test "missing correlated evidence remains a failure within the original deadline" do
    session = session([{:error, :closed}])
    send(self(), {:quic_closed, %{id: make_ref(), generation: make_ref()}, :wrong_reason})

    assert NoOTP.ConsumerReadiness.wait_ready(session, System.monotonic_time(:millisecond) + 5) ==
             {:error, :closed}
  end

  test "an expired original deadline cannot be renewed" do
    assert_raise RuntimeError, "original scenario deadline exceeded", fn ->
      NoOTP.ConsumerReadiness.wait_ready(session([:pending]), System.monotonic_time(:millisecond))
    end
  end
end
