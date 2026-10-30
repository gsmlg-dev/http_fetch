ExUnit.start()

defmodule QuicHttp3.Session do
  def poll(session, max, options) do
    send(self(), {:no_otp_poll, session, max, options})
    Process.get(:no_otp_poll).(session, options)
  end

  def resume(session) do
    send(self(), {:no_otp_resume, session})
    Process.get(:no_otp_resume).(session)
  end

  def close(session) do
    send(self(), {:no_otp_close, session})
    Process.get(:no_otp_close_result, :ok)
  end

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

timeout_helpers =
  for {:defp, metadata, [{name, _, arguments} = head, body]} <- definitions,
      name in [:h3_timeout, :h3_timeout_result, :remaining] do
    {if(name == :h3_timeout and length(arguments) == 3, do: :def, else: :defp), metadata,
     [head, body]}
  end

# Only the clock and public Session collaborator are test doubles. All timeout,
# reconciliation, event and close decisions come from the actual consumer.
Code.compile_quoted(
  quote do
    defmodule NoOTP.ConsumerTimeout do
      alias QuicHttp3.Session
      unquote_splicing(timeout_helpers)
      defp now, do: Process.get(:no_otp_timeout_clock)
    end
  end
)

defmodule NoOTP.ConsumerTimeoutTest do
  use ExUnit.Case, async: true

  setup do
    Process.put(:no_otp_timeout_clock, 1_000)
    :ok
  end

  test "unknown poll resumes the advanced session before closing within the original budget" do
    ref = make_ref()
    pending = make_ref()

    Process.put(:no_otp_poll, fn :initial, options ->
      assert options == [timeout: 500, deadline: {:abs_ms, 2_000}]
      Process.put(:no_otp_timeout_clock, 1_500)
      {:unknown, :advanced, pending}
    end)

    Process.put(:no_otp_resume, fn :advanced -> {:ok, :resolved, []} end)
    assert :ok = NoOTP.ConsumerTimeout.h3_timeout(:initial, ref, 2_000)
    assert_received {:no_otp_poll, :initial, 128, _options}
    assert_received {:no_otp_resume, :advanced}
    assert_received {:no_otp_close, :resolved}
    refute_received {:no_otp_poll, _, _, _}
    refute_received {:no_otp_close, _}
  end

  test "successive polls retain the original absolute deadline and shrink the response budget" do
    Process.put(:no_otp_poll, fn
      :initial, [timeout: 500, deadline: {:abs_ms, 2_000}] ->
        Process.put(:no_otp_timeout_clock, 1_250)
        {:ok, :advanced, []}

      :advanced, [timeout: 250, deadline: {:abs_ms, 2_000}] ->
        Process.put(:no_otp_timeout_clock, 1_500)
        {:ok, :resolved, []}
    end)

    assert :ok = NoOTP.ConsumerTimeout.h3_timeout(:initial, make_ref(), 2_000)
    assert_received {:no_otp_poll, :initial, 128, [timeout: 500, deadline: {:abs_ms, 2_000}]}
    assert_received {:no_otp_poll, :advanced, 128, [timeout: 250, deadline: {:abs_ms, 2_000}]}
    assert_received {:no_otp_close, :resolved}
    refute_received {:no_otp_resume, _}
  end

  test "successive unknown operations are reconciled without submitting another poll" do
    Process.put(:no_otp_poll, fn :initial, _ -> {:unknown, :advanced, make_ref()} end)

    Process.put(:no_otp_resume, fn
      :advanced ->
        Process.put(:no_otp_timeout_clock, 1_250)
        {:unknown, :still_pending, make_ref()}

      :still_pending ->
        Process.put(:no_otp_timeout_clock, 1_500)
        {:ok, :resolved, []}
    end)

    assert :ok = NoOTP.ConsumerTimeout.h3_timeout(:initial, make_ref(), 2_000)
    assert_received {:no_otp_poll, :initial, 128, _}
    assert_received {:no_otp_resume, :advanced}
    assert_received {:no_otp_resume, :still_pending}
    assert_received {:no_otp_close, :resolved}
    refute_received {:no_otp_poll, _, _, _}
  end

  test "an expired total deadline cannot renew reconciliation or report successful cleanup" do
    Process.put(:no_otp_poll, fn :initial, _ ->
      Process.put(:no_otp_timeout_clock, 2_000)
      {:unknown, :advanced, make_ref()}
    end)

    assert_raise RuntimeError, "original scenario deadline exceeded", fn ->
      NoOTP.ConsumerTimeout.h3_timeout(:initial, make_ref(), 2_000)
    end

    refute_received {:no_otp_resume, _}
    refute_received {:no_otp_close, _}
  end

  test "a matching response completion or reset still fails the timeout scenario" do
    for event <- [:done, :stream_reset] do
      ref = make_ref()
      value = if event == :done, do: {:done, ref}, else: {:stream_reset, ref, 0, :reset}
      Process.put(:no_otp_poll, fn :initial, _ -> {:ok, :advanced, [value]} end)

      assert_raise MatchError, fn ->
        NoOTP.ConsumerTimeout.h3_timeout(:initial, ref, 2_000)
      end

      refute_received {:no_otp_close, _}
    end
  end

  test "a response for another request cannot satisfy or reset this timeout" do
    Process.put(:no_otp_poll, fn :initial, _ ->
      Process.put(:no_otp_timeout_clock, 1_500)
      {:ok, :advanced, [{:done, make_ref()}, {:stream_reset, make_ref(), 0, :reset}]}
    end)

    assert :ok = NoOTP.ConsumerTimeout.h3_timeout(:initial, make_ref(), 2_000)
    assert_received {:no_otp_close, :advanced}
  end

  test "a failed close remains a failure rather than a cleanup confirmation" do
    Process.put(:no_otp_poll, fn :initial, _ ->
      Process.put(:no_otp_timeout_clock, 1_500)
      {:ok, :advanced, []}
    end)

    Process.put(:no_otp_close_result, {:error, :close_unconfirmed})

    assert_raise MatchError, fn ->
      NoOTP.ConsumerTimeout.h3_timeout(:initial, make_ref(), 2_000)
    end

    assert_received {:no_otp_close, :advanced}
  end
end

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
