defmodule HTTP.HTTP1IdleTimeoutWireTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion}

  test "empty normalized transport messages do not renew the pending read deadline" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    test = self()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        assert {:ok, _request} = :gen_tcp.recv(socket, 0, 3_000)
        send(test, :empty_policy_request)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 3_000)
        :gen_tcp.close(socket)
      end)

    promise =
      HTTP.fetch("http://127.0.0.1:#{port}/empty-policy",
        http_version: :http1,
        redirect: :manual,
        tls_backend: :ssl,
        read_idle_timeout: 1_000,
        timeout: 3_000,
        telemetry: false
      )

    assert_receive :empty_policy_request, 2_000
    completion = Promise.completion(promise)
    resources = :sys.get_state(completion.tracker).resources |> Map.values()
    {owner, :owner} = Enum.find(resources, fn {_resource, kind} -> kind == :owner end)
    {socket, :socket} = Enum.find(resources, fn {_resource, kind} -> kind == :socket end)

    # Native zero-byte sends do not produce TCP messages. Inject only the
    # normalized empty-data policy input; the request and closure use real TCP.
    for _ <- 1..4 do
      tick = make_ref()
      Process.send_after(self(), {:tick, tick}, 200)
      assert_receive {:tick, ^tick}, 1_000
      send(owner, {:tcp, socket, <<>>})
    end

    assert {:error, :read_idle_timeout} = Promise.await(promise, 500)
    assert :ok = RequestCompletion.await(completion, 1_000)
    assert :ok = Task.await(peer, 1_000)
  end

  for mode <- [:raw, :structured] do
    test "#{mode} read idle expires a pending header read and confirms owned TCP cleanup" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      on_exit(fn -> :gen_tcp.close(listener) end)
      {:ok, {_, port}} = :inet.sockname(listener)
      test = self()

      peer =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)
          assert {:ok, _request} = :gen_tcp.recv(socket, 0, 2_000)
          send(test, :request_received)
          assert {:error, reason} = :gen_tcp.recv(socket, 0, 2_000)
          assert reason in [:closed, :econnreset]
          :gen_tcp.close(socket)
          send(test, :peer_closed)
          :ok
        end)

      promise =
        HTTP.fetch("http://127.0.0.1:#{port}/idle",
          http_version: :http1,
          redirect: :manual,
          tls_backend: :ssl,
          error_mode: unquote(mode),
          read_idle_timeout: 100,
          timeout: 1_000
        )

      completion = Promise.completion(promise)
      assert_receive :request_received, 1_000
      assert {:error, reason} = Promise.await(promise, 1_500)

      case unquote(mode) do
        :raw ->
          assert reason == :read_idle_timeout

        :structured ->
          assert %HTTP.RequestError{
                   reason: :read_idle_timeout,
                   phase: :unknown,
                   request_started: :unknown
                 } = reason

          refute HTTP.RequestError.pre_send?(reason)
      end

      assert :ok = RequestCompletion.await(completion, 1_000)
      assert_receive :peer_closed, 1_000
      assert :ok = Task.await(peer, 1_000)
      assert :ok = RequestCompletion.await(completion, 0)
    end
  end
end
