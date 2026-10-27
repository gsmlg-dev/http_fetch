defmodule SSL.PolicyIOTest do
  use ExUnit.Case, async: false

  test "ordinary guard is acknowledged before use, authenticates Connection, and retires" do
    deadline = System.monotonic_time(:millisecond) + 2_000
    assert {:ok, context} = SSL.PolicyIO.install(nil, self(), deadline)
    assert Process.alive?(context.observer)
    parent = self()

    spawn(fn ->
      send(parent, {:foreign, SSL.PolicyIO.finish(context)})
    end)

    assert_receive {:foreign, {:error, :unauthorized_policy}}, 500
    monitor = Process.monitor(context.observer)
    assert :ok = SSL.PolicyIO.finish(context)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 500
  end

  test "expired setup cannot install a guard" do
    assert {:error, :deadline_exceeded} =
             SSL.PolicyIO.install(nil, self(), System.monotonic_time(:millisecond) - 1)
  end
end

defmodule SSL.PolicyIOFileIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  test "one observed same-opener actor reads bytes, EOF and closes before settlement" do
    path = Path.join(System.tmp_dir!(), "r49-file-#{System.unique_integer([:positive])}")
    bytes = :binary.copy(<<0, 17, 255, 42>>, 16_384)
    File.write!(path, bytes)
    on_exit(fn -> File.rm(path) end)
    deadline = System.monotonic_time(:millisecond) + 5_000
    assert {:ok, context} = SSL.PolicyIO.install(nil, self(), deadline)
    assert {:ok, ^bytes} = SSL.PolicyIO.read_file(context, path)
    assert :ok = SSL.PolicyIO.finish(context)
  end

  test "live raw-open ENOENT preserves native evidence scope and retires" do
    path = Path.join(System.tmp_dir!(), "r49-absent-#{System.unique_integer([:positive])}")
    deadline = System.monotonic_time(:millisecond) + 5_000
    assert {:ok, context} = SSL.PolicyIO.install(nil, self(), deadline)
    monitor = Process.monitor(context.observer)

    qualified_runtime =
      (:os.type() == {:unix, :linux} and :erlang.system_info(:otp_release) == ~c"28") or
        (:os.type() == {:unix, :linux} and :erlang.system_info(:otp_release) == ~c"29" and
           :erlang.system_info(:version) == ~c"17.1.1") or
        (:os.type() == {:unix, :darwin} and :erlang.system_info(:otp_release) == ~c"29" and
           :erlang.system_info(:version) == ~c"17.0.2")

    if qualified_runtime do
      assert {:error, :enoent} = SSL.PolicyIO.read_file(context, path)
      assert :ok = SSL.PolicyIO.finish(context)
    else
      assert {:error, :policy_io_failed} = SSL.PolicyIO.read_file(context, path)
      assert {:error, :resources_pending} = SSL.PolicyIO.finish(context)
      assert :ok = SSL.PolicyIO.retire(context)
    end

    assert_receive {:DOWN, ^monitor, :process, _, :normal}, SSL.PolicyIO.remaining(deadline)
  end
end

defmodule SSL.PolicyIOBoundsTest do
  use ExUnit.Case, async: true
  alias SSL.PolicyIO.Bounded

  test "proper callback list admission stops at N+1 and rejects an improper tail" do
    assert {:ok, _} = Bounded.list(List.duplicate(:value, 255), 256)
    assert {:ok, _} = Bounded.list(List.duplicate(:value, 256), 256)
    assert {:error, :policy_capacity} = Bounded.list(List.duplicate(:value, 257), 256)
    assert {:error, :invalid_policy_material} = Bounded.list([:value | :improper], 256)
  end

  test "DER node budget admits N-1 and N but rejects N+1 before ASN1 decoding" do
    assert {:ok, 65_535} = Bounded.der(tlv(0x30, :binary.copy(<<5, 0>>, 65_534)))
    assert {:ok, 65_536} = Bounded.der(tlv(0x30, :binary.copy(<<5, 0>>, 65_535)))
    assert {:error, :policy_capacity} = Bounded.der(tlv(0x30, :binary.copy(<<5, 0>>, 65_536)))
  end

  test "DER depth admits N-1 and N but rejects N+1" do
    assert {:ok, _} = Bounded.der(nested(31))
    assert {:ok, _} = Bounded.der(nested(32))
    assert {:error, :policy_capacity} = Bounded.der(nested(33))
  end

  test "certificate and CRL extension list admits N-1 and N but rejects N+1" do
    extension = tlv(0x30, <<6, 3, 85, 29, 17, 4, 2, 5, 0>>)
    assert {:ok, _} = Bounded.der(tlv(0x30, :binary.copy(extension, 127)))
    assert {:ok, _} = Bounded.der(tlv(0x30, :binary.copy(extension, 128)))
    assert {:error, :policy_capacity} = Bounded.der(tlv(0x30, :binary.copy(extension, 129)))
  end

  test "PEM block counts stop before decoder expansion" do
    assert :ok = Bounded.pem_count(String.duplicate("-----BEGIN", 255), 256)
    assert :ok = Bounded.pem_count(String.duplicate("-----BEGIN", 256), 256)

    assert {:error, :policy_capacity} =
             Bounded.pem_count(String.duplicate("-----BEGIN", 257), 256)
  end

  test "truncated, indefinite and noncanonical high tag DER are rejected" do
    for der <- [<<0x30, 2, 5>>, <<0x30, 0x80, 0, 0>>, <<0x1F, 0>>, <<0x30, 0x82, 0, 1, 0>>] do
      assert {:error, :invalid_policy_material} = Bounded.der(der)
    end
  end

  defp nested(count), do: Enum.reduce(1..count, <<5, 0>>, fn _, inner -> tlv(0x30, inner) end)
  defp tlv(tag, body) when byte_size(body) < 128, do: <<tag, byte_size(body), body::binary>>

  defp tlv(tag, body) do
    size = :binary.encode_unsigned(byte_size(body))
    <<tag, 0x80 + byte_size(size), size::binary, body::binary>>
  end
end

defmodule SSL.PolicyIOHTTPIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias SSL.PolicyIO.HTTP

  alias SSL.PolicyIO

  for family <- [:inet, :inet6] do
    test "#{family} HTTP timeout closes and settles within the original setup deadline" do
      family = unquote(family)
      {listener, port} = listener(family)

      server =
        Task.async(fn ->
          try do
            {:ok, socket} = :gen_tcp.accept(listener, 1_000)

            try do
              {:ok, _} = :gen_tcp.recv(socket, 0, 1_000)
              assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
              :ok
            after
              :gen_tcp.close(socket)
            end
          after
            :gen_tcp.close(listener)
          end
        end)

      assert {:ok, context} = PolicyIO.install(nil, self(), PolicyIO.now() + 3_000)

      try do
        assert {:error, _} = HTTP.get(context, url(family, port), 100)
        assert :ok = PolicyIO.finish(context)
        assert :ok = Task.await(server, 1_000)
      after
        if Process.alive?(server.pid), do: Task.shutdown(server, :brutal_kill)
      end
    end
  end

  for size <- [16_777_215, 16_777_216, 16_777_217] do
    test "HTTP body admission at #{size} bytes" do
      body_limit(unquote(size))
    end
  end

  for size <- [16_383, 16_384, 16_385] do
    test "HTTP total header admission at #{size} bytes" do
      header_limit(unquote(size))
    end
  end

  for {name, response} <- [
        truncated: "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx",
        duplicate: "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        compressed: "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx",
        conflicting:
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\nx",
        invalid_chunk: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nx\r\n",
        oversized_chunk: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000001\r\n"
      ] do
    test "HTTP #{name} closes exact socket and rejects bounded malformed framing" do
      assert {:error, _} = exchange([unquote(response)])
    end
  end

  for attempts <- [31, 32, 33] do
    test "HTTP redirects consume the attempt-wide network budget at #{attempts}" do
      redirect_limit(unquote(attempts))
    end
  end

  defp body_limit(size) do
    payload = if size <= 16_777_216, do: :binary.copy(<<42>>, size), else: <<>>
    response = "HTTP/1.1 200 OK\r\nContent-Length: #{size}\r\n\r\n" <> payload
    result = exchange([response])

    if size <= 16_777_216,
      do: assert(result == {:ok, payload}),
      else: assert(result == {:error, :policy_capacity})
  end

  defp header_limit(size) do
    prefix = "HTTP/1.1 200 OK\r\nPadding: "
    suffix = "\r\nContent-Length: 1\r\n\r\n"

    response =
      prefix <> String.duplicate("x", size - byte_size(prefix <> suffix)) <> suffix <> "x"

    result = exchange([response])

    if size <= 16_384,
      do: assert(result == {:ok, "x"}),
      else: assert(result == {:error, :policy_capacity})
  end

  defp redirect_limit(attempts) do
    redirects =
      List.duplicate(
        "HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n",
        min(attempts - 1, 32)
      )

    responses =
      if attempts <= 32,
        do: redirects ++ ["HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"],
        else: redirects

    result = exchange(responses)

    if attempts <= 32,
      do: assert(result == {:ok, "x"}),
      else: assert(result == {:error, :policy_capacity})
  end

  defp exchange(responses) do
    {listener, port} = listener(:inet)

    server =
      Task.async(fn ->
        try do
          for response <- responses do
            {:ok, socket} = :gen_tcp.accept(listener, 2_000)

            try do
              {:ok, _} = :gen_tcp.recv(socket, 0, 2_000)
              :gen_tcp.send(socket, response)
            after
              :gen_tcp.close(socket)
            end
          end

          :ok
        after
          :gen_tcp.close(listener)
        end
      end)

    assert {:ok, context} = PolicyIO.install(nil, self(), PolicyIO.now() + 5_000)

    try do
      result = HTTP.get(context, url(:inet, port), 2_000)
      assert :ok = PolicyIO.finish(context)
      assert :ok = Task.await(server, 2_000)
      result
    after
      if Process.alive?(server.pid), do: Task.shutdown(server, :brutal_kill)
    end
  end

  defp listener(family) do
    address = if family == :inet, do: {127, 0, 0, 1}, else: {0, 0, 0, 0, 0, 0, 0, 1}
    {:ok, listener} = :gen_tcp.listen(0, [family, :binary, active: false, ip: address])
    {:ok, {_, port}} = :inet.sockname(listener)
    {listener, port}
  end

  defp url(:inet, port), do: "http://127.0.0.1:#{port}/leaf.crl"
  defp url(:inet6, port), do: "http://[::1]:#{port}/leaf.crl"
end

defmodule SSL.PolicyIOMaterialBoundsTest do
  use ExUnit.Case, async: true
  alias SSL.PolicyIO
  alias SSL.PolicyIO.Bounded

  for size <- [16_777_215, 16_777_216, 16_777_217] do
    test "structural DER byte admission #{size} precedes ASN1 decoding" do
      bytes = tlv(4, :binary.copy(<<42>>, unquote(size) - 5))
      assert byte_size(bytes) == unquote(size)
      expected = if unquote(size) <= 16_777_216, do: {:ok, 1}, else: {:error, :policy_capacity}
      assert Bounded.der(bytes) == expected
    end
  end

  for size <- [33_554_431, 33_554_432, 33_554_433] do
    test "aggregate material bytes #{size} remain bounded across many small entries" do
      small = tlv(4, :binary.copy(<<42>>, 1_020))
      assert byte_size(small) == 1_024
      Process.delete({PolicyIO, :budget})

      try do
        for _ <- 1..32_767, do: assert(:ok == PolicyIO.material(small))
        remaining = unquote(size) - 32_767 * 1_024
        last = tlv(4, :binary.copy(<<42>>, remaining - 4))
        assert byte_size(last) == remaining
        expected = if unquote(size) <= 33_554_432, do: :ok, else: {:error, :policy_capacity}
        assert PolicyIO.material(last) == expected
        actual = Process.get({PolicyIO, :budget})
        assert actual.nodes == if(unquote(size) <= 33_554_432, do: 32_768, else: 32_767)
        assert actual.bytes <= 33_554_432
      after
        Process.delete({PolicyIO, :budget})
      end
    end
  end

  for count <- [4_095, 4_096, 4_097] do
    test "trust structural preflight admits #{count} entries before certificate decoding" do
      entries = List.duplicate(<<4, 1, 42>>, unquote(count))

      if unquote(count) <= 4_096 do
        assert {:ok, ^entries} = Bounded.trust(entries)
      else
        assert {:error, :policy_capacity} = Bounded.trust(entries)
      end
    end
  end

  defp tlv(tag, body) do
    size = :binary.encode_unsigned(byte_size(body))
    <<tag, 0x80 + byte_size(size), size::binary, body::binary>>
  end
end
