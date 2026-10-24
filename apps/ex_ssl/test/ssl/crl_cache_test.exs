defmodule SSL.CRLCacheIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.RevocationFixtures

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  test "missing and failed file reads cannot later kill their still-live public caller", %{
    directory: directory
  } do
    parent = self()
    reference = make_ref()

    {pid, monitor} =
      spawn_monitor(fn ->
        Process.send_after(self(), :survival_check, 5_300)
        path = Path.join(directory, "does-not-exist-r49-cache")
        assert {:error, :enoent} = SSL.CRLCache.insert({:file, path})
        assert {:error, :enoent} = SSL.CRLCache.delete({:file, path})
        assert {:error, _} = SSL.CRLCache.insert({:file, directory})
        assert {:error, _} = SSL.CRLCache.delete({:file, directory})
        send(parent, {reference, :returned})

        receive do
          :survival_check -> send(parent, {reference, :survived})
        after
          5_500 -> raise "public cache caller survival timer missing"
        end
      end)

    assert_receive {^reference, :returned}, 1_000
    assert_receive {^reference, :survived}, 5_500
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 500
  end

  test "a blocked native file open returns an error without killing the public caller", %{
    directory: directory
  } do
    # Load the external release path before deliberately occupying the sole
    # dirty-I/O scheduler; code loading and filesystem cleanup use it too.
    assert {"", 0} = System.cmd("python3", ["-c", "pass"])
    path = Path.join(directory, "cache-fifo-#{System.unique_integer([:positive])}")
    {output, 0} = System.cmd("mkfifo", [path], stderr_to_stdout: true)
    assert output == ""
    parent = self()
    reference = make_ref()

    {caller, monitor} =
      spawn_monitor(fn ->
        result = SSL.CRLCache.insert({:file, path})
        send(parent, {reference, :result, result})

        receive do
          :survival_check -> send(parent, {reference, :survived})
        after
          2_000 -> raise "public cache caller did not receive survival check"
        end
      end)

    try do
      assert_receive {^reference, :result, result}, 6_500
      # Release before assertions or filesystem cleanup, including on failure.
      assert {"", 0} = release_fifo(path)
      assert {:error, reason} = result
      assert reason in [:acceptance_unconfirmed, :deadline_exceeded, :resources_pending]
      send(caller, :survival_check)
      assert_receive {^reference, :survived}, 500
      assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}, 500
    after
      _ = release_fifo(path)
      File.rm(path)
      if Process.alive?(caller), do: Process.exit(caller, :kill)
    end
  end

  test "public DER deletion bounds every item and aggregate before messaging the cache" do
    maximum = :binary.copy(<<42>>, 16_777_216)
    below = binary_part(maximum, 0, 16_777_215)
    assert :ok = SSL.CRLCache.delete({:der, below})
    assert :ok = SSL.CRLCache.delete({:der, maximum})
    assert {:error, :policy_capacity} = SSL.CRLCache.delete({:der, maximum <> <<42>>})
    assert :ok = SSL.CRLCache.delete({:der, [maximum, below]})
    assert :ok = SSL.CRLCache.delete({:der, [maximum, maximum]})
    assert {:error, :policy_capacity} = SSL.CRLCache.delete({:der, [maximum, maximum, <<42>>]})

    for count <- [255, 256],
        do: assert(:ok == SSL.CRLCache.delete({:der, List.duplicate(<<>>, count)}))

    assert {:error, :policy_capacity} = SSL.CRLCache.delete({:der, List.duplicate(<<>>, 257)})
    assert {:error, :invalid_policy_material} = SSL.CRLCache.delete({:der, [<<>> | :improper]})
    assert {:error, :invalid_crl_source} = SSL.CRLCache.delete({:der, [:invalid]})
    assert {:error, :policy_capacity} = SSL.CRLCache.insert({:der, maximum <> <<42>>})
    assert {:error, :policy_capacity} = SSL.CRLCache.insert({:der, [maximum, maximum, <<42>>]})
  end

  test "public URI byte admission accepts N-1 and N and rejects N+1 before conversion" do
    prefix = "http://r49.example/"

    for size <- [16_383, 16_384] do
      uri = prefix <> String.duplicate("x", size - byte_size(prefix))
      assert :ok = SSL.CRLCache.insert(String.to_charlist(uri), {:der, []})
      assert :ok = SSL.CRLCache.delete(uri)
    end

    oversized = String.to_charlist(prefix) ++ List.duplicate(0x1F600, 4_096)
    assert {:error, :unsupported_crl_uri} = SSL.CRLCache.insert(oversized, {:der, []})

    assert {:error, :unsupported_crl_uri} =
             SSL.CRLCache.insert(String.duplicate("x", 16_385), {:der, []})

    assert {:error, :unsupported_crl_uri} = SSL.CRLCache.delete([?h | :improper])
    assert {:error, :unsupported_crl_uri} = SSL.CRLCache.delete([0xD800])
  end

  test "public insert and delete accept DER and PEM files without leaking cache diagnostics", %{
    directory: directory
  } do
    der = File.read!(Path.join(directory, "root-good.crl.der"))
    uri = "http://r49.example/private-cache-diagnostic-token"

    try do
      assert :ok = SSL.CRLCache.insert(uri, {:file, Path.join(directory, "root-good.crl.pem")})

      status =
        :sys.get_status(SSL.CRLCache) |> inspect(limit: :infinity, printable_limit: :infinity)

      refute status =~ "private-cache-diagnostic-token"
      refute status =~ inspect(der, limit: :infinity, printable_limit: :infinity)
      assert status =~ "redacted"
      assert :ok = SSL.CRLCache.delete({:der, [der]})
      assert :ok = SSL.CRLCache.insert({:der, der})
      assert :ok = SSL.CRLCache.delete({:file, Path.join(directory, "root-good.crl.pem")})
    after
      SSL.CRLCache.delete(uri)
      SSL.CRLCache.delete({:der, der})
    end
  end

  test "public cache entry admission preserves state at N+1", %{directory: directory} do
    der = File.read!(Path.join(directory, "leaf-good.crl.der"))
    uris = for index <- 1..129, do: "http://r49.example/capacity-#{index}"

    try do
      Enum.each(Enum.take(uris, 127), fn uri ->
        assert :ok = SSL.CRLCache.insert(uri, {:der, der})
      end)

      assert :ok = SSL.CRLCache.insert(Enum.at(uris, 127), {:der, der})
      assert {:error, :policy_capacity} = SSL.CRLCache.insert(Enum.at(uris, 128), {:der, der})
      assert :ok = SSL.CRLCache.delete(hd(uris))
      assert :ok = SSL.CRLCache.insert(Enum.at(uris, 128), {:der, der})
    after
      Enum.each(uris, &SSL.CRLCache.delete/1)
    end
  end

  defp release_fifo(path) do
    code = "import os,sys; fd=os.open(sys.argv[1], os.O_WRONLY|os.O_NONBLOCK); os.close(fd)"

    port =
      Port.open(
        {:spawn_executable, "/usr/bin/python3"},
        [:binary, :exit_status, :stderr_to_stdout, args: ["-c", code, path]]
      )

    release_result(port, <<>>)
  end

  defp release_result(port, output) do
    receive do
      {^port, {:data, bytes}} -> release_result(port, output <> bytes)
      {^port, {:exit_status, status}} -> {output, status}
    after
      1_000 ->
        Port.close(port)
        {output, :timeout}
    end
  end
end
