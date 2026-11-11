"""Behavior gates for standalone HTTP pool and test-adapter Hex consumers."""

from pathlib import Path

from consumer_gate import command


POOL_GATE = '''
{:ok, policy} = HTTP.Pool.policy(http1: [max_idle: 3], http2: [max_streams: 2])
3 = policy.http1[:max_idle]
2 = policy.http2[:max_streams]
{:error, {:invalid_pool_option, :unknown, :unknown}} = HTTP.Pool.policy(unknown: 1)
:http_pool = Application.get_application(HTTP.HTTP1.Pool)
:http_pool = Application.get_application(HTTP.HTTP2.Pool)
false = Code.ensure_loaded?(HTTP.Runtime.Pool)
false = Code.ensure_loaded?(HTTP)
IO.puts("STANDALONE_POOL_PASS")
'''

FETCH_GATE = '''
for app <- [:http_test, :plug, :ex_unit, :nimble_ownership] do
  unless Enum.all?(Mix.Dep.cached(), &(&1.app != app)), do: raise("testing dependency leaked: #{app}")
end
{:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
{:ok, {_, port}} = :inet.sockname(listener)
owner = self()
peer = spawn_monitor(fn ->
  {:ok, socket} = :gen_tcp.accept(listener, 5_000)
  for _ <- 1..2 do
    {:ok, request} = :gen_tcp.recv(socket, 0, 5_000)
    unless String.contains?(request, "GET /"), do: raise("invalid request")
    :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok")
  end
  send(owner, :both_requests_on_one_socket)
  receive do :stop -> :gen_tcp.close(socket) after 5_000 -> exit(:peer_not_stopped) end
end)
{:ok, family} = HTTP.Runtime.Pool.start_link(name: "candidate", http1: [max_idle: 1, max_idle_per_key: 1])
{:ok, reference} = HTTP.Runtime.Pool.reference("candidate")
for _ <- 1..2 do
  promise = HTTP.fetch("http://127.0.0.1:#{port}/", pool: reference, redirect: :manual)
  %HTTP.Response{status: 200, body: "ok"} = HTTP.Promise.await(promise)
end
receive do :both_requests_on_one_socket -> :ok after 5_000 -> raise("reuse not proven") end
{:ok, %{http1: %{idle: 1}}} = HTTP.Pool.snapshot(reference)
:ok = Supervisor.stop(family)
{:error, :stale_pool} = HTTP.Pool.snapshot(reference)
{:error, :stale_pool} = HTTP.fetch("http://127.0.0.1:#{port}/", pool: reference) |> HTTP.Promise.await()
{peer_pid, peer_ref} = peer
send(peer_pid, :stop)
receive do {:DOWN, ^peer_ref, :process, ^peer_pid, :normal} -> :ok after 5_000 -> raise("peer cleanup") end
:ok = :gen_tcp.close(listener)
IO.puts("PRODUCTION_FETCH_NAMED_POOL_PASS")
'''

TEST_GATE = '''
HTTP.Test.expect(:service, 2, fn request -> HTTP.Test.json(%{path: request.url.path}) end)
for scheme <- ["http", "https"] do
  task = Task.async(fn -> HTTP.fetch("#{scheme}://never-dial.invalid/items", adapter: {HTTP.Test, :service}) |> HTTP.Promise.await() end)
  %HTTP.Response{status: 200, body: body} = Task.await(task)
  %{"path" => "/items"} = JSON.decode!(body)
end
HTTP.Test.expect(:stream, fn _ -> HTTP.Test.stream(["one", "two"], trailers: [{"x-end", "yes"}]) end)
promise = HTTP.fetch("https://never-dial.invalid/stream", adapter: {HTTP.Test, :stream}, redirect: :manual)
%HTTP.Response{body: stream} = response = HTTP.Promise.await(promise)
true = is_pid(stream)
"onetwo" = HTTP.Response.read_all(response)
:ok = HTTP.Test.verify!()
IO.puts("STANDALONE_TEST_ADAPTER_PASS")
'''

PLUG_GATE = '''
true = Code.ensure_loaded?(Plug.Conn)
HTTP.Test.stub(:plug, fn request ->
  HTTP.Test.plug(request, fn conn -> Plug.Conn.send_resp(conn, 201, "bridge") end, body_limit: 32)
end)
%HTTP.Response{status: 201, body: "bridge"} = HTTP.fetch("http://never-dial.invalid/", adapter: {HTTP.Test, :plug}) |> HTTP.Promise.await()
:ok = HTTP.Test.verify!()
IO.puts("OPTIONAL_PLUG_PASS")
'''


def family_projects(directory, version, env):
    variants = (
        ("pool", ("http_pool",), POOL_GATE),
        ("fetch", ("http_fetch",), FETCH_GATE),
        ("test-no-plug", ("http_test",), 'false = Code.ensure_loaded?(Plug.Conn)\n' + TEST_GATE),
        ("test-plug", ("http_test", "plug"), PLUG_GATE),
    )
    for name, packages, script in variants:
        project = Path(directory) / "family" / name
        project.mkdir(parents=True)
        deps = ", ".join('{:' + app + ', "' + ("~> 1.16" if app == "plug" else "== " + version) + '"}'
                         for app in packages)
        (project / "mix.exs").write_text('''defmodule FamilyConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :family_consumer, version: "0.0.0", deps: [''' + deps + ''']]
  def application, do: [extra_applications: [:logger]]
end
''')
        (project / "gate.exs").write_text(script)
        project_env = {**env, "MIX_BUILD_PATH": str(project / "build")}
        command(["mix", "deps.get"], cwd=project, env=project_env)
        command(["mix", "compile", "--warnings-as-errors"], cwd=project, env=project_env)
        command(["mix", "run", "gate.exs"], cwd=project, env=project_env)
