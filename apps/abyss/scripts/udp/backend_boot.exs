alias Abyss.Client
alias Abyss.Transport.UDP
alias Abyss.Transport.UDP.{Core, Multicast}

[expected, selection] = System.argv()
expected = String.to_existing_atom(expected)

options =
  if selection == "omitted", do: [], else: [inet_backend: String.to_existing_atom(selection)]

check = fn condition, label -> if !condition, do: raise(label) end

# Exercise capability validation before any explicit selector is injected.
strict = Multicast.open(0, options ++ [strict_group_filter: true])

case {expected, strict} do
  {:socket, {:error, {:unsupported_capability, :strict_group_filter, :inet, :socket}}} -> :ok
  {:inet, {:ok, socket}} -> Multicast.close(socket)
  other -> raise "strict filtering mismatch: #{inspect(other)}"
end

{:ok, normalized} = Core.normalize_options([], options)
check.(hd(normalized) == {:inet_backend, expected}, "effective selector is not frozen first")

check.(
  Core.normalize_options([], normalized) == {:ok, normalized},
  "normalization is not idempotent"
)

check.(
  Core.normalize_options([], inet_backend: :bad) ==
    {:error, {:invalid_option, :inet_backend, :bad}},
  "invalid backend accepted"
)

for transport <- [UDP, Abyss.Transport.UDP.Unicast, Abyss.Transport.UDP.Broadcast, Multicast] do
  {:ok, socket} = transport.open(0, options)

  check.(
    is_port(socket) == (expected == :inet),
    "actual socket driver mismatch: #{inspect(transport)}"
  )

  transport.close(socket)
end

# Independently bound peers exercise all request-response entry points under
# the actual boot default, including a wrong source port before the answer.
loopback = {127, 0, 0, 1}

{:ok, peer} =
  :gen_udp.open(0, [{:inet_backend, :inet}, :binary, {:active, false}, {:ip, loopback}])

{:ok, stranger} =
  :gen_udp.open(0, [{:inet_backend, :inet}, :binary, {:active, false}, {:ip, loopback}])

{:ok, {_, peer_port}} = :inet.sockname(peer)

requests = [
  {fn -> Client.send_recv(loopback, peer_port, "query", 500, options) end, {:ok, "answer"}},
  {fn -> UDP.send_recv({loopback, peer_port}, "query", 500, options) end,
   {:ok, {loopback, peer_port, "answer"}}},
  {fn -> Abyss.Transport.UDP.Unicast.send_recv({loopback, peer_port}, "query", 500, options) end,
   {:ok, {loopback, peer_port, "answer"}}}
]

try do
  for {request, expected_response} <- requests do
    task = Task.async(request)
    {:ok, {address, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
    :ok = :gen_udp.send(stranger, address, client_port, "wrong")
    :ok = :gen_udp.send(peer, address, client_port, "answer")
    check.(Task.await(task) == expected_response, "boot-default wrong peer accepted")
  end
after
  :gen_udp.close(peer)
  :gen_udp.close(stranger)
end

group = {239, 255, 42, 82}

{:ok, receiver} =
  Multicast.open(
    0,
    options ++
      [add_membership: {group, {127, 0, 0, 1}}, multicast_if: {127, 0, 0, 1}, multicast_ttl: 7]
  )

try do
  {:ok, {_, port}} = Multicast.sockname(receiver)
  :ok = Client.broadcast(group, port, "boot-default", options ++ [source: {127, 0, 0, 1}])
  {:ok, {_, _, "boot-default"}} = Multicast.recv(receiver, 0, 1000)

  {:ok, [multicast_if: {127, 0, 0, 1}, multicast_ttl: 7]} =
    Multicast.getopts(receiver, [:multicast_if, :multicast_ttl])

  :ok = Multicast.setopts(receiver, multicast_ttl: 3)
  {:ok, [multicast_ttl: 3]} = Multicast.getopts(receiver, [:multicast_ttl])
  :ok = Multicast.leave(receiver, {group, {127, 0, 0, 1}})
after
  Multicast.close(receiver)
end

if expected == :socket do
  {:error, {:unsupported_capability, :scoped_sockaddr_send, :socket}} =
    Client.multicast_query(
      {0xFF02, 0, 0, 0, 0, 0, 0, 42},
      49_000,
      "scoped",
      0,
      options ++ [interface: "lo"]
    )
end

IO.puts(
  "PASS boot=#{inspect(:application.get_env(:kernel, :inet_backend))} selection=#{selection} effective=#{expected} OTP=#{System.otp_release()}"
)
