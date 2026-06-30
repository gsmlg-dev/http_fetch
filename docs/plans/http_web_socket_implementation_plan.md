---
title: "Implement http_web_socket"
status: "implemented"
created: "2026-06-30"
source_design: "docs/http_web_socket_design.md"
scope:
  - "apps/http_web_socket/**"
  - "mix.exs"
  - ".dialyzer_ignore.exs"
  - "README.md"
  - "docs/http_web_socket_design.md"
  - "docs/plans/http_web_socket_implementation_plan.md"
verification:
  - "mix test apps/http_web_socket/test"
  - "mix compile --warnings-as-errors"
  - "mix format --check-formatted"
---

# Superpowers Plan: `http_web_socket`

## Objective

Implement a sibling Mix child app named `:http_web_socket` that exposes
`HTTP.WebSocket`, a browser-like WebSocket client API for Elixir. Use
`docs/http_web_socket_design.md` as the source design.

## Ground Rules

- Every checklist item below is intended as a 2-5 minute implementor checkpoint.
- Work phase by phase. Do not start connection-process work before the pure
  options, handshake, and frame modules have focused tests.
- Only modify files listed in frontmatter `scope`.
- Do not route WebSocket upgrades through `HTTP.fetch/2`.
- Do not change existing `HTTP.fetch/2` behavior.
- Keep options flat. Do not add `options:`, `opts:`, or `client_opts:`.
- Use process ownership only for runtime socket state, send queue state,
  receive fragmentation state, and close lifecycle.
- Closed connection children must use `restart: :temporary`.
- If a dependency bug or missing feature is found in a configured upstream org,
  create the upstream issue and add the required upstream comment before
  continuing.

## Architecture Target

```text
HTTP.WebSocket                 # public browser-like API
HTTP.WebSocket.Event           # open/message/error/close structs
HTTP.WebSocket.ArrayBuffer     # explicit binary send wrapper
HTTP.WebSocket.Options         # pure constructor/init normalization
HTTP.WebSocket.Handshake       # pure RFC 6455 opening handshake logic
HTTP.WebSocket.Frame           # pure RFC 6455 frame encode/parse logic
HTTP.WebSocket.Connection      # socket owner and lifecycle process
HTTP.WebSocket.Telemetry       # telemetry event helpers
HTTPWebSocket.Application      # DynamicSupervisor + Registry
```

## Phase 1: App Scaffold

- [x] SP-001 Create `apps/http_web_socket/mix.exs` with umbrella paths matching
  `apps/http_fetch/mix.exs`.
- [x] SP-002 Add `{:http_core, "~> 0.9.1", in_umbrella: true, hex: :http_core}` and `{:telemetry, "~> 1.0"}`
  to the child app dependencies.
- [x] SP-003 Add `extra_applications: [:logger, :crypto, :public_key, :ssl]`.
- [x] SP-004 Create `apps/http_web_socket/.formatter.exs` with the same local
  input style as `apps/http_fetch/.formatter.exs`.
- [x] SP-005 Create `apps/http_web_socket/lib/http_web_socket.ex` with a short
  app-level moduledoc.
- [x] SP-006 Create `HTTPWebSocket.Application` with a `DynamicSupervisor`
  named `HTTP.WebSocket.ConnectionSupervisor`.
- [x] SP-007 Add a unique-key `Registry` named `HTTP.WebSocket.Registry`.
- [x] SP-008 Create `apps/http_web_socket/test/test_helper.exs`.
- [x] SP-009 Run `mix compile --warnings-as-errors` and fix only scaffold
  warnings.

## Phase 2: Public API Shell

- [x] SP-010 Create `apps/http_web_socket/lib/http/web_socket.ex`.
- [x] SP-011 Define `%HTTP.WebSocket{pid: nil, ref: nil, url: nil}`.
- [x] SP-012 Add constants `connecting/0`, `open/0`, `closing/0`, and
  `closed/0`.
- [x] SP-013 Add a placeholder `new/3` that validates input through
  `HTTP.WebSocket.Options` once that module exists.
- [x] SP-014 Add `url/1` as a pure accessor from the socket struct.
- [x] SP-015 Add process-backed accessors with bounded `GenServer.call/3`:
  `ready_state/1`, `buffered_amount/1`, `extensions/1`, `protocol/1`, and
  `binary_type/1`.
- [x] SP-016 Add `set_binary_type/2` with accepted values `:blob` and
  `:array_buffer`.
- [x] SP-017 Add public `send/2` and `close/1..3` placeholders returning
  explicit expected errors until the connection process is ready.
- [x] SP-018 Create `apps/http_web_socket/test/http/web_socket_test.exs` with
  constant and struct tests.
- [x] SP-019 Run `mix test apps/http_web_socket/test/http/web_socket_test.exs`.

## Phase 3: Browser Event Structs

- [x] SP-020 Create `apps/http_web_socket/lib/http/web_socket/event.ex`.
- [x] SP-021 Define `%HTTP.WebSocket.Event.Open{target: nil, type: "open"}`.
- [x] SP-022 Define `%HTTP.WebSocket.Event.Message{target: nil, type:
  "message", data: nil, origin: nil}`.
- [x] SP-023 Define `%HTTP.WebSocket.Event.Error{target: nil, type: "error",
  reason: nil}`.
- [x] SP-024 Define `%HTTP.WebSocket.Event.Close{target: nil, type: "close",
  code: nil, reason: "", was_clean: false}`.
- [x] SP-025 Add event struct assertions to `web_socket_test.exs`.
- [x] SP-026 Run `mix test apps/http_web_socket/test/http/web_socket_test.exs`.

## Phase 4: Explicit Binary Wrapper

- [x] SP-027 Create `apps/http_web_socket/lib/http/web_socket/array_buffer.ex`.
- [x] SP-028 Define `%HTTP.WebSocket.ArrayBuffer{data: <<>>, byte_length: 0}`.
- [x] SP-029 Add `HTTP.WebSocket.array_buffer/1` for binary input.
- [x] SP-030 Return `{:error, :invalid_array_buffer}` for non-binary input.
- [x] SP-031 Add wrapper tests to `web_socket_test.exs`.
- [x] SP-032 Run `mix test apps/http_web_socket/test/http/web_socket_test.exs`.

## Phase 5: Options Functional Core

- [x] SP-033 Create `apps/http_web_socket/lib/http/web_socket/options.ex`.
- [x] SP-034 Create
  `apps/http_web_socket/test/http/web_socket/options_test.exs`.
- [x] SP-035 Add URL normalization for string and `URI` input.
- [x] SP-036 Map `http` to `ws` and `https` to `wss`.
- [x] SP-037 Reject unsupported schemes with `{:error, {:unsupported_scheme,
  scheme}}`.
- [x] SP-038 Reject URLs with fragments.
- [x] SP-039 Normalize protocols from omitted value, string, and list.
- [x] SP-040 Reject duplicate protocol names.
- [x] SP-041 Reject protocol tokens that cannot appear in
  `Sec-WebSocket-Protocol`.
- [x] SP-042 Normalize flat init fields: `owner`, `binary_type`, `headers`,
  `timeout`, `connect_timeout`, `ssl`, `socket_opts`, and `max_message_size`.
- [x] SP-043 Run
  `mix test apps/http_web_socket/test/http/web_socket/options_test.exs`.

## Phase 6: Handshake Functional Core

- [x] SP-044 Create `apps/http_web_socket/lib/http/web_socket/handshake.ex`.
- [x] SP-045 Create
  `apps/http_web_socket/test/http/web_socket/handshake_test.exs`.
- [x] SP-046 Add `accept_key/1` using RFC 6455 GUID hashing.
- [x] SP-047 Add `build_request/4` with required WebSocket headers.
- [x] SP-048 Add tests for root path, non-root path, and query string targets.
- [x] SP-049 Add optional `Sec-WebSocket-Protocol` request header support.
- [x] SP-050 Prevent caller headers from overriding required handshake headers.
- [x] SP-051 Add `validate_response/4` requiring status `101`.
- [x] SP-052 Validate `Upgrade`, `Connection`, and `Sec-WebSocket-Accept`.
- [x] SP-053 Reject selected protocols not requested by the caller.
- [x] SP-054 Reject unexpected `Sec-WebSocket-Extensions`.
- [x] SP-055 Run
  `mix test apps/http_web_socket/test/http/web_socket/handshake_test.exs`.

## Phase 7: Frame Functional Core

- [x] SP-056 Create `apps/http_web_socket/lib/http/web_socket/frame.ex`.
- [x] SP-057 Create `apps/http_web_socket/test/http/web_socket/frame_test.exs`.
- [x] SP-058 Add `encode/3` for `:text` frames with client masking.
- [x] SP-059 Add `encode/3` for `:binary` frames with client masking.
- [x] SP-060 Add `encode/3` for `:close`, `:ping`, and `:pong`.
- [x] SP-061 Test minimal payload length encoding for `0..125`, `126`, and
  `127` length markers.
- [x] SP-062 Reject control frame payloads larger than 125 bytes.
- [x] SP-063 Add `new_parser/1` with `max_message_size`.
- [x] SP-064 Parse unfragmented server text frames.
- [x] SP-065 Parse unfragmented server binary frames.
- [x] SP-066 Reject masked server frames.
- [x] SP-067 Reject non-zero RSV bits.
- [x] SP-068 Reject unknown opcodes with close code `1002` metadata.
- [x] SP-069 Parse close frame code and reason.
- [x] SP-070 Parse ping and pong frames.
- [x] SP-071 Reassemble fragmented text messages.
- [x] SP-072 Reassemble fragmented binary messages.
- [x] SP-073 Reject invalid continuation sequences.
- [x] SP-074 Reject fragmented control frames.
- [x] SP-075 Reject text messages with invalid UTF-8 using close code `1007`.
- [x] SP-076 Reject oversized messages using close code `1009`.
- [x] SP-077 Run `mix test apps/http_web_socket/test/http/web_socket/frame_test.exs`.

## Phase 8: Connection Process

- [x] SP-078 Create `apps/http_web_socket/lib/http/web_socket/connection.ex`.
- [x] SP-079 Define connection state fields for owner, socket struct, URL,
  transport, ready state, parser, protocol, extensions, binary type,
  buffered amount, send queue, close status, and timers.
- [x] SP-080 Implement `child_spec/1` with `restart: :temporary`.
- [x] SP-081 Start the connection from `HTTP.WebSocket.new/3` under
  `HTTP.WebSocket.ConnectionSupervisor`.
- [x] SP-082 Move network connection work into `handle_continue/2`.
- [x] SP-083 Select TCP transport for `ws`.
- [x] SP-084 Select SSL transport for `wss`.
- [x] SP-085 Send the opening handshake request.
- [x] SP-086 Read until `\r\n\r\n` for the opening response headers.
- [x] SP-087 Validate the opening handshake using `Handshake.validate_response/4`.
- [x] SP-088 Transition to `OPEN` and emit `%HTTP.WebSocket.Event.Open{}`.
- [x] SP-089 Emit `%HTTP.WebSocket.Event.Error{}` and `%Event.Close{}` on
  failed connection setup.
- [x] SP-090 Enable active-once socket receive after the handshake.
- [x] SP-091 Feed received socket bytes into `Frame.parse/2`.
- [x] SP-092 Emit `%Event.Message{}` for complete text messages.
- [x] SP-093 Emit `%Event.Message{}` for binary messages as `HTTP.Blob` when
  `binary_type == :blob`.
- [x] SP-094 Emit `%Event.Message{}` for binary messages as
  `HTTP.WebSocket.ArrayBuffer` when `binary_type == :array_buffer`.
- [x] SP-095 Automatically reply to server ping frames with pong frames.
- [x] SP-096 Respond to peer close with a close frame if one has not been sent.
- [x] SP-097 Close transport and emit one final close event when closed.
- [x] SP-098 Run `mix test apps/http_web_socket/test/http/web_socket_test.exs`.

## Phase 9: Send and Close API

- [x] SP-099 Implement `HTTP.WebSocket.send/2` through the connection process.
- [x] SP-100 Return `{:error, :invalid_state}` when sending during
  `CONNECTING`.
- [x] SP-101 Treat plain Elixir binaries as UTF-8 text frame payloads.
- [x] SP-102 Treat `HTTP.Blob` payloads as binary frame payloads.
- [x] SP-103 Treat `HTTP.WebSocket.ArrayBuffer` payloads as binary frame
  payloads.
- [x] SP-104 Increment `buffered_amount` before enqueue.
- [x] SP-105 Decrement `buffered_amount` after successful transport send.
- [x] SP-106 Start close handling if the send queue exceeds the configured
  limit.
- [x] SP-107 Implement `close/1` with no status code payload.
- [x] SP-108 Implement `close/2` and `close/3` close code validation.
- [x] SP-109 Reject close reasons longer than 123 UTF-8 bytes.
- [x] SP-110 No-op when already `CLOSING` or `CLOSED`.
- [x] SP-111 Fail the opening handshake when closing during `CONNECTING`.
- [x] SP-112 Preserve already queued sends before the close frame where
  possible.
- [x] SP-113 Run `mix test apps/http_web_socket/test/http/web_socket_test.exs`.

## Phase 10: Telemetry

- [x] SP-114 Create `apps/http_web_socket/lib/http/web_socket/telemetry.ex`.
- [x] SP-115 Create
  `apps/http_web_socket/test/http/web_socket/telemetry_test.exs`.
- [x] SP-116 Emit `[:http_web_socket, :connect, :start]`.
- [x] SP-117 Emit `[:http_web_socket, :connect, :stop]`.
- [x] SP-118 Emit `[:http_web_socket, :connect, :exception]`.
- [x] SP-119 Emit `[:http_web_socket, :message, :received]`.
- [x] SP-120 Emit `[:http_web_socket, :message, :sent]`.
- [x] SP-121 Emit `[:http_web_socket, :close, :start]`.
- [x] SP-122 Emit `[:http_web_socket, :close, :stop]`.
- [x] SP-123 Run
  `mix test apps/http_web_socket/test/http/web_socket/telemetry_test.exs`.

## Phase 11: Documentation

- [x] SP-124 Add concise `HTTP.WebSocket` usage examples to `README.md`.
- [x] SP-125 Document text sends, binary sends, owner-process receive, and
  close handling.
- [x] SP-126 Document browser compatibility differences in the
  `HTTP.WebSocket` moduledoc.
- [x] SP-127 Keep existing `HTTP.fetch/2` README examples intact.
- [x] SP-128 Run `mix docs`.

## Phase 12: Final Quality Gate

- [x] SP-129 Run `mix test apps/http_web_socket/test`.
- [x] SP-130 Run `mix compile --warnings-as-errors`.
- [x] SP-131 Run `mix format --check-formatted`.
- [x] SP-132 Run `mix credo`.
- [x] SP-133 Run `mix dialyzer` if public specs or app structure affect
  success typings.
- [x] SP-134 Review `git diff` for accidental `http_fetch` behavior changes.

## Stop Conditions

- Stop if a blocker upstream issue is created for a dependency problem.
- Stop if existing `apps/http_fetch/test` behavior fails and the failure is not
  caused by this plan's scoped changes.
- Stop if supporting WebSocket extensions becomes necessary for MVP behavior;
  extension negotiation is intentionally later work.
- Stop if the public API must choose between browser parity and Elixir
  ergonomics beyond the decisions already captured in the source design.

## Done Definition

- `HTTP.WebSocket.new/3` starts a connection and emits owner-process events.
- Text, binary, ping, pong, and close frames follow RFC 6455 client rules.
- `ready_state`, `buffered_amount`, `protocol`, `extensions`, `binary_type`,
  and `url` are observable through public accessors.
- The app compiles without warnings.
- Scoped WebSocket tests pass.
- README and moduledocs explain the browser compatibility boundary.
