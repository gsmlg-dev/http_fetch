# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.4] - 2026-10-05

### Fixed
- Frame binary and demand-driven uploads as HTTP/3 DATA, retain blocked work
  without freezing sibling reads, and retire completed requests exactly once.
- Decode responses incrementally with separate header and retained-byte limits,
  informational/final/trailer validation, critical streams, and GOAWAY admission.
- Correct all 99 QPACK static indexes and preserve indexed/literal field order.
- Use uv to install the release peer dependencies in its Python environment.

### Validation
- Native adapter regressions and a pinned independent aioquic binary echo gate.
  Public Fetch HTTP/3 remains unsupported pending runtime integration.

## [0.16.3] - 2026-10-05

### Fixed
- Compose HTTP/3 sessions with native QUIC generations, authenticated H3
  readiness, consistent stream handles, retained operation references, and
  explicit endpoint ownership and terminal teardown.
- Preserve cancellation isolation and reconcile ambiguous admission without
  replaying request bytes or destructive reads.
- Repair the baseline ServerHello Dialyzer warning without changing GREASE
  handling, and make release tests independent of the prepared patch version.

### Validation
- WP1 native-contract seams and local UDP session tests; public Fetch HTTP/3
  remains unsupported until the runtime and independent acceptance gates.

## [0.16.2] - 2026-10-05

### Fixed
- Restore Fetch's test dependency in isolated WebSocket and EventSource CI jobs.
- Inspect candidate Hex archives in memory using Hex's supported unpack mode.

### Validation
- WP0 baseline restoration; see `docs/http3-wp0-baseline.md` and
  `docs/http3-implementation-audit.md`. HTTP/3 remains unsupported at this step.

## [0.16.1] - 2026-10-01

### Changed
- Remove the `elixir_quic_http3` sub-app after its migration to
  `gsmlg-dev/ex_quic`, including unused dependencies from Fetch and WebTransport.
- Update six-package CI, release, and consumer tooling and current documentation
  to reflect the new ownership boundary. HTTP/3 and WebTransport selectors
  remain explicitly unsupported pending integration and interoperability work.

### Fixed
- Keep isolated package consumers on explicit shared local dependency overrides
  after removing the migrated package.

## [0.16.0] - 2026-10-01

### Added
- Extract `http_runtime` as the shared, independently installable HTTP/2 owner,
  pool and stream application used by Fetch, EventSource and WebSocket.
- Add explicitly selected HTTP/2/h2c EventSource and RFC 8441 WebSocket support,
  acknowledged delivery, finite parsing/send/delivery bounds and actual-version
  accessors. Preserve HTTP/1 defaults and explicit TLS backend selection.
- Add independent SSE/WebSocket/mixed peers, standalone package traffic gates and
  a reproducible final acceptance entrypoint with original Fetch42 workloads.

### Fixed
- Preserve ordinary Fetch early-response upload cleanup while accepted CONNECT
  tunnels remain duplex; gate admission on peer capability without blocking
  ordinary siblings or consuming stream capacity while waiting.
- Settle logical stream resources on close, owner death, reset and runtime restart,
  retain accepted bytes before terminal errors, and stop parsing after an internal
  WebSocket terminal failure.
- Mask WebSocket payloads using binary words to avoid per-byte list heap growth.

### Validation
- See `docs/http2-stream-clients-validation.md` for exact phase/final-candidate
  results, source and artifact checksums, backend/peer matrices and resource
  observations. Short runner checks are explicitly distinct from 30-minute soaks.

## [0.15.1] - 2026-09-30

### Fixed
- Stop abandoned HTTP/2 uploads atomically after final response headers, retain
  incomplete response bodies and trailers, and close unfinished request halves
  before releasing peer capacity without replaying upload DATA.
- Promote queued, never-sent requests when connection capacity becomes available,
  including owner shutdown, draining, cross-origin capacity release, and a
  saturated surviving sibling, while preserving deadlines and connection limits.
- Preserve sibling upload scheduling when an already-stopped stream is removed
  again during cleanup.

### Validation
- Add deterministic wire-level early-response, queued-admission, lifecycle and
  package-consumer regressions with explicit event barriers.
- Complete all 42 local HTTP/2 acceptance gates, including both independent peers,
  supported transports, 10-MiB transfers, 10,000-request reuse workloads and a
  full 30-minute mixed soak. See `docs/http2-production-validation.md` for exact
  candidate provenance, outcomes, resource bounds and archived evidence.

## [0.15.0] - 2026-09-30

### Added
- Include `elixir_quic_http3` in the coordinated six-package release, with
  versioned HTTP/3 dependencies for Fetch and WebTransport and standalone
  package-consumer validation.

### Changed
- Route explicit HTTP/2 and h2c requests through supervised, profile-aware pooled
  owners, including requests without an explicit wire profile.
- Reclaim completed protocol streams; slice binary and streaming uploads by
  available peer credit; bound download admission and return stream credit on
  consumption.
- Validate frame boundaries, response phases and lengths, HPACK table updates,
  and peer settings; preserve typed reset/GOAWAY outcomes and original deadlines.
- Advertise no server push in wire-profile revision 2, with cold/warm header
  ordering applied once. Keep synthetic profiles explicitly synthetic.
- Add redacted connection/pool telemetry and independent peer/package/soak gates.

### Known limitations
- HTTP/2 production acceptance remains in progress; see
  `docs/http2-production-validation.md` for failing or unrun blocking gates.

## [0.14.0] - 2026-09-29

### Added
- Add an internal authenticated QUIC client adapter with bounded stream I/O,
  cancellation, operation outcome tracking, and lifecycle validation.
- Add published TLS consumer provenance and independent resumption coverage
  for HTTP/1.1, HTTP/2, WebSocket, and EventSource.
- Add validated versioned HTTP/2 wire profiles, ordered serialization controls,
  pure connection/stream state models, and bounded redacted fingerprint observations.
- Add flat HTTP/2 profile, reuse, scope, and priority option validation.
- Add bounded PRIORITY_UPDATE handling, upload credit recovery after
  WINDOW_UPDATE, peer MAX_FRAME_SIZE DATA fragmentation, and capture provenance
  manifest validation.

### Changed
- Use Hex `elixir_quic ~> 0.2.2` and `ex_ssl ~> 0.7.2`, with no runtime Git pins.
- Preserve OTP TLS defaults and existing production HTTP/3/WebTransport paths.

### Known limitations
- The new adapter does not implement HTTP/3 sessions or QPACK. The Abyss joint
  raw-stream test awaits its published-engine namespace migration (abyss #5).
- Full drain-deadline policy, broader independent mature-implementation
  interoperability, and captured browser-profile verification remain pending.
  Profiled h2c and HTTPS h2 pooling support overlapping socket streams while
  preserving TLS/profile identity isolation.

## [0.13.0] - 2026-09-22

### Changed
- Publish all five packages at the shared 0.13.0 version and update their
  internal `http_core` dependency requirements to `~> 0.13.0`.
- Retain the ex_ssl `~> 0.4.0` integration from 0.12.0 without further runtime
  changes; OTP `:ssl` remains the default TLS backend.

## [0.12.0] - 2026-09-22

### Added
- Add verified ex_ssl 0.4.0 TLS 1.2 support across Fetch, HTTP/2, WebSocket,
  and EventSource, and opt-in TLS 1.3 ticket resumption over fresh HTTP/1.1
  connections. The default remains verified TLS 1.3 with tickets disabled.
- Forward validated ex_ssl client identities, TCP socket options, and ordered
  TLS 1.3 algorithm preferences. Pin client identities to the redirect origin.

### Changed
- Keep OTP `:ssl` as the default TCP TLS backend while allowing verified TLS
  1.3 or explicitly selected TLS 1.2 through the optional `:ex_ssl` backend.
  HTTP/3 and
  WebTransport continue to use QUIC's independent TLS implementation.
- Run individual app tests and E2E suites from the umbrella root after explicit
  test-environment preparation, so transitive runtime applications are compiled
  and on the code path even on cold checkouts.
- Validate all five built packages in an isolated external consumer, including
  transitive dependencies and verified local TLS requests.

### Fixed
- Deliver complete HTTP/2 responses when the peer closes immediately after an
  END_STREAM DATA frame and a non-essential WINDOW_UPDATE or acknowledgement
  returns `:closed`. Incomplete responses and required request writes before
  response completion still fail normally.
- Preserve unread ex_ssl TLS records when an HTTP/2 control write fails after
  normal peer closure. Drain them through the existing active-once receiver and
  require a complete HTTP/2 response, without extending deadlines or accepting
  truncated responses, error resets, or protocol errors.
- Preserve valid HTTP/2 early final responses while cancelling remaining upload
  DATA, including queued DATA released by WINDOW_UPDATE. Accept NO_ERROR resets
  only after response completion; require END_STREAM and a complete field block
  even for responses with no body.
- Enforce HTTP/2 response Content-Length and bounded frame/header parsing while
  preserving valid cross-record and streaming completion after peer closure.

## [0.11.0] - 2026-07-04

### Added
- Added Fetch-style streaming response bodies by exposing the stream PID in
  `response.body`, while keeping `response.stream` as a compatibility alias.
- Added HTTP/1.1 streaming request uploads with `HTTP.Stream` bodies and
  `duplex: "half"` chunked request framing.

### Changed
- Updated response helpers, docs, and e2e coverage for the new streamed body
  shape.
- Return explicit unsupported errors for streaming request bodies on HTTP/2 and
  HTTP/3 instead of buffering or misframing them.

## [0.10.0] - 2026-07-01

### Added
- Added independent `http_web_socket`, `http_event_source`, and
  `http_web_transport` umbrella apps with browser-like protocol APIs.
- Added e2e coverage for EventSource, WebSocket, and WebTransport workflows.

### Changed
- Extracted shared HTTP primitives into the `http_core` app so protocol apps
  share common code without depending on `http_fetch`.
- Updated CI, test, e2e, and release workflows to cover every umbrella app and
  publish all packages with one shared version.

## [0.9.1] - 2026-06-23

### Changed
- Removed legacy `:httpc` compatibility option buckets from `HTTP.fetch/2`.
  Fetch init options are now flat, and redirects use `redirect: :follow | :manual | :error`.

### Fixed
- Validate response `Transfer-Encoding` framing instead of falling back to
  `Content-Length` for unsupported transfer codings.
- Keep completed empty streams readable for late consumers.
- Make the Unix socket e2e coverage independent of a host Docker daemon.
- Align release metadata, README examples, and project guidance with the socket
  transport.

## [0.9.0] - 2026-06-17

### Changed
- Replaced `:httpc` with the internal socket transport while preserving the default
  redirect-following behavior; pass `autoredirect: false` to return redirect responses.
- Legacy `:httpc` options that are not implemented by the socket transport are documented
  as compatibility-only options.

## [0.7.0] - 2025-01-XX

### Added - Browser Fetch API Compatibility (~85% API Parity)
- **HTTP.StatusText module** - Maps HTTP status codes to standard status text messages (60+ codes)
- **Response.status_text** - Status message property (e.g., "OK", "Not Found")
- **Response.ok** - Boolean property indicating success (true for 200-299 status codes)
- **Response.body_used** - Tracks body consumption (field exists for API compatibility)
- **Response.redirected** - Indicates if response was redirected
- **Response.type** - Response type (`:basic`, `:cors`, `:error`, `:opaque`)
- **Response.new/1** - Constructor helper that auto-populates Browser API fields
- **Response.clone/1** - Clone response for multiple reads (buffers streaming responses)
- **Response.arrayBuffer/1** - Read body as binary (ArrayBuffer equivalent)
- **Response.array_buffer/1** - Snake_case alias for arrayBuffer
- **HTTP.Blob module** - Blob struct with `data`, `type`, and `size` fields
- **Response.blob/1** - Read body as Blob with metadata (extracts MIME type from headers)
- Comprehensive Browser API compatibility documentation in README
- 41 new tests covering all Browser Fetch API features

### Changed - Breaking Changes for Browser API Compatibility
- **Response struct fields added**: `status_text`, `ok`, `body_used`, `redirected`, `type`
  - **Migration**: Update pattern matches to ignore new fields or use variable binding
  - Example: `%Response{status: 200} = response` (ignores new fields)
- **Response construction**: All internal Response creation now uses `Response.new/1`
  - Ensures consistent Browser API field population
  - **Migration**: Use `Response.new/1` instead of direct `%Response{}` for consistency
- **body_used field**: Present for Browser API compatibility but doesn't enforce in Elixir
  - Due to Elixir's immutability, multiple reads of the same response value work
  - Use `clone/1` for clarity when reading multiple times

### Documentation
- Added "Browser Fetch API Compatibility" section to README with examples
- Documented Elixir-specific differences (immutability, synchronous returns, streams)
- Updated all Response documentation to reflect new Browser API properties
- Added comprehensive examples for `clone/1`, `arrayBuffer/1`, and `blob/1`

### Notes
- This release prioritizes Browser Fetch API compatibility over Elixir-specific patterns
- The `body_used` field exists for API compatibility but cannot prevent multiple reads due to immutability
- All critical Browser Fetch API Response properties and methods are now supported

## [0.5.0] - 2025-08-01

### Added
- **HTTP.Telemetry module** - Complete telemetry integration for HTTP request monitoring
  - Request lifecycle events with rich metadata
  - Response body reading events for tracking download progress
  - Streaming events for real-time data transfer monitoring
  - Zero configuration integration with Elixir's :telemetry library

### Changed
- Updated default User-Agent string format to include library version 0.5.0
- Enhanced telemetry event metadata with improved error reporting

## [0.4.3] - 2025-08-01

### Added
- Added `HTTP.Headers.set_default/3` method to set headers only if they don't already exist
  - Uses case-insensitive header name matching
  - Preserves existing headers when they already contain the specified name
- Added automatic default `User-Agent` header to all HTTP requests
  - Format: `Mozilla/5.0 (macOS; aarch64-apple-darwin24.3.0) OTP/27 BEAM/15.2.3 Elixir/1.18.3 http_fetch/0.4.3`
  - Includes OS information, system architecture, OTP version, BEAM version, Elixir version, and library version
  - Uses dynamic version detection via `Application.spec(:http_fetch, :vsn)`
  - Preserves custom `User-Agent` headers when provided
- Added `HTTP.Headers.user_agent/0` method to access the default User-Agent string
- Added comprehensive `HTTP.Telemetry` module for HTTP request metrics and monitoring
  - **Request lifecycle events**: `[:http_fetch, :request, :start]`, `[:http_fetch, :request, :stop]`, `[:http_fetch, :request, :exception]`
  - **Response body reading events**: `[:http_fetch, :response, :body_read_start]`, `[:http_fetch, :response, :body_read_stop]`
  - **Streaming events**: `[:http_fetch, :streaming, :start]`, `[:http_fetch, :streaming, :chunk]`, `[:http_fetch, :streaming, :stop]`
  - **Rich metadata**: Includes URLs, HTTP status codes, response sizes, durations, and error reasons
  - **Automatic integration**: All HTTP.fetch operations automatically emit telemetry events
  - **Zero configuration**: Works out of the box with Elixir's :telemetry library

### Changed
- Enhanced User-Agent string to include system architecture information
- Refactored User-Agent generation for consistency across the codebase
- Updated default headers handling to use `set_default/3` for better extensibility

## [0.4.2] - 2025-08-01

### Added
- Added `HTTP.Response.write_to/2` method to write response bodies to files
  - Supports both streaming and non-streaming responses
  - Automatically creates directories if they don't exist
  - Returns `:ok` or `{:error, reason}` for proper error handling

### Fixed
- Fixed streaming implementation message format for complete responses
- Increased streaming threshold from 100KB to 5MB to prevent issues with large files
- Fixed test assertion for content-length comparison using `byte_size/1` instead of `length/1`

### Changed
- Updated streaming threshold to prevent streaming for files under 5MB
- Improved streaming process error handling

## [0.4.1] - 2025-07-31

### Added
- **URI struct support** - HTTP.fetch/2 now accepts both string URLs and %URI{} structs
- **Enhanced URL handling** - Automatic conversion from string to %URI{} for internal processing
- **Type safety improvements** - HTTP.Request and HTTP.Response now use %URI{} internally
- **Improved Request field naming** - More intuitive field names for :httpc.request mapping

### Changed
- **Refactored URL handling** - All internal representations now use %URI{} instead of string
- **Updated type specifications** - HTTP.Request.url type changed from String.t() | charlist() to URI.t()
- **Updated Response.url type** - Changed from String.t() to URI.t()
- **Updated function signatures** - handle_httpc_response and related functions now accept URI.t()
- **HTTP.Request field renaming** for better clarity:
  - `options` → `http_options` (3rd argument to :httpc.request)
  - `opts` → `options` (4th argument to :httpc.request)

### Technical Details
- **Backward compatibility** - String URLs are automatically parsed to URI structs
- **Consistent URI handling** - All internal operations use parsed URI structs
- **Eliminated redundant parsing** - Removed duplicate URI.parse calls in streaming functions
- **Enhanced type safety** - Stronger typing throughout the codebase
- **Updated test suite** - Request tests updated to use URI.parse/1 for consistency
- **Improved field documentation** - Clear mapping to :httpc.request arguments

## [0.4.0] - 2025-07-30

### Added
- **HTTP.FetchOptions module** - New dedicated module for processing fetch options with full httpc support
- **Enhanced option handling** - Support for all :httpc.request options including timeout, SSL, streaming, etc.
- **Multiple input formats** - Accept keyword lists, maps, or HTTP.FetchOptions struct
- **Complete httpc integration** - Proper separation of HttpOptions and Options for :httpc.request
- **Type-safe configuration** - Structured approach to HTTP request configuration
- **Comprehensive option coverage** - All documented :httpc.request options supported
- **HTTP.FormData module** - New dedicated module for handling form data and multipart/form-data encoding
- **File upload support** - Support for file uploads with streaming via `File.Stream.t()`
- **Automatic content type detection** - Automatically chooses between `application/x-www-form-urlencoded` and `multipart/form-data`
- **Streaming file uploads** - Efficient large file uploads using Elixir streams
- **Form data builder API** - Fluent interface with `new/0`, `append_field/3`, `append_file/4-5`
- **Multipart boundary generation** - Automatic random boundary generation for multipart requests
- **Comprehensive test coverage** - Full test suite for form data and fetch options functionality

### Changed
- **HTTP.fetch refactored** - Now uses HTTP.FetchOptions for consistent option processing
- **HTTP.Request body parameter** - Now accepts `HTTP.FormData.t()` for form submissions
- **Enhanced content type handling** - Automatic content-type detection and header setting
- **Improved multipart encoding** - Proper multipart/form-data format with boundaries
- **Unified configuration API** - All configuration goes through HTTP.FetchOptions

### Technical Details
- **HTTP.FetchOptions struct** with comprehensive field support for all httpc options
- **FormData struct** with parts array for form fields and file uploads
- **Streaming support** via `File.Stream.t()` for memory-efficient file uploads
- **URL encoding fallback** for simple form data without file uploads
- **Backward compatibility** maintained for existing string/charlist body usage

## [0.3.0] - 2025-07-30

### Fixed
- **HTTP option placement** - Fixed `body_format: :binary` option being passed to wrong :httpc argument
- **Eliminated warning messages** - Removed "Invalid option {body_format,binary} ignored" notices during tests
- **Improved error handling** - Enhanced response handling for malformed URLs and network errors

### Technical Details
- **Corrected httpc arguments** - Proper separation of request options vs client options
- **Cleaned up streaming setup** - Removed redundant option configurations
- **Enhanced test reliability** - Reduced external dependency flakiness

## [0.2.0] - 2025-07-30

### Added
- **HTTP.Headers module** - New dedicated module for HTTP header processing
- **Structured headers** - HTTP.Request and HTTP.Response now use `HTTP.Headers.t()` struct
- **Header manipulation utilities** - `new/1`, `get/2`, `set/3`, `merge/2`, `delete/2`, etc.
- **Header parsing** - Content-Type parsing with media type and parameters extraction
- **Case-insensitive header access** via `HTTP.Headers.get/2` and `HTTP.Response.get_header/2`
- **Backward compatibility** - HTTP.fetch still accepts list/map formats with auto-conversion

### Changed
- **Refactored header storage** from plain lists to `HTTP.Headers` struct
- **Enhanced type safety** with proper struct types throughout the codebase
- **Updated Response API** - Added `get_header/2` and `content_type/1` helper methods

### Technical Details
- **New HTTP.Headers struct** with comprehensive header manipulation capabilities
- **Immutable operations** - All header operations return new struct instances
- **Automatic conversion** - Input formats (list/map) auto-converted to struct
- **Enhanced documentation** with examples for new header functionality
- **Maintained backward compatibility** - Existing code continues to work

## [0.1.0] - 2025-07-30

### Added
- Initial project setup with Mix
- Basic project structure and configuration
- Core HTTP fetch functionality
- Response and Request struct definitions
- Promise implementation for async operations
- AbortController for request cancellation
- Comprehensive test coverage
- Documentation and README
