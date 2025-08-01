# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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