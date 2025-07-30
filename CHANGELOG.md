# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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