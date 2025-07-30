# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of HTTP fetch API for Elixir
- Promise-based asynchronous interface using Elixir Tasks
- Request cancellation support via AbortController
- JSON and text response parsing helpers
- Basic HTTP request/response structs
- Support for custom headers and request options
- Content-Type handling for requests with bodies
- Default timeout of 120 seconds for requests

### Technical Details
- Uses Erlang's built-in `:httpc` module for HTTP operations
- Requires Elixir 1.18+ for built-in JSON support
- Depends on Erlang standard library modules `:inets` and `:httpc`
- Provides both sync and async operation modes (default: async)
- Includes comprehensive test suite covering core functionality

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