# Changelog

## [Unreleased]

## [v0.1.7] - 2026-11-27

### Added

- Streamable HTTP tool-call spans include forwarded caller identity headers, with `User-Agent` as the fallback MCP client name when client metadata is absent (#67).
- Tools can report an `isError` result as `mcp.error.type=system_error` with `SystemErrorResult` or `_meta["last9/error-type"] = "system_error"`; untagged `isError` results stay `user_error` (#59).

### Fixed

- Tool-call cancellation and deadline errors now record distinct `cancelled` and `deadline_exceeded` outcomes across traces and metrics instead of `system_error` (#64).
- Tool calls preserve validated request trace parents and record `mcp.turn.id` from trace context or explicit turn metadata instead of grouping unrelated calls under a synthetic session query span (#58).
