# Changelog

## [Unreleased]

### Added

- Streamable HTTP tool-call spans now record forwarded caller identity as `user_agent.original`, `mcp.source`, `user.id`, and `token.kind`, with User-Agent as a fallback for missing MCP client names (#68).

## [v0.1.7] - 2026-11-27

### Added

- Tools can report an `isError` result as `mcp.error.type=system_error` with `SystemErrorResult` or `_meta["last9/error-type"] = "system_error"`; untagged `isError` results stay `user_error` (#59).

### Fixed

- Tool-call cancellation and deadline errors now record distinct `cancelled` and `deadline_exceeded` outcomes across traces and metrics instead of `system_error` (#64).
- Tool calls preserve validated request trace parents and record `mcp.turn.id` from trace context or explicit turn metadata instead of grouping unrelated calls under a synthetic session query span (#58).
