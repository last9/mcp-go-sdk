# Changelog

## [Unreleased]

### Added

- Tools can report an `isError` result as `mcp.error.type=system_error` with `SystemErrorResult` or `_meta["last9/error-type"] = "system_error"`; untagged `isError` results stay `user_error` (#59).

### Fixed

- Tool calls preserve validated request trace parents and record `mcp.turn.id` from trace context or explicit turn metadata instead of grouping unrelated calls under a synthetic session query span (#58).
