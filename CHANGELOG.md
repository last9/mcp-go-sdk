# Changelog

## [Unreleased]

### Fixed

- Tool calls preserve validated request trace parents and record `mcp.turn.id` from trace context or explicit turn metadata instead of grouping unrelated calls under a synthetic session query span (#58).
