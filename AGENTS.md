# Engineering guidance

- Keep telemetry-only fallbacks out of session identity. Derive them when emitting telemetry, and test anonymous-session isolation and cleanup.
