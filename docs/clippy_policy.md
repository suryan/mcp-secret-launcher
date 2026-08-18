# Clippy Policy

This project enforces strict code quality using `clippy::pedantic`. 

## Rules

- **Global Policy**: `pedantic` is set to `deny` in `Cargo.toml`. Any pedantic warning will cause the build and tests to fail.
- **Local Development**: Developers are expected to fix all clippy warnings before committing. `cargo test` automatically runs clippy checks.

## Allowed Exceptions

The following lints are explicitly allowed in `Cargo.toml` to reduce noise and avoid unproductive refactoring:

1. **`too_many_lines`**: Allowed. Functions exceeding 100 lines are permitted, especially in integration tests or complex routing logic where splitting would decrease readability.
2. **`similar_names`**: Allowed. Prevents warnings for common naming patterns in tests (e.g., `res1`, `res2`).
3. **`unused_async`**: Allowed. Useful for trait implementations where `async` is required by the interface but not needed by the specific implementation.
4. **`missing_errors_doc`**: Requirement for documenting all error cases in public functions returning `Result`.
5. **`missing_panics_doc`**: Requirement for documenting all possible panic cases in public functions.


## Rationale

We use `pedantic` to catch potential logic errors, performance issues (like needless cloning), and to ensure the codebase remains idiomatic. By denying it at the crate level, we ensure that every developer works under the same constraints as the CI pipeline.
