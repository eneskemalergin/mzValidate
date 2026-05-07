//! Single source of truth for the project version in Zig code.
//!
//! `semantic` is kept in sync with `build.zig.zon` by the `bump-version` build step.

/// Current semantic version string. Matches the `.version` field in `build.zig.zon`.
pub const semantic = "0.0.3";
