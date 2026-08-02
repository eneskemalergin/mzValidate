//! One version string, two places, zero excuses.
//! Keep `semantic` in sync with `build.zig.zon` or the build breaks.

/// Release version for `-version` and `build.zig` package metadata.
pub const semantic = "0.1.7";

/// Schema version emitted by `mzValidate check -json`.
pub const json_schema: u32 = 1;

pub const mapping_model = "mzML.xsd";
pub const mapping_model_version = "1.0.0";
