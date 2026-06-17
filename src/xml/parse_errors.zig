//! Human-readable messages for `xml.parser.ParseError` values.
//!
//! One switch keeps diagnostic text identical whether XML fails in
//! `validate.zig` or a validator's standalone `run()` loop.

const parser = @import("parser.zig");

pub const ParseError = parser.ParseError;

/// Maps parser errors to stable user-facing strings for `mzml.structure.xml`.
pub fn parseErrorMessage(err: ParseError) []const u8 {
    return switch (err) {
        error.UnexpectedEof => "unexpected end of XML input",
        error.InvalidUtf8 => "invalid UTF-8 in XML input",
        error.TokenTooLong => "XML token exceeds the configured parser buffer",
        error.TooManyAttributes => "XML element has more attributes than the configured parser limit",
        error.MismatchedEndTag => "closing tag does not match the most recent opening tag",
        error.UnknownEntity => "unknown XML entity reference",
        error.UnsupportedMarkup => "DTD or unsupported XML construct",
        error.TooManyNamespaces,
        error.NamespaceStorageExceeded,
        error.ElementNestingTooDeep,
        error.ElementStorageExceeded,
        error.MalformedXml,
        error.InvalidCharacterReference,
        error.ReadFailed,
        => "malformed XML input",
    };
}
