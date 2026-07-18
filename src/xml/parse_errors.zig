//! Human-readable messages for `xml.parser.ParseError` values.
//!
//! One switch keeps diagnostic text identical whether XML fails in
//! `validate.zig` or a validator's standalone `run()` loop.

const std = @import("std");
const parser = @import("parser.zig");

pub const ParseError = parser.ParseError;

/// Maps parser errors to stable user-facing strings for `mzml.structure.xml`.
pub fn parseErrorMessage(err: ParseError) []const u8 {
    return switch (err) {
        error.UnexpectedEof => "unexpected end of XML input",
        error.InvalidUtf8 => "invalid UTF-8 in XML input",
        error.TokenTooLong => "XML token exceeds the configured parser buffer",
        error.StartTagTooLong => "XML start tag exceeds the configured start-tag limit",
        error.AttributeTooLong => "XML attribute exceeds the configured attribute limit",
        error.ScalarTextTooLong => "XML scalar text exceeds the configured scalar-text limit",
        error.BinaryTextTooLong => "XML binary text exceeds the configured binary-text limit",
        error.TooManyAttributes => "XML element has more attributes than the configured parser limit",
        error.MismatchedEndTag => "closing tag does not match the most recent opening tag",
        error.UnknownEntity => "unknown XML entity reference",
        error.UnsupportedMarkup => "DTD or unsupported XML construct",
        error.TooManyNamespaces => "XML namespace bindings exceed the configured parser limit",
        error.NamespaceStorageExceeded => "XML namespace storage exceeds the configured parser limit",
        error.ElementNestingTooDeep => "XML element nesting exceeds the configured parser limit",
        error.ElementStorageExceeded => "XML element name storage exceeds the configured parser limit",
        error.InvalidCharacterReference => "invalid XML character reference",
        error.ReadFailed => "failed while reading XML input",
        error.MalformedXml => "malformed XML input",
    };
}

// --- Unit Tests ---

test "parse errors preserve limit details" {
    try std.testing.expectEqualStrings(
        "XML start tag exceeds the configured start-tag limit",
        parseErrorMessage(error.StartTagTooLong),
    );
    try std.testing.expectEqualStrings(
        "XML attribute exceeds the configured attribute limit",
        parseErrorMessage(error.AttributeTooLong),
    );
    try std.testing.expectEqualStrings(
        "XML scalar text exceeds the configured scalar-text limit",
        parseErrorMessage(error.ScalarTextTooLong),
    );
    try std.testing.expectEqualStrings(
        "XML binary text exceeds the configured binary-text limit",
        parseErrorMessage(error.BinaryTextTooLong),
    );
    try std.testing.expectEqualStrings(
        "XML namespace bindings exceed the configured parser limit",
        parseErrorMessage(error.TooManyNamespaces),
    );
    try std.testing.expectEqualStrings(
        "XML namespace storage exceeds the configured parser limit",
        parseErrorMessage(error.NamespaceStorageExceeded),
    );
    try std.testing.expectEqualStrings(
        "XML element nesting exceeds the configured parser limit",
        parseErrorMessage(error.ElementNestingTooDeep),
    );
    try std.testing.expectEqualStrings(
        "XML element name storage exceeds the configured parser limit",
        parseErrorMessage(error.ElementStorageExceeded),
    );
}
