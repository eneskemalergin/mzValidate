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

test "parse errors preserve limit details" {
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
