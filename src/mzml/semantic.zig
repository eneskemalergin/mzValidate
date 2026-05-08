//! CV accession and namespace validation for mzML files.
//!
//! Validates every `<cvParam>` and `<userParam>` against the CvTable built
//! from psi-ms.obo. Checks:
//!   - Accession exists in the CV
//!   - Term is not obsolete
//!   - cvRef matches the term's namespace
//!
//! Slice B of Phase 3. Wired into `checkReader` alongside structural, binary,
//! and index validators.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const obo = @import("../obo/parser.zig");
const xml_events = @import("../xml/events.zig");

const Attribute = xml_events.Attribute;
const CvTable = obo.CvTable;
const Diagnostic = diagnostic.Diagnostic;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const QName = xml_events.QName;

/// Namespace used for mzML cvParams.
const mzml_namespace = "http://psi.hupo.org/ms/mzml";

pub const SemanticValidator = struct {
    cv_table: *const CvTable,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, cv_table: *const CvTable, diagnostics: *std.ArrayList(Diagnostic), path: ?[]const u8) SemanticValidator {
        return .{
            .allocator = allocator,
            .cv_table = cv_table,
            .diagnostics = diagnostics,
            .path = path,
        };
    }

    pub fn deinit(_: *SemanticValidator) void {}

    /// Process a start element event. If the element is a cvParam or userParam
    /// with an accession, validate it against the CvTable.
    pub fn consumeStart(validator: *SemanticValidator, start: StartElement, _: usize) !void {
        if (!start.name.matches(mzml_namespace, "cvParam") and !start.name.matches(mzml_namespace, "userParam")) return;

        const accession = attributeValue(start.attributes, "accession") orelse return;
        const cv_ref = attributeValue(start.attributes, "cvRef") orelse return;

        const term = validator.cv_table.lookup(accession);
        if (term) |t| {
            if (t.is_obsolete) {
                const msg = if (t.replaced_by) |repl|
                    try std.fmt.allocPrint(validator.allocator, "CV term {s} ({s}) is obsolete; consider {s}", .{ accession, t.name, repl })
                else
                    try std.fmt.allocPrint(validator.allocator, "CV term {s} ({s}) is obsolete", .{ accession, t.name });
                defer validator.allocator.free(msg);
                try validator.diagnostics.append(validator.allocator, .{
                    .severity = .warning,
                    .rule = RuleId.mzml_cv_obsolete,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = msg,
                });
                return;
            }
            if (!std.mem.eql(u8, t.namespace, cv_ref)) {
                const msg = try std.fmt.allocPrint(validator.allocator, "cvRef \"{s}\" does not match namespace of {s}", .{ cv_ref, accession });
                defer validator.allocator.free(msg);
                try validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_cv_namespace,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = msg,
                });
                return;
            }
        } else {
            const msg = try std.fmt.allocPrint(validator.allocator, "unrecognized CV accession {s}", .{accession});
            defer validator.allocator.free(msg);
            try validator.diagnostics.append(validator.allocator, .{
                .severity = .@"error",
                .rule = RuleId.mzml_cv_accession,
                .location = .{ .byte_offset = start.byte_offset },
                .path = validator.path,
                .message = msg,
            });
        }
    }

    pub fn consumeEnd(_: *SemanticValidator, _: xml_events.EndElement, _: usize) void {}

    pub fn finish(_: *SemanticValidator) void {}
};

fn attributeValue(attributes: []const Attribute, name: []const u8) ?[]const u8 {
    for (attributes) |a| {
        if (a.name.matches(null, name)) return a.value;
    }
    return null;
}

// --- Unit tests ---

const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;

fn makeCvParam(accession: []const u8, cv_ref: []const u8, byte_offset: u64) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
            .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
        },
        .self_closing = false,
    };
}

fn makeUserParamNoAccession(byte_offset: u64) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "userParam", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "name" }, .value = "some param" },
        },
        .self_closing = false,
    };
}

test "SemanticValidator: valid accession produces no diagnostic" {
    const allocator = testing.allocator;
    const obo_text =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: sample name\n" ++
        "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(makeCvParam("MS:1000001", "MS", 0), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: invalid accession produces error" {
    const allocator = testing.allocator;
    const obo_text =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: sample name\n" ++
        "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(makeCvParam("MS:9999999", "MS", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_accession, diagnostics.items[0].rule);
}

test "SemanticValidator: obsolete accession produces warning" {
    const allocator = testing.allocator;
    const obo_text =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: obsolete term\n" ++
        "namespace: MS\n" ++
        "is_obsolete: true\n" ++
        "replaced_by: MS:1000002\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(makeCvParam("MS:1000001", "MS", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_obsolete, diagnostics.items[0].rule);
    try expectEqualStrings("warning", diagnostics.items[0].severity.label());
}

test "SemanticValidator: mismatched cvRef/namespace produces error" {
    const allocator = testing.allocator;
    const obo_text =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: sample name\n" ++
        "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(makeCvParam("MS:1000001", "UO", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_namespace, diagnostics.items[0].rule);
}

test "SemanticValidator: userParam without accession is skipped" {
    const allocator = testing.allocator;
    const obo_text =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: sample name\n" ++
        "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(makeUserParamNoAccession(0), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}
