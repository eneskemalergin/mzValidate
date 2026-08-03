<!-- markdownlint-disable MD033 MD036 MD041 -->

<p align="center">
  <img src="assets/logo-readme.svg" alt="mzValidate" width="180">
</p>

<p align="center">
  Validates mzML files with one primary streaming parser pass. No JVM or managed runtime.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.8-blue?style=flat-square" alt="version 0.1.8">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/status-development-green?style=flat-square" alt="status: development">
  <br/>
  <img src="https://img.shields.io/badge/mzML-validated-4B9D6E?style=flat-square" alt="mzML validated">
</p>

---

I built mzValidate as a focused native validator for mzML. It checks XML syntax, mzML structure, binary integrity, index metadata, CV semantics, and references without building an XML tree or DOM. Most work happens in one primary pass over streaming XML events; indexed regular files can require bounded positional reads for offsets and a declared SHA-1 checksum. The default native build embeds libdeflate and links the host C runtime; use `-Denable-libdeflate=false` when you do not want that dependency.

- No JVM, no Python, no .NET, no libxml2
- Streaming XML parser in one primary forward pass
- Regular files use bounded stream input with file-stability checks around validation.
- Uncompressed arrays validated by counting base64 characters incrementally, without decoding the full payload
- Zlib arrays validated through bounded compressed and decompressed workspaces
- Uses CPU vector instructions for faster base64 scanning
- Unit tests, CLI contract fixtures, and focused adversarial boundary cases

## Quick start

```sh
mzValidate check sample.mzML
mzValidate check sample.mzML -summary
mzValidate check sample.mzML -brief
mzValidate check sample.mzML -json > report.json
mzValidate check -summary file1.mzML file2.mzML
```

Exit codes: `0` = clean, `1` = warnings only, `2` = errors present.

## Installation

Build from source. You need **Zig 0.16.0** exactly. Other Zig versions will not work.

1. Get Zig 0.16.0 from the [Zig download page](https://ziglang.org/download/#release-0.16.0) for your OS and CPU.
2. Keep the portable runner at `./zig-0.16.0/zig` in the repository, or obtain the exact Zig 0.16.0 runner for your platform.
3. Check the version:

```sh
./zig-0.16.0/zig version
# 0.16.0
```

Then:

```sh
git clone https://github.com/eneskemalergin/mzValidate.git
cd mzValidate
./zig-0.16.0/zig build -Doptimize=ReleaseFast
```

The binary is at `zig-out/bin/mzValidate`. The default build bundles libdeflate and links the host C runtime. Use `-Denable-libdeflate=false` for a build with no system C dependency.

If you prefer not to install Zig globally, extract the archive somewhere and keep a local copy in the repo as `./zig-0.16.0/` (that path is gitignored). Then use `./zig-0.16.0/zig` instead of `zig`. This is how I work on Zig projects. It leaves a few compiler copies around, but I always know which version a project uses and can change it without touching the rest of my system.

**Linux x86_64 local-copy example:**

```sh
curl -LO https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
tar xf zig-x86_64-linux-0.16.0.tar.xz
mv zig-x86_64-linux-0.16.0 zig-0.16.0
rm zig-x86_64-linux-0.16.0.tar.xz
./zig-0.16.0/zig version
```

## Supported targets

mzValidate requires targets with 64-bit pointers. The build rejects 32-bit targets during configuration, before compiling Zig or vendored C sources.

The Debug build matrix I currently verify is:

- `x86_64-linux`: native build and runtime tests
- `x86_64-windows`: cross-build only
- `aarch64-linux`: cross-build only

Vendored libdeflate is enabled by default on every listed target and links that target's C runtime. `-Denable-libdeflate=false` is also supported on every listed target and removes the vendored C sources and C runtime link. Other 64-bit Zig targets may build, but they are not part of the verified matrix. Routine development runs native Debug tests only; run the cross-build smoke checks when target, pointer-width, or vendor integration changes.

Focused cross-build smoke commands:

```sh
./zig-0.16.0/zig build -Dtarget=x86_64-windows -Doptimize=Debug
./zig-0.16.0/zig build -Dtarget=aarch64-linux -Doptimize=Debug
```

Add `-Denable-libdeflate=false` to the relevant command when changing the fallback decompression build path.

## CLI reference

```bash
mzValidate check [flags] <paths...>
```

Output modes (pick one). The default format prints one line per diagnostic with the byte offset and rule ID:

- `-summary`: single-line aggregate status (clean/warnings-only/errors-present with counts)
- `-brief`: groups identical diagnostics by rule with occurrence counts; useful for spotting patterns in files with thousands of findings
- `-json`: emits the versioned result report described below; designed for CI pipelines and programmatic consumption

### JSON result contract

JSON schema version 1 records every file result in input order and one invocation summary. Clean files remain visible with an empty `diagnostics` array.

```json
{
  "schema_version": 1,
  "files": [
    {
      "path": "sample.mzML",
      "completion": "complete",
      "status": "clean",
      "totals": {"info": 0, "warnings": 0, "errors": 0},
      "diagnostics_truncated": false,
      "dropped_diagnostics": {"info": 0, "warnings": 0, "errors": 0},
      "first_failure": null,
      "diagnostics": []
    }
  ],
  "summary": {
    "completion": "complete",
    "status": "clean",
    "files": 1,
    "incomplete_files": 0,
    "totals": {"info": 0, "warnings": 0, "errors": 0},
    "diagnostics_truncated": false,
    "dropped_diagnostics": {"info": 0, "warnings": 0, "errors": 0},
    "first_failure": null
  }
}
```

`completion` is `complete` only when every enabled stage finishes. `status` is `clean`, `warnings-only`, or `errors-present`; an incomplete result is always `errors-present`. Severity totals count every finding, including details omitted after a retention limit. `diagnostics_truncated` and `dropped_diagnostics` report that omission explicitly. When detail is dropped, `diagnostics` ends with a `runtime.diagnostics-truncated` renderer notice; that notice is not an additional finding and is not added to the totals. `first_failure` is either `null` or an object containing `stage`, `reason`, `rule`, `message`, `path`, and `location`.

Rule IDs are the stable machine contract. Human-readable `message` text is separate and may improve without changing the rule ID. A JSON schema version changes only when consumers must handle an incompatible shape or meaning change.

### Library ownership contract

`CheckOptions` contains values except for `obo_path`. `InvocationContext.init` borrows that optional path only while it builds the catalog, then owns the parsed catalog until `deinit`. The allocator and `std.Io` handle must remain valid for the context lifetime. Path validation reads regular files through a bounded stream.

`InvocationContext.validateOne`, `checkSliceResult`, and `checkReaderResult` borrow their path, input slice, or reader for the call. A `DiagnosticSink` owns its retained record array, but each retained diagnostic string still borrows its original storage and must be rendered or cleared before that storage expires. `DiagnosticSink.append` counts every item and returns `true` only when it retained that item's detail. A sink configured with `retain_details = false` returns `false` without incrementing its dropped-detail totals. Parser events are shorter lived: their slices expire at the next `Parser.next()` call.

`FileResult` is a self-contained value. It does not reference parser buffers, file-local validation state, the semantic catalog, or diagnostic storage. Its `FirstFailure` owns bounded copies of the rule, message, and path; the accessor slices borrow the `FirstFailure` value itself. The fixed capacities are 64 bytes for a rule ID, 512 bytes for a message, and `std.Io.Dir.max_path_bytes` for a path. An overlong value is copied as a prefix ending in `...`, and `FirstFailure.metadataTruncated()` reports that condition.

The CLI is the reference caller. It creates one invocation context, validates explicit paths serially in input order, and releases each file's diagnostic sink and file-local state before starting the next path. One fixed `Summary` retains invocation totals, completion, truncation, and first-failure metadata. JSON file objects are written incrementally, and brief mode retains at most 256 borrowed rule and message groups until final rendering. Run independent mzValidate processes when an external scheduler needs parallel file validation; the built-in CLI does not schedule workers.

Validation phases (each flag disables one phase). By default all phases run:

- `-skip-binary`: skip base64 decoding, zlib decompression, array length cross-checks, and precision validation
- `-skip-index`: skip index offset verification and SHA-1 checksum validation
- `-skip-semantic`: skip CV term resolution, contradiction detection, and reference resolution

I/O and limits:

- `-max-binary-size N`: reject any binary array whose `encodedLength` exceeds N; accepts K, M, G, T suffixes (1024-based)
- `-obo <path>`: replace the embedded OBO catalog with a custom file; useful for testing a deliberate catalog snapshot

Informational:

- `-version`, `--version`: print the version number and exit

## Performance

I am not publishing a current throughput or RSS table yet. When I publish new numbers, I want them to come from matched ReleaseFast builds with the same fixtures, flags, cache state, and repeated-sample policy. Debug remains the routine development mode.

### Memory

Path validation reads through a bounded `std.Io.Reader` and performs file identity checks before validation plus a final stability check.

Large files and parallel validation still require capacity planning for semantic state, index maps, binary workspaces, diagnostics, and the bounded stream working set. Do not multiply single-file wall time by core count and assume a cohort will finish in that time.

## Current limitations

The stream path targets a bounded validator working set. Semantic state, index maps, and binary workspaces have independent limits that make validation incomplete when reached. Diagnostic retention limits omit excess detail while preserving totals, truncation metadata, and the first failure. File stability, checksum behavior, and owner-specific resource limits remain part of the validation contract.

## Format support

For now, mzML 1.1.0 is the only format I support. I want to add the other formats below later; they are roadmap entries, not partial implementations. The current mzML structural checks are implemented directly in Zig, so the validator does not need an XSD engine at runtime.

| Format                    | Status  | Structural | Binary  | Index   | Semantic |
| ------------------------- | ------- | ---------- | ------- | ------- | -------- |
| **mzML** 1.1.0            | active  | active     | active  | active  | active   |
| **mzTab** 1.0             | planned | planned    | -       | -       | planned  |
| **SDRF-Proteomics** 1.1.0 | planned | planned    | -       | -       | planned  |
| **imzML** 1.0             | planned | planned    | planned | -       | planned  |
| **mzIdentML** 1.2         | planned | planned    | -       | planned | planned  |

## Validation

Every file is checked in one primary forward pass over parser events. Indexed stream checksum verification may add a bounded positional pass. The regular-file source is bounded stream input.

### Structural

The XML parser enforces supported XML 1.0 and 1.1 syntax, legal names and characters, matching tags, namespace bindings, and unique expanded attribute names. It rejects DTD and external-entity declarations. The structural validator requires the mzML namespace, recognizes the mzML and indexed mzML element set, and checks implemented parent, child-order, cardinality, required-child, list-count, required-attribute, unqualified-attribute, and selected attribute-datatype rules.

This is not a general XSD engine and is not a claim of exhaustive mzML schema conformance. String and URI lexical spaces are not exhaustively validated, and foreign namespaced attributes are generally outside the mzML attribute contract.

### Binary integrity

Each `binaryDataArray` is checked for canonical base64, `encodedLength`, applicable decoded length against `defaultArrayLength`, declared 32-bit or 64-bit precision, and duplicate array types within a `binaryDataArrayList`. Zlib payloads are decompressed and checked for corrupt, truncated, or trailing compressed input. Uncompressed arrays use a streaming base64 counter that avoids materializing the full decoded payload. Zlib arrays use reusable compressed scratch and a bounded decoded workspace. Recognized unsupported compression schemes are reported rather than ignored.

### Index and checksum

For indexed mzML files, validation checks the index list count and position, spectrum and chromatogram index entries, duplicate indexed IDs, offset bounds, and offsets against positions recorded independently during parsing. A present `fileChecksum` is validated and recomputed. Regular-file stream validation uses bounded positional reads for checksum and whitespace-tolerant offset verification. A caller-provided reader with a declared checksum but no complete or seekable source returns an incomplete result instead of silently claiming that integrity work completed.

### Semantic

The embedded catalog contains PSI-MS 4.1.248 and Unit Ontology terms. For embedded terms, validation checks accession and `cvRef` prefixes, obsolete status, namespace, known datatypes for present values, and allowed units. BTO, GO, and PATO are accepted external prefixes, but their terms are not resolved because those ontologies are not embedded. The `cvRef` still has to match the accession prefix.

The embedded mapping rules (`mzML.xsd` model version 1.0.0) enforce their MUST and SHOULD term requirements, repeatability, and selected contradictions. Supported unqualified reference attributes are resolved against typed declarations with bounded forward-reference state. These checks include PSI-MS terms used by IM-MS and DIA data, but they do not establish that every external ontology term or every possible mzML semantic rule is covered.

### Rule reference

Category header rows align with the Validation sections above.

| Rule ID                          | Severity | Description                                                                |
| -------------------------------- | -------- | -------------------------------------------------------------------------- |
| **Structural**                   |          |                                                                            |
| `mzml.structure.xml`             | error    | Malformed XML or parser error                                              |
| `mzml.structure.root`            | error    | Missing or wrong root element                                              |
| `mzml.structure.nesting`         | error    | Invalid element nesting                                                    |
| `mzml.structure.attribute`       | error    | Missing or invalid attribute                                               |
| `mzml.structure.count`           | error    | List count mismatch                                                        |
| `mzml.structure.missing-child`   | error    | Required child element absent                                              |
| **Binary**                       |          |                                                                            |
| `mzml.binary.base64`             | error    | Invalid base64 encoding                                                    |
| `mzml.binary.decompress`         | error    | Invalid zlib compressed data                                               |
| `mzml.binary.compression`        | error    | Conflicting or unsupported compression terms                               |
| `mzml.binary.precision-mismatch` | error    | Declared precision does not match payload                                  |
| `mzml.binary.length-mismatch`    | error    | Encoded or decoded binary length does not match its declaration            |
| `mzml.binary.oversized`          | error    | Payload exceeds `-max-binary-size` limit                                   |
| `mzml.binary.type-mismatch`      | error    | Duplicate array type in one `binaryDataArrayList`                          |
| **Index**                        |          |                                                                            |
| `mzml.index.offset-list`         | error    | `indexListOffset` does not match actual offset                             |
| `mzml.index.offset`              | error    | Index offset does not match recorded position                              |
| `mzml.index.duplicate-id`        | error    | Indexed ID repeats within its spectrum or chromatogram kind                |
| `mzml.index.truncated`           | error    | Index offset points past end of file                                       |
| `mzml.index.checksum`            | error    | SHA-1 mismatch or invalid hex format                                       |
| **Semantic**                     |          |                                                                            |
| `mzml.cv.accession`              | error    | Unrecognized CV accession                                                  |
| `mzml.cv.obsolete`               | warning  | CV term is obsolete                                                        |
| `mzml.cv.namespace`              | error    | `cvRef` does not match term namespace                                      |
| `mzml.cv.name`                   | error    | Required CV term name is empty                                             |
| `mzml.cv.unit`                   | error    | Unrecognized unit accession (info: unitName does not match canonical name) |
| `mzml.cv.value`                  | error    | Present value does not match the CV term's declared datatype               |
| `mzml.cv.required`               | error    | Missing required CV term                                                   |
| `mzml.cv.recommended`            | warning  | Missing recommended CV term                                                |
| `mzml.cv.contradiction`          | warning  | Mutually exclusive CV terms on same element                                |
| `mzml.cv.term-repeat`            | warning  | Non-repeatable CV term appears more than once                              |
| **References**                   |          |                                                                            |
| `mzml.ref.unresolved`            | error    | Supported reference attribute does not resolve to a typed declaration      |
| `mzml.ref.duplicate-id`          | error    | Two or more elements share the same `id`                                   |
| `mzml.ref.missing`               | error    | Required `*Ref` attribute is missing                                       |

## Architecture

### Streaming XML parser

Hand-rolled in Zig. No external XML libraries. Reads from a stream or a caller-provided byte slice and emits events into caller-provided storage. Comments and processing instructions are skipped. CDATA surfaces as text. Built-in entities and numeric character references are decoded. Namespace-aware with proper prefix cleanup on scope exit.

### Validation engine

Events are dispatched to four validators in one pass. Structural and binary validators run on every event. Index and semantic validators skip themselves for element types they do not need to inspect.

### Output modes

Four renderers consume the same bounded result state. Text mode is for interactive use. JSON schema 1 carries file and invocation results for pipelines. Summary mode keeps only fixed counters. Brief mode groups identical diagnostics by rule with occurrence counts.

### Memory model

- Regular-file input uses a fixed 64 KiB stack buffer. Parser structural scratch is also fixed stack storage: 64 attributes, 32 namespace bindings, 2 KiB of namespace text, 128 element frames, and 4 KiB of element-name text.
- The parser token buffer is an eager 1 MiB heap allocation per active file, reused across all events and reported in `ResourceUsage`
- Compressed and libdeflate output buffers reuse capacities through 1 MiB; larger one-off capacities are freed after their binary array. The fixed 128 KiB flate workspace is reused.
- Binary scratch telemetry covers allocator-owned compressed, flate, and libdeflate output capacities. It excludes the opaque external libdeflate decompressor allocation because the library ABI does not report its size.
- Transient element, scope, and binary state is released or reused, while semantic declarations, unresolved references, parameter-group state, and index entries are retained across the file within owner-specific limits.
- Diagnostic details are retained within count and rendered-byte limits; totals and first-failure metadata remain available when detail retention is exhausted.
- Input files use bounded stream input, so input size does not become a file-sized validator allocation.

## Build steps

- `./zig-0.16.0/zig build`: routine Debug binary
- `./zig-0.16.0/zig build test`: routine Debug unit tests with leak detection
- `./zig-0.16.0/zig build cli-contract`: CLI output and exit-code tests on known fixtures
- `./zig-0.16.0/zig build ci`: combined `test` and `cli-contract` when both contracts are in scope
- `./zig-0.16.0/zig build run -- check file.mzML`: build and run
- `./zig-0.16.0/zig build -Doptimize=ReleaseSafe`: targeted safety-oriented release evidence
- `./zig-0.16.0/zig build -Doptimize=ReleaseFast`: stripped release build for deliberate throughput or RSS measurement

## Roadmap

These are the features I want to work toward:

- I want a [conformance score for CI integration](https://github.com/eneskemalergin/mzValidate/issues/7), so pipelines can set a useful quality threshold instead of parsing every diagnostic.
- I want [`--fix` for common mzML problems](https://github.com/eneskemalergin/mzValidate/issues/6), but only where a repair is predictable and does not hide damaged data.
- I want a [`--require-centroid` check](https://github.com/eneskemalergin/mzValidate/issues/5) for search workflows that cannot use profile spectra.
- I want [quick summary statistics](https://github.com/eneskemalergin/mzValidate/issues/4) without turning the validator into a full analysis package.
- I want a practical [mzML diff command](https://github.com/eneskemalergin/mzValidate/issues/3) for converter and pipeline testing.

Longer term, I want to support more proteomics formats and settle the public API before calling the project stable.

## Ecosystem

I built [mzBridge](https://github.com/eneskemalergin/mzbridge) to write mzML from Thermo `.raw` files, and [mzarc](https://github.com/eneskemalergin/mzarc) to pack mzML into a compressed archive. They are separate tools, and mzValidate does not depend on either one. I want this validator to work on mzML from any converter, including tools I do not control.

## References

- [mzML 1.1.0](https://www.psidev.info/mzml): PSI standard for mass spectrometry data
- [HUPO-PSI](https://www.psidev.info/): Proteomics Standards Initiative
- [PSI-MS CV](https://github.com/hupo-psi/psi-ms-cv): Controlled vocabulary, v4.1.248
- [ProteomeXchange](https://proteomecentral.proteomexchange.org/): Data repository consortium
- [mzML Java validator](https://github.com/HUPO-PSI/mzML/tree/master/validator): Existing semantic validator
- [OpenMS XMLValidator](https://openms.de/documentation/TOPP_XMLValidator.html): XSD schema validation

## License

MIT. See [LICENSE](LICENSE).

---

<p align="center"><em>
A stream of spectra,<br>
The parser reads what was written,<br>
A clean report returns.
</em></p>
