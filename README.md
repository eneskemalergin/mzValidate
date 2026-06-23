<!-- markdownlint-disable MD033 MD036 MD041 -->

<h1 align="center">mzValidate</h1>

<p align="center">
  Validates mzML files in a single streaming pass. No JVM, no runtime, no setup.
</p>

<p align="center">
  <a href="https://github.com/eneskemalergin/mzValidate/actions/workflows/ci.yml">
    <img src="https://github.com/eneskemalergin/mzValidate/actions/workflows/ci.yml/badge.svg?style=flat-square" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/version-0.1.4-blue?style=flat-square" alt="version 0.1.4">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/status-development-green?style=flat-square" alt="status: development">
  <br/>
  <img src="https://img.shields.io/badge/mzML-validated-4B9D6E?style=flat-square" alt="mzML validated">
</p>

---

Validates mzML files in a single streaming pass. Structural conformance, binary integrity, index offsets, SHA-1 checksums, CV term semantics, and link validation. No XML tree in memory, no full-file buffer, no external dependencies. Single binary, no runtime required.

- No JVM, no Python, no .NET, no libxml2
- Streaming XML parser in one forward pass, predictable memory use
- Uncompressed arrays validated by counting base64 characters incrementally, without decoding the full payload
- Zlib arrays validated through streaming inflate, no output buffer needed
- Uses CPU vector instructions for faster base64 scanning
- 205 unit tests, CLI contract tests, adversarial edge cases, and randomly generated inputs

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

Build from source. Requires Zig 0.16.0 (bundled at `./zig-0.16.0/zig`).

```sh
git clone https://github.com/eneskemalergin/mzValidate.git
cd mzValidate
./zig-0.16.0/zig build -Doptimize=ReleaseFast
```

The binary is at `zig-out/bin/mzValidate`. The default build bundles a fast zlib library called libdeflate via `-lc` (links the system C runtime, available on every OS). Use `-Denable-libdeflate=false` for a standalone binary with zero system dependencies.

## CLI reference

```
mzValidate check [flags] <paths...>
```

Output modes (pick one). The default format prints one line per diagnostic with the byte offset and rule ID:

- `-summary`: single-line aggregate status (clean/warnings-only/errors-present with counts)
- `-brief`: groups identical diagnostics by rule with occurrence counts; useful for spotting patterns in files with thousands of findings
- `-json`: emits a stable JSON array of all diagnostics; designed for CI pipelines and programmatic consumption; keys are ordered and will not change between versions

Validation phases (each flag disables one phase). By default all phases run:

- `-skip-binary`: skip base64 decoding, zlib decompression, array length cross-checks, and precision validation
- `-skip-index`: skip index offset verification and SHA-1 checksum validation
- `-skip-semantic`: skip CV term resolution, contradiction detection, and reference resolution

I/O and limits:

- `-mmap`: memory-map the input file for random-access SHA-1 verification; without this flag the validator falls back to reading into a heap buffer when mmap is unavailable
- `-max-binary-size N`: reject any binary array larger than N; accepts K, M, G, T suffixes (1024-based)
- `-obo <path>`: override the embedded psi-ms.obo with a custom file; useful for testing against bleeding-edge CV terms

Informational:

- `-version`, `--version`: print the version number and exit

## Performance

Benchmarked on a 642 MB Fusion file (172k spectra, all zlib) with `tools/bench`. ReleaseFast build, 5 runs, 10-second warmup. Stages are additive from the Struct baseline.

| Stage                     | Wall time  | vs Struct | Throughput    |
| ------------------------- | ---------- | --------- | ------------- |
| Struct (XML + schema)     | 1.08 s     | baseline  | 592 MiB/s     |
| + Binary (base64 + zlib)  | 2.16 s     | +1.08 s   | 297 MiB/s     |
| + Index (offsets + SHA-1) | 2.24 s     | +1.15 s   | 287 MiB/s     |
| + Semantic (CV + refs)    | 1.91 s     | +0.82 s   | 337 MiB/s     |
| **Full** (all stages)     | **4.23 s** | -         | **152 MiB/s** |

RSS at full validation: 720 MiB (mostly the memory-mapped file at 642 MiB, plus the CV term table at ~9 MiB and per-spectrum ID tables).

## Format support

Each format validated against its published specification. No XSD embedded or required.

| Format                    | Status  | Structural | Binary  | Index   | Semantic |
| ------------------------- | ------- | ---------- | ------- | ------- | -------- |
| **mzML** 1.1.0            | ready   | ready      | ready   | ready   | ready    |
| **mzTab** 1.0             | planned | planned    | -       | -       | planned  |
| **SDRF-Proteomics** 1.1.0 | planned | planned    | -       | -       | planned  |
| **imzML** 1.0             | planned | planned    | planned | -       | planned  |
| **mzIdentML** 1.2         | planned | planned    | -       | planned | planned  |


## Validation

Every file is checked in a single streaming pass. Same parser, same diagnostic list.

### Structural

XML well-formedness and mzML 1.1 schema conformance. Catches missing elements, wrong nesting, invalid attributes, and list count mismatches. Namespace-aware. No XSD required.

### Binary integrity

Each `binaryDataArray` is checked for base64 validity, zlib integrity, length against `defaultArrayLength`, precision (32/64-bit) against the declared CV term, and duplicate array types within a `binaryDataArrayList`. Uncompressed arrays use a streaming base64 counter that avoids decoding the full payload. Zlib arrays use streaming inflate with no output buffer. Other compression schemes (MS-Numpress, truncation) are recognized and reported as unsupported rather than ignored.

### Index and checksum

For indexed mzML files: validates every index offset against the recorded byte position, recomputes SHA-1 without rescanning, and detects truncated data. SHA-1 requires random access (mmap or read into memory). When streaming from a pipe, index validation runs without checksum.

### Semantic

Every `cvParam` accession is checked against the embedded psi-ms.obo ontology (version 4.1.248). Unit terms are validated against the Unit Ontology. Mutually exclusive OR terms (centroid + profile, positive + negative) are flagged. Non-repeatable CV terms are checked for duplicates. MUST and SHOULD rules from the official PSI mapping file are enforced per element. All `*Ref` attributes are checked against declared `id` values. IM-MS and DIA CV terms are handled without false positives.

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
| `mzml.binary.length-mismatch`    | error    | Decoded length does not match `defaultArrayLength`                         |
| `mzml.binary.oversized`          | error    | Payload exceeds `-max-binary-size` limit                                   |
| `mzml.binary.type-mismatch`      | error    | Duplicate array type in one `binaryDataArrayList`                          |
| **Index**                        |          |                                                                            |
| `mzml.index.offset-list`         | error    | `indexListOffset` does not match actual offset                             |
| `mzml.index.offset`              | error    | Index offset does not match recorded position                              |
| `mzml.index.truncated`           | error    | Index offset points past end of file                                       |
| `mzml.index.checksum`            | error    | SHA-1 mismatch or invalid hex format                                       |
| **Semantic**                     |          |                                                                            |
| `mzml.cv.accession`              | error    | Unrecognized CV accession                                                  |
| `mzml.cv.obsolete`               | warning  | CV term is obsolete                                                        |
| `mzml.cv.namespace`              | error    | `cvRef` does not match term namespace                                      |
| `mzml.cv.unit`                   | error    | Unrecognized unit accession (info: unitName does not match canonical name) |
| `mzml.cv.required`               | error    | Missing required CV term                                                   |
| `mzml.cv.recommended`            | warning  | Missing recommended CV term                                                |
| `mzml.cv.contradiction`          | warning  | Mutually exclusive CV terms on same element                                |
| `mzml.cv.term-repeat`            | warning  | Non-repeatable CV term appears more than once                              |
| **References**                   |          |                                                                            |
| `mzml.ref.unresolved`            | error    | `*Ref` does not resolve to any declared `id`                               |
| `mzml.ref.duplicate-id`          | error    | Two or more elements share the same `id`                                   |
| `mzml.ref.missing`               | error    | Required `*Ref` attribute is missing                                       |

## Architecture

### Streaming XML parser

Hand-rolled in Zig. No external XML libraries. Reads from a stream or a memory-mapped byte slice and emits events into caller-provided storage. Comments and processing instructions are skipped. CDATA surfaces as text. Built-in entities and numeric character references are decoded. Namespace-aware with proper prefix cleanup on scope exit.

### Validation engine

Events are dispatched to four validators in one pass. Structural and binary validators run on every event. Index and semantic validators skip themselves for element types they do not need to inspect.

### Output modes

Four renderers from the same diagnostic list. Text mode for interactive use. JSON mode for pipeline consumption with stable key ordering. Summary mode for quick pass/fail. Brief mode groups identical diagnostics by rule with occurrence counts.

### Memory model

- Parser scratch space is fixed-size and lives on the call stack
- Text token buffer is 1 MiB, reused across all events
- Binary scratch buffers are cleared between arrays without reallocating
- No per-spectrum accumulation: state is discarded after each element's end event
- Semantic ID table grows with spectrum count (the only unbounded piece)

## Build steps

- `zig build`: build debug binary
- `zig build -Doptimize=ReleaseFast`: build release binary
- `zig build test`: run all unit tests with leak detection
- `zig build cli-contract`: run tests that verify the CLI produces correct output and exit codes on known fixtures
- `zig build ci`: test + cli-contract
- `zig build run -- check file.mzML`: build and run

## Roadmap

- Conformance score for CI integration (`mzValidate score`)
- Quick summary statistics (`mzValidate stats`)
- Auto-repair common mzML issues (`mzValidate check --fix`)
- Profile spectrum detection and centroid requirement warning
- Compare two mzML files (`mzValidate diff`)
- imzML, mzIdentML, mzTab, SDRF-Proteomics validation
- Stable release and public API

## Ecosystem

[mzBridge](https://github.com/eneskemalergin/mzbridge) writes mzML from Thermo .raw files. [mzarc](https://github.com/eneskemalergin/mzarc) encodes mzML into a compressed archive. Both run mzValidate in CI to gate on corruption before it propagates.

mzValidate validates mzML from any source: ThermoRawFileParser, msconvert, mzdata-converter, mzBridge. It is format-focused, not tool-focused.

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
