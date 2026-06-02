<!-- markdownlint-disable MD033 MD036 MD041 -->

<h1 align="center">mzValidate</h1>

<p align="center">
  Validates mzML files. No runtime required. Single binary, no dependencies.
</p>

<p align="center">
  <a href="https://github.com/eneskemalergin/mzValidate/actions/workflows/ci.yml">
    <img src="https://github.com/eneskemalergin/mzValidate/actions/workflows/ci.yml/badge.svg?style=flat-square" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/status-development-green?style=flat-square" alt="status: development">
  <br/>
  <img src="https://img.shields.io/badge/mzML-validated-4B9D6E?style=flat-square" alt="mzML validated">
</p>

---

## Format support

What works today and what is coming. Each format is validated against its published specification.

| Format                    | Status    | Structural | Binary  |  Index  | Semantic |
| ------------------------- | --------- | :--------: | :-----: | :-----: | :------: |
| **mzML** 1.1.0            | ready     |   ready    |  ready  |  ready  |  ready   |
| **imzML** 1.0             | planned   |  planned   | planned |    -    | planned  |
| **SDRF-Proteomics** 1.1.0 | planned   |  planned   |    -    |    -    | planned  |
| **mzIdentML** 1.2         | planned   |  planned   |    -    | planned | planned  |
| **mzTab** 1.0             | planned   |  planned   |    -    |    -    | planned  |

No XML schema is embedded or required. All validation is driven by format-aware rules compiled into the binary.

---

- No JVM, no Python, no .NET, no libxml2.
- Streaming XML parser in a single forward pass, no DOM, bounded memory.
- Structural validation: element nesting, required attributes, list counts, child-element presence.
- Binary integrity: base64 decoding, zlib decompression, `defaultArrayLength` cross-check, precision validation.
- Uncompressed arrays validated by counting base64 characters incrementally, no materialization.
- Zlib arrays validated through streaming inflate, no allocation of decompressed output.
- Tested against known-good and known-bad fixtures, adversarial edge cases, and fuzz targets.

## Requirements

Zig **0.16.0** or later to build from source.

## Installation

### From source

```sh
git clone https://github.com/eneskemalergin/mzValidate.git
cd mzValidate
zig build -Doptimize=ReleaseFast
```

The binary is placed at `zig-out/bin/mzValidate`.

## Quick start

```sh
mzValidate check sample.mzML
mzValidate check sample.mzML -summary
mzValidate check sample.mzML -brief
mzValidate check sample.mzML -json > report.json
mzValidate check sample.mzML -skip-binary
mzValidate check -summary file1.mzML file2.mzML
```

```sh
# Summary output
# -> status=clean info=0 warnings=0 errors=0
```

## CLI reference

| Argument           | Description                     |
| ------------------ | ------------------------------- |
| `check <paths...>` | Validate one or more mzML files |

| Flag                 | Description                                                   |
| -------------------- | ------------------------------------------------------------- |
| *(default)*          | Human-readable text, one line per diagnostic                  |
| `-summary`           | Single-line status                                            |
| `-brief`             | Grouped by rule with occurrence counts                        |
| `-json`              | Stable JSON array of all diagnostics                          |
| `-skip-binary`       | Skip binary payload validation                                |
| `-skip-index`        | Skip index validation                                         |
| `-skip-semantic`     | Skip CV term and semantic validation                          |
| `-mmap`              | Memory-map input for random-access SHA-1                      |
| `-max-binary-size N` | Reject binary arrays with encodedLength > N (suffix: K/M/G/T) |
| `-obo <path>`        | Override embedded psi-ms.obo with a custom file               |
| `-version`           | Print version number and exit                                 |

Exit codes: `0` = clean, `1` = warnings only, `2` = errors present.

## Validation

Every file is checked in a single streaming pass. Same parser, same diagnostic list.

### Structural

XML well-formedness and mzML schema conformance. Catches missing elements, wrong nesting, invalid attributes, list count mismatches. Namespace-aware. No XSD required.

### Binary integrity

mzML stores spectral data as base64-encoded, optionally compressed arrays. Each array is checked: byte count against `defaultArrayLength`, precision (32 or 64 bit) against the declared CV term.

Supported compression: `MS:1000576` (none) and `MS:1000574` (zlib). Uncompressed arrays are validated by counting base64 characters incrementally without decoding the payload. Zlib arrays stream through `std.compress.flate` with no inflated buffer allocation.

Other compression schemes (MS-Numpress, truncation-based) are recognised and reported as unsupported (`mzml.binary.compression`) rather than passing silently.

### Index and checksum

For indexed mzML files: validates every index offset against the actual byte position, recomputes the SHA-1 checksum, and detects truncated files. SHA-1 requires random access to the file (mmap or read into memory). When streaming without the file bytes available, index validation runs without checksum and truncation checks.

### Semantic

CV accession validation against the PSI-MS controlled vocabulary (psi-ms.obo 4.1.248), `*Ref` attribute resolution, unit term validation, contradiction checks, and required-term enforcement from the official `ms-mapping.xml` rules. Can be disabled with `-skip-semantic`.

- Every `<cvParam>` accession is resolved against the embedded OBO. Obsolete terms are flagged.
- Unit accessions are validated against the Unit Ontology. Unit names are checked against the canonical term.
- Mutually exclusive OR terms on the same element (centroid + profile, positive + negative) are flagged.
- MUST and SHOULD rules from `ms-mapping.xml` are enforced per element.
- All `*Ref` attributes are resolved against declared `id` values. Duplicate IDs are flagged.
- IM-MS and DIA CV terms are recognised without false positives.

### Rule reference

| Rule ID                          | Description                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------ |
| `mzml.structure.xml`             | Malformed XML or parser error                                                  |
| `mzml.structure.root`            | Missing or wrong root element                                                  |
| `mzml.structure.nesting`         | Invalid element nesting                                                        |
| `mzml.structure.attribute`       | Missing or invalid attribute                                                   |
| `mzml.structure.count`           | List count mismatch                                                            |
| `mzml.structure.missing-child`   | Required child element absent                                                  |
| `mzml.binary.base64`             | Invalid base64 encoding                                                        |
| `mzml.binary.decompress`         | Invalid zlib compressed data                                                   |
| `mzml.binary.compression`        | Conflicting, missing, or unsupported compression terms                         |
| `mzml.binary.precision-mismatch` | Declared precision does not match payload                                      |
| `mzml.binary.length-mismatch`    | Decoded array length does not match `defaultArrayLength`                       |
| `mzml.binary.oversized`          | Binary payload exceeds `-max-binary-size` limit                                |
| `mzml.index.offset-list`         | IndexListOffset mismatch or count mismatch                                     |
| `mzml.index.offset`              | Index offset does not match actual position or references non-existent element |
| `mzml.index.truncated`           | Index offset points past end of file                                           |
| `mzml.index.checksum`            | FileChecksum SHA-1 mismatch or invalid hex format                              |
| `mzml.cv.accession`              | Unrecognized CV accession                                                      |
| `mzml.cv.obsolete`               | CV term is obsolete                                                            |
| `mzml.cv.namespace`              | cvRef does not match term namespace or cvList                                  |
| `mzml.cv.unit`                   | Invalid unit accession or unitName mismatch                                    |
| `mzml.cv.required`               | Missing required CV term on element                                            |
| `mzml.cv.recommended`            | Missing recommended CV term (warning)                                          |
| `mzml.cv.contradiction`          | Mutually exclusive CV terms on same element                                    |
| `mzml.ref.unresolved`            | *Ref attribute does not resolve to any declared id                             |
| `mzml.ref.duplicate-id`          | Two or more elements share the same id                                         |
| `mzml.ref.missing`               | Required *Ref attribute is missing                                             |

## Architecture

### Streaming XML parser

No DOM, no full-file buffer. Events are read in a single forward pass over a `std.Io.Reader`. Memory use stays flat for structural, binary, and index checks regardless of file size. (Semantic validation accumulates ID tables, so memory grows with spectrum count.)

Hand-rolled in Zig. No libxml2, no expat, no dependency.

### Validation engine

Structural and binary validators share the same parser and diagnostic list. Events are dispatched to both in parallel during a single pass.

### Output modes

Four renderers from the same diagnostic model. Text for interactive use. JSON for pipeline consumption. Summary mode for quick pass/fail in scripts. Brief mode groups identical diagnostics by rule and shows occurrence counts; useful for spotting patterns in files with thousands of findings.

## Testing

```sh
zig build test                # Unit tests with leak detection
zig build cli-contract        # Valid and invalid fixture checks
zig build fuzz-smoke          # Random and mutation-based fuzzing
zig build resource-check      # Peak RSS profiling
zig build throughput-baseline # Release-mode throughput metrics
zig build ci                 # test + cli-contract + fuzz-smoke + throughput-baseline
```

## Build steps

| Command                            | What it does           |
| ---------------------------------- | ---------------------- |
| `zig build`                        | Build debug binary     |
| `zig build -Doptimize=ReleaseFast` | Build release binary   |
| `zig build test`                   | Run all unit tests     |
| `zig build cli-contract`           | Run CLI contract tests |
| `zig build fuzz-smoke`             | Run fuzz targets       |
| `zig build resource-check`         | Profile peak RSS       |
| `zig build throughput-baseline`    | Benchmark throughput   |
| `zig build run -- check file.mzML` | Build and run          |

## Roadmap

- Performance: SIMD base64, parser profiling, large-file throughput
- Conformance score for CI integration (`mzValidate score`)
- Quick summary statistics (`mzValidate stats`)
- Auto-repair common mzML issues (`mzValidate check --fix`)
- Detect profile spectra and warn before search
- Compare two mzML files (`mzValidate diff`)
- CI integration, static binary releases, mzBridge/mzarc CI gates
- SDRF-Proteomics validation
- imzML cross-file validation
- mzIdentML validation
- mzTab validation
- Stable release, public API, documentation

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
