<!-- markdownlint-disable MD033 MD036 MD041 -->

<h1 align="center">mzValidate</h1>

<p align="center">
  A fast, zero-dependency validator for open proteomics data formats.
  Written in Zig. Single static binary. Streaming single-pass validation.
</p>

<p align="center">
  <a href="https://github.com/eneskemalergin/mzValidate/actions/workflows/ci.yml">
    <img src="https://github.com/eneskemalergin/mzValidate/actions/workflows/ci.yml/badge.svg?style=flat-square" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/mzML-ready-4B9D6E?style=flat-square" alt="mzML ready">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/status-early_research-yellow?style=flat-square" alt="status: early research">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

## Format support

What works today and what is coming. Each format is validated against its published specification.

| Format | Status | Structural | Binary | Index | Semantic |
| ------ | ------ | :--------: | :----: | :---: | :------: |
| **mzML** 1.1.0 | ✅ | ✅ ready | ✅ ready | 🔲 planned | 🔲 planned |
| **imzML** 1.0 | 🔲 planned | 🔲 | 🔲 | - | 🔲 |
| **SDRF-Proteomics** 1.1.0 | 🔲 planned | 🔲 | - | - | 🔲 |
| **mzIdentML** 1.2 | 🔲 planned | 🔲 | - | 🔲 | 🔲 |
| **mzTab** 1.0 | 🔲 planned | 🔲 | - | - | 🔲 |

No XML schema is embedded or required. All validation is driven by format-aware rules compiled into the binary.

---

- No JVM, no Python, no .NET, no libxml2.
- Streaming XML parser in a single forward pass, no DOM, constant memory.
- Structural validation: element nesting, required attributes, list counts, child-element presence.
- Binary integrity: base64 decoding, zlib decompression, `defaultArrayLength` cross-check, precision validation.
- Uncompressed arrays validated by counting base64 characters incrementally, no materialization.
- Zlib arrays counted through streaming inflate, no allocation of decompressed output.
- Corpus-validated with known-good and known-bad fixtures, adversarial edge cases, and fuzz targets.

## Requirements

Zig **0.16.0** or later to build from source.

Pre-built static binaries for Linux x86_64, Linux aarch64, and macOS arm64. No runtime dependencies.

## Installation

### From source

```sh
git clone https://github.com/eneskemalergin/mzValidate.git
cd mzValidate
zig build -Doptimize=ReleaseFast
```

The binary is placed at `zig-out/bin/mzValidate`.

### Download a release

```sh
curl -L https://github.com/eneskemalergin/mzValidate/releases/download/v0.1.0/mzValidate-x86_64-linux.tar.gz | tar xz
./mzValidate check myfile.mzML
```

## Quick start

```sh
mzValidate check sample.mzML
mzValidate check sample.mzML -summary
mzValidate check sample.mzML -json > report.json
mzValidate check sample.mzML -skip-binary
mzValidate check -summary file1.mzML file2.mzML
```

```sh
# Summary output
# -> status=clean info=0 warnings=0 errors=0
```

## CLI reference

| Argument | Description |
| -------- | ----------- |
| `check <paths...>` | Validate one or more mzML files |

| Flag | Description |
| ---- | ----------- |
| *(default)* | Human-readable text, one line per diagnostic |
| `-summary` | Single-line status |
| `-json` | Stable JSON array of all diagnostics |
| `-skip-binary` | Skip binary payload validation |

Exit codes: `0` = clean, `1` = warnings only, `2` = errors present.

## Validation levels

Validation runs in a single streaming pass over the file. All levels share the same parser and diagnostic list.

### Level 1: Structural <img src="https://img.shields.io/badge/ready-4B9D6E?style=flat-square" alt="ready">

XML well-formedness and mzML schema conformance. Catches missing elements, wrong nesting, invalid attributes, list count mismatches. Namespace-aware. No XSD dependency.

### Level 2: Binary Integrity <img src="https://img.shields.io/badge/ready-4B9D6E?style=flat-square" alt="ready">

mzML stores spectral data as base64-encoded, optionally compressed arrays inside XML. Every array is validated: the byte count is checked against `defaultArrayLength`, and the encoded precision (32-bit or 64-bit float) is verified against the declared CV term.

**Supported compression:** `MS:1000576` (no compression) and `MS:1000574` (zlib). Uncompressed arrays are validated by counting base64 characters incrementally with no materialization. Zlib arrays are decoded and streamed through `std.compress.flate` with no allocation of the inflated buffer.

**Recognized but not yet implemented:** All remaining `is_a: MS:1000572` (binary data compression type) terms (MS-Numpress variants `MS:1002312`–`MS:1002314`, `MS:1002746`–`MS:1002748`, truncation-based schemes `MS:1003089`, `MS:1003090`) produce a diagnostic (`mzml.binary.compression`) signaling unsupported compression rather than being silently misvalidated.

### Level 3: Index & Checksum <img src="https://img.shields.io/badge/planned-8B8B8B?style=flat-square" alt="planned">

Index offset verification, SHA-1 checksum recomputation, truncation detection for indexed mzML.

### Level 4: Semantic <img src="https://img.shields.io/badge/planned-8B8B8B?style=flat-square" alt="planned">

CV accession validation against the PSI-MS controlled vocabulary, `*Ref` attribute resolution, unit term validation, contradictory term detection.

## Rule reference

| Rule ID | Description |
| ------- | ----------- |
| `mzml.structure.xml` | Malformed XML or parser error |
| `mzml.structure.root` | Missing or wrong root element |
| `mzml.structure.nesting` | Invalid element nesting |
| `mzml.structure.attribute` | Missing or invalid attribute |
| `mzml.structure.count` | List count mismatch |
| `mzml.structure.missing-child` | Required child element absent |
| `mzml.binary.base64` | Invalid base64 encoding |
| `mzml.binary.decompress` | Invalid zlib compressed data |
| `mzml.binary.compression` | Conflicting, missing, or unsupported compression terms (all 10 PSI-MS `is_a: MS:1000572` types are recognized; MS-Numpress and truncation schemes are diagnosed as unsupported) |
| `mzml.binary.precision-mismatch` | Declared precision does not match payload |
| `mzml.binary.length-mismatch` | Decoded array length does not match `defaultArrayLength` |

## Architecture

### Streaming XML parser

No DOM, no full-file buffer. Events are read in a single forward pass over a `std.Io.Reader`. Memory stays flat regardless of file size for Levels 1-3. A 50 GB mzML file validates in the same footprint as a 50 MB one.

Hand-rolled in Zig. No libxml2, no expat, no dependency.

### Validation engine

Checks register as independent rules. Each rule receives the XML event stream and emits zero or more diagnostics. The structural and binary validators share the same parser and diagnostic list, with events dispatched to both in parallel.

### Output modes

Three renderers from the same diagnostic model. Text for interactive use. JSON for pipeline consumption. Summary mode for quick pass/fail in scripts.

## Testing

```sh
zig build test               # 100+ unit tests, memory leak detection, fuzzing
zig build cli-contract       # Known-good and known-bad fixture checks
zig build fuzz-smoke         # Deterministic fuzz targets
zig build resource-check     # Peak RSS gate
zig build throughput-baseline # Release-mode throughput gate
zig build ci                 # All of the above
```

## Build steps

| Command | What it does |
| ------- | ------------ |
| `zig build` | Build debug binary |
| `zig build -Doptimize=ReleaseFast` | Build release binary |
| `zig build test` | Run all unit tests |
| `zig build cli-contract` | Run CLI contract tests |
| `zig build fuzz-smoke` | Run fuzz targets |
| `zig build resource-check` | Profile peak RSS |
| `zig build throughput-baseline` | Benchmark throughput |
| `zig build run -- check file.mzML` | Build and run |

## Roadmap

| Version | Feature | Status |
| ------- | ------- | ------ |
| **v0.1.0** | mzML structural + binary validation, streaming parser, three output modes, fuzz testing, CI gates | ✅ Released |
| **v0.2.0** | Index offset verification, SHA-1 checksum, truncation detection | 🔲 Planned |
| **v0.3.0** | Semantic validation: OBO parser, CV accession checks, ID resolution, contradiction detection | 🔲 Planned |
| **v0.4.0** | CI integration, static binary releases, mzBridge/mzarc CI gates | 🔲 Planned |
| **v0.5.0** | SDRF-Proteomics validation | 🔲 Planned |
| **v0.6.0** | imzML cross-file validation | 🔲 Planned |
| **v0.7.0** | mzIdentML validation | 🔲 Planned |
| **v0.8.0** | mzTab validation | 🔲 Planned |
| **v1.0.0** | Stable release, public API, documentation | 🔲 Planned |

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
