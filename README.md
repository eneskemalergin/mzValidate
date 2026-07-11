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

Validates mzML files in a single streaming pass. Structural conformance, binary integrity, index offsets, SHA-1 checksums, CV term semantics, and link validation. No XML tree in memory, no external dependencies at runtime. Single binary, no JVM or Python stack required.

- No JVM, no Python, no .NET, no libxml2
- Streaming XML parser in one forward pass
- Input is mmap'd today, so peak RSS tracks file size (see Performance). Next: stream by default, mmap when the file fits
- Uncompressed arrays validated by counting base64 characters incrementally, without decoding the full payload
- Zlib arrays validated through streaming inflate with bounded scratch buffers
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

Build from source. You need **Zig 0.16.0** exactly. Other Zig versions will not work.

1. Get Zig 0.16.0 from the [Zig download page](https://ziglang.org/download/#release-0.16.0) for your OS and CPU.
2. Put the `zig` binary on your `PATH` (or call it by full path).
3. Check the version:

```sh
zig version
# 0.16.0
```

Then:

```sh
git clone https://github.com/eneskemalergin/mzValidate.git
cd mzValidate
zig build -Doptimize=ReleaseFast
```

The binary is at `zig-out/bin/mzValidate`. The default build bundles libdeflate via `-lc` (system C runtime). Use `-Denable-libdeflate=false` for a standalone binary with no system C dependency.

If you prefer not to install Zig globally, extract the archive somewhere and keep a local copy in the repo as `./zig-0.16.0/` (that path is gitignored). Then use `./zig-0.16.0/zig` instead of `zig`. (This is how I work with Zig on my projects. Keeps many copies but at least I know which one I am using and I can change it easily.)

**Linux x86_64 local-copy example:**

```sh
curl -LO https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
tar xf zig-x86_64-linux-0.16.0.tar.xz
mv zig-x86_64-linux-0.16.0 zig-0.16.0
rm zig-x86_64-linux-0.16.0.tar.xz
./zig-0.16.0/zig version
```

## CLI reference

```bash
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

ReleaseFast build, one Linux host, warm page cache, July 2026. Two real files. Not release gates.

| File                   |    Size | Spectra | Full validation | Peak RSS |
| ---------------------- | ------: | ------: | --------------: | -------: |
| Fusion (indexed, zlib) | 642 MiB |    ~86k |           4.1 s | ~720 MiB |
| Astral (plain, zlib)   | 2.1 GiB |    ~44k |          10.3 s | ~2.2 GiB |

Fusion stage breakdown (separate runs on the same file):

| Stage                     | Wall time |
| ------------------------- | --------: |
| Structural (XML + schema) |     1.1 s |
| + Binary (base64 + zlib)  |     2.1 s |
| + Index (offsets + SHA-1) |     2.2 s |
| + Semantic (CV + refs)    |     1.8 s |
| **Full** (all stages)     | **4.1 s** |

On Fusion, most of the ~720 MiB RSS is the mmap'd file (~642 MiB). Validator state adds about 80 MiB. On Astral, full validation hits ~2.2 GiB RSS because the 2.1 GiB plain file stays resident. Binary work is most of the Astral runtime (~8 s of ~10 s).

### Memory

The default path mmap's the input, or reads the whole file into heap if mapping fails. The parser walks that slice. There is no bounded streaming mode yet.

One 2 GiB file is fine if the machine has the RAM. Many large files in parallel is a different story. Each process can hold most of its input resident, and Linux does not always reclaim those pages quickly under load. Do not multiply single-file wall time by core count and assume a cohort will finish in that time.

> Working toward: stream as the default input path, with mmap kept for files that fit in memory.

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
- Semantic ID table grows with spectrum count
- Input file is mmap'd or read whole today; stream-default with optional mmap is the next input work

## Build steps

- `zig build`: debug binary
- `zig build -Doptimize=ReleaseFast`: release binary
- `zig build test`: unit tests with leak detection
- `zig build cli-contract`: CLI output and exit-code tests on known fixtures
- `zig build ci`: test + cli-contract
- `zig build run -- check file.mzML`: build and run

## Roadmap

- Stream as default input; mmap when the file fits
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
