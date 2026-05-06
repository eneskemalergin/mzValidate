# XML Fixture Sources

This tree intentionally vendors a hand-picked XML fixture slice instead of a full upstream corpus.

Canonical upstream for future expansion:

- W3C XML Conformance Test Suites: <https://www.w3.org/XML/Test/>

Selection rules for this repo:

- Prefer no-DTD well-formedness cases that match the current Phase 1 parser surface.
- Keep fixtures small enough to review directly.
- Add one fixture per behavior we actually want to lock down.

Curated sourced fixtures added in this pass:

- `valid/xml10-declaration-basic.xml`
  Source: W3C XML 1.0 Fifth Edition examples.
  Purpose: basic XML 1.0 declaration and element parsing.
- `valid/xml11-declaration-basic.xml`
  Source: W3C XML 1.1 Second Edition examples.
  Purpose: basic XML 1.1 declaration with PI skipping and CDATA text emission.
- `invalid/xml11-unclosed-declaration.xml`
  Source: W3C XML declaration shape, reduced to an adversarial malformed case.
  Purpose: lock down EOF handling for an unterminated declaration.
- `corpus/w3c-versioned-prolog.xml`
  Source: W3C conformance-suite style prolog coverage.
  Purpose: exercise XML declaration, comment, PI, namespace, and child event flow together.
- `corpus/libxml2-namespace-rebind.xml`
  Source: libxml2 regression-style namespace rebinding coverage.
  Purpose: exercise nested default namespaces plus prefix rebinding on elements and attributes.

Adversarial invalid fixtures added in this pass:

- `invalid/namespace-empty-prefix-declaration.xml`
  Source: namespace declaration syntax reduced to a misuse case.
  Purpose: reject an empty namespace prefix declaration name like `xmlns:`.
- `invalid/malformed-processing-instruction.xml`
  Source: XML processing instruction shape reduced to an unterminated case.
  Purpose: reject processing instructions that never terminate with `?>`.
