# XML Fixture Sources

This tree intentionally vendors a hand-picked XML fixture slice instead of a full upstream corpus.

These fixtures lock down the implemented parser contract. They are not evidence of exhaustive W3C XML conformance.

Canonical upstream for future expansion:

- W3C XML Conformance Test Suites: <https://www.w3.org/XML/Test/>

Selection rules for this repo:

- Prefer no-DTD well-formedness cases that match the current parser contract.
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

- `invalid/undeclared-prefix.xml`
  Source: W3C Namespaces `Prefix Declared` constraint reduced to an mzML root QName.
  Purpose: reject a prefixed mzML root with no in-scope binding.
- `invalid/duplicate-attribute.xml`
  Source: W3C Namespaces `Attributes Unique` constraint reduced to two prefixes bound to one namespace.
  Purpose: reject attributes with the same expanded name.
- `invalid/duplicate-namespace-declaration.xml`
  Source: W3C XML attribute uniqueness reduced to repeated declarations for one prefix.
  Purpose: reject two bindings for the same prefix on one element.
- `invalid/invalid-name-start.xml`
  Source: W3C XML `NameStartChar` production reduced to an ASCII boundary case.
  Purpose: reject an element name that starts with a digit.
- `invalid/invalid-attribute-value.xml`
  Source: W3C XML `AttValue` production reduced to a forbidden literal less-than sign.
  Purpose: reject `<` when it appears literally inside an attribute value.
- `invalid/invalid-character-reference.xml`
  Source: W3C XML `CharRef` legal-character constraint reduced to the NUL boundary.
  Purpose: reject a numeric reference to a character forbidden in every XML version.
- `invalid/forbidden-text-close.xml`
  Source: W3C XML `CharData` production reduced to its forbidden closing sequence.
  Purpose: reject `]]>` outside CDATA.

- `invalid/namespace-empty-prefix-declaration.xml`
  Source: namespace declaration syntax reduced to a misuse case.
  Purpose: reject an empty namespace prefix declaration name like `xmlns:`.
- `invalid/malformed-processing-instruction.xml`
  Source: XML processing instruction shape reduced to an unterminated case.
  Purpose: reject processing instructions that never terminate with `?>`.
- `invalid/external-entity.xml`
  Source: XML external entity declaration reduced to a no-access case.
  Purpose: reject external declarations before any entity could be fetched or expanded.
