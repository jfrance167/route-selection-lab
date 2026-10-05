# Research evidence — October 5, 2026

Recommendation: original bounded standard-library installed-route lookup teaching model in PLAN.md. Targeted search, not exhaustive; no candidate security-certification claim. No project code or third-party execution.

## Reuse and overlap

Read coordinator SUCCESSORS.md 01:25 assignment, existing `7.2.8-packet-tracer-verify-ipv4-and-ipv6-addressing/README.md`, and vault `02 Research/IP Address Network and Interface Semantics.md`. Packet Tracer records actual activity observations; do not transplant its topology/interface data into this fictional lab. Vault note already distinguishes strict network declarations, host/interface meaning and mathematical membership from reachability. Targeted local README/vault searches for longest-prefix, route-selection, ECMP and administrative-distance returned no matching completed lookup lab. Search limitations apply; no exhaustive duplication claim.

The completed DNS lab provides a reviewed bounded parser design and boundary-test patterns. Reuse those ideas/appropriate minimal helpers only after adapting/retesting for this different schema; do not mutate the DNS project or import its cache semantics as route logic. Existing unittest/script entry points remain useful verification mechanisms.

## Connected GitHub and candidates

Connected GitHub tools became available during this stage. Used repository search `Python longest prefix match`, candidate file fetches, commit and issue searches. Results included small longest-prefix exercise repos and a networking toolkit; names/stars alone were not evidence of fit. Evaluated stronger known prefix-index candidates and the standard-library primitive instead.

### Recommended primitive: CPython ipaddress

[Official Python 3.13 documentation](https://docs.python.org/3.13/library/ipaddress.html), [v3.13.7 source](https://github.com/python/cpython/blob/v3.13.7/Lib/ipaddress.py), [tests](https://github.com/python/cpython/blob/v3.13.7/Lib/test/test_ipaddress.py), [license](https://github.com/python/cpython/blob/v3.13.7/LICENSE). Inspected source lines 700–770: network containment rejects differing versions and uses a bit-mask comparison. Source blob `67e45450fc1c9f672d5d5635d50bb4b389bd8075`. Test lines 1800–1860 demonstrate interface/prefix/collapse coverage; blob `e69e12495ad5c1df3a7adbdfbd3917c8a66501a5`. This test excerpt is not a complete upstream test review or an executed suite.

`ip_network(strict=True)` rejects host bits; address/interface/network meanings differ. Proposed code adds its own narrow syntax/fictional-data constraints, rather than accepting every library input. Documentation currently renders a later 3.13 patch than the installed 3.13.7 runtime; implementation must record the actual runtime and test behavior. Bundled standard-library module needs no separately installed package/native build. Python's PSF licensing permits use/distribution subject to notices where applicable; no source copying proposed. No upstream CI execution or blanket assurance inferred from CPython maintenance.

### Pytricia

[Repository](https://github.com/jsommers/pytricia), latest commit returned by commit search `eacae4c67784ca85e2ef995a7a63be60da66c61e`, September 15, 2025, version bump 1.3. README describes a Patricia prefix index and warns that mixing families in one trie can match unrelated IPv4/IPv6 values. Actual [pytricia.c](https://github.com/jsommers/pytricia/blob/master/pytricia.c) subscript path normalizes a key then invokes `patricia_search_best`; source blob `a86bd3a40dbf1b3d5494b5f6f0fbe9654d28f416`. It is an index, not vendor route-selection logic.

[test.py](https://github.com/jsommers/pytricia/blob/master/test.py) inspected: invalid-prefix and nested-prefix lookup assertions; blob `71ae3959562b8fd3e5f4a759df9059f39f7fa875`. [setup.py](https://github.com/jsommers/pytricia/blob/master/setup.py) builds C extensions from pytricia.c/patricia.c via setuptools. [.travis.yml](https://github.com/jsommers/pytricia/blob/master/.travis.yml) lists Python 2.7/3.6 tests; this is old configuration, not proof of currently passing CI. README labels beta testing on old platforms and as-time-permits development. Recent-enough commit evidence does not guarantee maintenance quality or abandonment.

Source/README specify LGPL 3 or later, with underlying code provenance; copying/linking/distribution would require a full applicable notice/source-obligation review. No adoption proposed. Issue searches returned [IPv6 small-address errors #34](https://github.com/jsommers/pytricia/issues/34) and [mixed-family insertion #36](https://github.com/jsommers/pytricia/issues/36); returned status/date fields were absent, so current fix status is unverified. No issue reproduction, install, benchmark or security audit. No Scorecard obtained. Later full patricia.c/test reads returned no usable structured excerpt; do not claim additional algorithm inspection.

### py-radix comparison

[Repository](https://github.com/mjschultz/py-radix) documents radix-based IPv4/IPv6 best matches; [LICENSE](https://github.com/mjschultz/py-radix/blob/main/LICENSE) actually inspected, blob `9b55be4b9bfbee2d595b7c935374c333151175d2`: ISC-style Python bindings plus underlying four-clause BSD advertising/non-endorsement requirements. Do not describe the entire project as unqualified ISC. Commit search returned `b5e4e93031475fdaf2360bceb8bc2390bb56d0c7`, December 4, 2025, free-threaded Python support. Tests/workflows are visible in the repository listing; actual current run results and deep C implementation review were not obtained. Not selected: disproportionate native index/library scope and no learning-report policy.

## Primary protocol sources

- [RFC 1812 §5.2.4.3](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.4.3): basic/longest-match, metric comparisons within routing domains and vendor policy. This is historical IPv4 router requirements, not a full modern dual-stack implementation contract.
- [RFC 4632 §5.1](https://www.rfc-editor.org/rfc/rfc4632.html#section-5.1): longest-match forwarding. [Errata](https://errata.rfc-editor.org/search/?rfc_number=4632) includes verified corrections to examples/history/filter text. Proposed independent fictional examples avoid copying those erroneous diagrams. RFC1812 info/errata reads failed; no absence-of-errata claim.
- [Cisco route-selection explanation](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/8651-21.html): distinguish installing routes using preference/metrics from forwarding among installed prefix lengths. IOS-specific example, not universal administrative-distance semantics.
- [RFC 2991](https://www.rfc-editor.org/rfc/rfc2991.html): equal-cost paths need a packet/flow next-hop selection mechanism. Do not pretend an id-sort/input-order choice simulates ECMP.
- [RFC 4291 §2.3](https://www.rfc-editor.org/rfc/rfc4291.html#section-2.3): IPv6 prefix lengths describe leading contiguous bits. Proposed family-separated math is a limited model, not complete IPv6 forwarding behavior.

## Local-first/free-only drafting

One bounded Ollama qwen3.5:2b test-idea attempt: 7362 ms, 300 reported output tokens, truncated. Draft also chose /24 over /25 and invented first-match tie behavior. Rejected; raw output/metadata retained in research/.

Explicitly selected configured OpenRouter profile for the same public/synthetic brief after consulting omniroute-delegate and routing guidance. Prior shared readiness degraded due to unavailable catalog; refreshed read-only readiness into this project. At 2026-10-05T05:32:55Z guardrails passed, including logging/usage/cloud restrictions, exact allowlists and live zero pricing. Readiness is not inference success or quota proof. One 450-token/60-second request returned no text draft; stopped without retry, model switch or paid fallback. Failure recorded separately. No private/device data supplied. Provider upstream logging is not disabled by gateway settings.

Codex retained source verification, scope/security judgment and corrected plan drafting. This consumes allowance; no measured savings claim.
