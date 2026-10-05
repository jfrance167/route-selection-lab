# Route Selection Lab

An offline tool that explains longest-prefix lookup among fictional installed route entries. It preserves equal-best ambiguity, reports declared ECMP candidates, and separates mathematical lookup from actual route installation, reachability and firewall permission.

## Run

Python 3.11+; no packages required. From this directory:

```powershell
python route_lab.py examples/lookup.json
python route_lab.py examples/ambiguous.json
python route_lab.py examples/ecmp.json
python route_lab.py examples/unsupported.json
python -m unittest discover -s tests -v
python -O -m unittest discover -s tests -v
```

All output is escaped JSON on stdout. Exit 0 means a supported analysis, including ambiguity, discard and no-model-route results. Exit 3 means a recognized policy context is outside this model after complete input validation. Exit 2 means invalid input/arguments or an I/O/short-write error. Errors go to stderr without echoing input data or paths. See [SCHEMA.md](SCHEMA.md) for exact fields, limits and examples.

The CLI reads at most 65536 bytes, validates and serializes the complete report before writing. It has no output-file option. Shell redirection can truncate a destination before the CLI starts; physical output delivery is not transactional.

## Demo results

The lookup fixture has an IPv4 default, /24, /25 and a host /32 discard:

| Fictional destination | Surviving entry | Decision |
|---|---|---|
| 192.0.2.20 | host /32 | selected_discard |
| 192.0.2.127 | r25 /25 | selected_forward |
| 192.0.2.128 | r24 /24 | selected_forward |
| 198.51.100.20 | default4 /0 | selected_forward |
| 2001:db8::1 | none | no_model_route |

The ambiguous fixture retains two /24 paths. The ECMP fixture declares a group on both, so it reports `declared_ecmp_candidates`; neither fixture identifies a packet's actual next hop. Every result has `actual_flow_path: unknown`.

Reports preserve original spellings and canonical IP/prefix values, sorted route IDs, longest-prefix length and a trace showing why each route matched, lost to a longer prefix, differed in family or did not contain the destination. Sorting controls report order, never selects a tie winner. A more-specific discard does not fall back to a shorter forward route.

## Reusable API and architecture

`route_lab.analyze(data: bytes) -> dict` accepts exact built-in bytes containing the same bounded UTF-8 schema as the CLI. It validates output size before returning a JSON-compatible report; invalid input/output budget raises `LabError`. Recognized unsupported contexts return a report with an empty results list. No custom object/generator coercion occurs.

Bounded JSON loader → strict normalizer/canonical-path/group validation → pure family-separated linear lookup → bounded escaped JSON. At most 64 routes and 16 queries; no address enumeration. The bounded parser design reuses the completed local DNS lab's reviewed approach, adapted and retested for this contract.

## Security and limitations

Fictional documentation addresses and opaque lab labels only; no real route/device data. No network packets, socket resolution, OS routing APIs, host/interface/VM changes or subprocesses in application. [SECURITY.md](SECURITY.md) documents input/knowledge boundaries.

Entries are fixture assertions about installed routes. This does not simulate choosing among protocol candidates, administrative distance, unrelated metric scales, policy routing, recursive next-hop resolution, source/traffic-class selection or flow hashing. A known unsupported context produces `unsupported_policy`; unknown/malformed representations are errors. This is a restricted teaching model, not a complete router implementation, actual forwarding observation or authorization tool.

Verified locally on Windows CPython 3.13.7: 21 normal/optimized tests, bounded independent bit-mask checks, four demos, compileall, zero Bandit findings and two detected/restored semantic mutations. ECC self-review found and fixed a closed-pipe shutdown exit bug. [Evidence and limits](verification/REPORT.md). Linux/other runtimes/hosted CI were not run; no independent audit. Original scanner live Linux SYN testing remains pending and unaffected.

## License and learning

Original code under [MIT](LICENSE). Candidate/protocol sources and licensing review are in [RESEARCH.md](RESEARCH.md); no upstream trie/RFC code copied. Adapted local DNS parser portions are also original MIT code. Codex implemented and self-reviewed this tool; Ollama's incorrect/truncated draft and one empty free OpenRouter draft were rejected. No measured allowance-saving claim.

See [LEARNING.md](LEARNING.md) and [DECISIONS.md](DECISIONS.md). Optional exercise: remove the host discard from a copy of the lookup fixture, predict the .20 result, then replay it.

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
