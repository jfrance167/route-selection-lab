# Route Selection Lab — research plan

Status: stages 2–4 approved in coordinator SUCCESSORS.md October 5 01:41 addendum under Jake's verified direct mandate. Addendum reviewed before code. SCHEMA.md freezes exits, empty inputs, canonical duplicate paths, groups and examples. Tier 3 learning/portfolio workflow, narrow offline scope.

## Problem, gap and success

Explain why an address matches several installed route prefixes but only the longest matches survive, and why an equal-best set cannot identify an actual packet path. Existing Packet Tracer work records observed addresses/routes/connectivity; this tool would explain fictional lookup decisions without accessing devices. The completed DNS simulator addresses a different cache/expiry question.

Success: an original Python standard-library CLI reads bounded fictional normalized JSON and produces deterministic escaped JSON identifying matched, shorter and surviving entries, with `selected_forward`, `selected_discard`, `ambiguous_equal_best`, `declared_ecmp_candidates`, `no_model_route` or `unsupported_policy`. No result asserts live reachability, firewall permission, route installation, next-hop usability or authorization to test.

## Scope and proposed input contract

- Destination-only lookup in one already-installed synthetic table. IPv4 and IPv6 handled independently. Routes are assertions made by the fixture, not discovered installation facts.
- Python 3.11+ using `ipaddress` and standard JSON/unittest. Linear scan at fixed small limits; no trie/native dependency. Original MIT code; RFC/research attribution and AI-assistance disclosure.
- Envelope: integer version 1; context enum; routes array; destinations array. Context `destination_only` supports lookup. Recognized contexts `source_policy`, `tos_policy`, `vendor_route_installation`, `recursive_next_hop`, `flow_hash` yield `unsupported_policy`, with no selected-path result. Still validate their common fictional payload before returning unsupported. Unknown contexts/keys are invalid input. No metrics, administrative distance, source addresses, policy rules or raw vendor output accepted.
- Route: unique ASCII id, numeric CIDR prefix, action `forward` or `discard`. Forward requires documentation-range next_hop of the same family and opaque fictional egress label. Discard forbids next_hop/egress. Optional ecmp_group for forward entries only. IDs/labels/group <=32 LDH-style ASCII characters. These labels are not actual interfaces.
- Non-default prefixes must be subnets of 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 or 2001:db8::/32. Defaults 0.0.0.0/0 and ::/0 allowed as mathematical fixtures. Destinations and next_hops restricted to those documentation blocks. No real device/network data or public lookup targets.
- CIDR uses decimal prefix length, no netmask notation, scope IDs, leading-zero ambiguity or IPv4-mapped IPv6. Use strict network parsing: host bits set are invalid, never silently masked. Normalize IPv6 spelling and preserve original alongside canonical input. Separate version comparisons before membership.
- <=64KiB UTF-8 input, nesting <=6, numeric tokens <=10 characters, strings <=128 characters, 64 routes, 16 queries, <=256KiB final JSON. Reject duplicate keys, floats/non-finite constants, bool-as-integer, controls/surrogates, unknown fields, canonical duplicate route actions/paths and duplicate destination values. Validate whole input and assemble bounded output before emitting anything. Physical stdout failures are not transactional.
- Only public entry point `analyze(bytes)` accepts exact built-in bytes and enforces the same limits as CLI. Internal functions receive normalized objects. No arbitrary object coercion/generator execution. CLI reads bounded bytes, stdout only, error text never echoes input paths or untrusted exceptions.

## Lookup and equal-best contract to freeze before code

Among same-family routes containing the destination, retain the largest prefix length. This is a restricted mathematical model of the basic/longest-match steps; [RFC 1812 §5.2.4.3](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.4.3) also describes metric and vendor policy steps not implemented here. [RFC 4632 §5.1](https://www.rfc-editor.org/rfc/rfc4632.html#section-5.1) supports longest-match forwarding; the model is not full router compliance.

One survivor: `selected_forward` or `selected_discard`, always qualified as a fixture/model action. Zero survivors: `no_model_route`, which does not establish real unreachability. Multiple survivors: never choose input order, smallest id, lowest unrelated metric or arbitrary next hop. Report their sorted ids and `ambiguous_equal_best`, unless all declare the same validated ECMP group.

An ECMP declaration requires >=2 distinct forward paths, one identical canonical prefix/family, one group label, no duplicate path. The group cannot span prefixes/families, include discard, or conflict with an ungrouped entry at that prefix. Reject contradictory declarations as invalid input. If all longest survivors are that declared group, report `declared_ecmp_candidates`, preserving all paths and `actual_flow_path: unknown`. The declaration is not proof of equal protocol cost or actual load sharing. [RFC 2991](https://www.rfc-editor.org/rfc/rfc2991.html) explains why ECMP needs a next-hop selection mechanism; no hashing or flow simulation is included.

Candidate route installation is a separate operation: vendor administrative preference and protocol metrics can affect what gets installed. [Cisco's route-selection documentation](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/8651-21.html) gives a concrete IOS example; its values/order are not made universal. This lab accepts already-installed assertions and does not compare metric scales across protocols.

## Worked expectations and verification strategy

Freeze the schema and exact examples before code:

| Fictional table/query | Expected model result |
|---|---|
| /24, /25, host /32 covering 192.0.2.20 | /32 selected |
| same table, 192.0.2.127 | /25 selected |
| same table, 192.0.2.128 | /24 selected |
| IPv6 destination, IPv4 default only | no_model_route |
| two distinct /24 paths, no declaration | ambiguous_equal_best |
| same paths, valid group declaration | declared_ecmp_candidates; flow path unknown |
| /25 discard and /24 forward, destination in /25 | selected_discard; no fallback invented |
| supported-looking table with source_policy context | unsupported_policy |

Tests: /0 and host /32,/128; each side of prefix boundary; mixed families; nested/disjoint prefixes; equal-best sets and input-order permutation; canonical duplicate IPv6 and duplicate paths; valid/contradictory ECMP groups; discard versus forward; default fallback only when no more-specific match; no route; all recognized unsupported contexts; host-bit/netmask/zone-id/leading-zero/mapped-address rejection; UTF-8/JSON depth/numbers/controls/keys/counts/output overflow; public API exact bytes and forbidden-capability mocks; CLI invalid/unsupported/supported exit behavior and no partial semantic output. Independent fixed expected cases and bit-mask containment oracle for bounded examples, not implementation-derived snapshots.

Run unittest normally and under -O, optimized CLI children, compileall, Bandit and ECC actual-source self-review. Focused mutations must reject shortest-prefix selection and arbitrary first tie winner, then restore and rerun affected final checks. Record hashes and runtime. Linux/other Python/hosted checks remain unverified unless actually executed. No device comparison is needed or claimed.

## Architecture, alternatives and threat model

Bounded JSON reader → strict normalizer → pure family-separated membership/longest-prefix classifier → bounded escaped JSON renderer. Sorting ids is reporting order, never a path-selection policy. Do not enumerate addresses in networks. No socket/network modules, OS route APIs, subprocesses, shell commands or system configuration in application.

Recommendation: build original bounded stdlib tool. Pytricia/py-radix supply fast prefix indexes but do not provide this explicit ambiguity/unsupported learning contract; native code/build/licensing is unnecessary at 64 routes. Standard-library choice meets requirements without extra installed dependencies; this is not a general fewer-dependencies-means-safe claim.

Alternate: subnet/address-scope interpretation lab separating address/network/interface, strict versus masked network derivation, prefix membership and special-address caveats. It has lower implementation complexity but more overlap with the existing vault/Packet Tracer material. A general scope classifier also needs versioned IANA/Python semantics and cannot infer routing from a label. Research supports route lookup as the stronger distinct gap; alternate is not implementation scope.

Assets: host configuration, local files/private network context, accurate learning conclusions. Boundary: untrusted normalized JSON. Risks: expensive parsing/output, ambiguous normalization/ECMP, terminal injection, accidental live route collection or overclaiming reachability. Mitigate with bounds, exact types, fictional data, escaped JSON, fail-before-output, no network/system capabilities and explicit conditional results. No authenticating route advertisements or protecting a production router.

## Stages and definitions of done

1. Coordinator approves exact plan/addendum; freeze schema, exits and equal-best examples before code. No implementation yet.
2. Build pure parser/normalizer/classifier and semantic/adversarial tests. Done when fixed expectations and parser/API bounds pass.
3. CLI plus fictional supported/ambiguous/ECMP/discard/unsupported demos. Done when deterministic complete outputs and normal/-O checks pass.
4. ECC review, repair/retest, SAST and mutation evidence; README/security/license/learning/state/decisions with honest runtime limits and relevant Obsidian milestone. No independent audit claim. Repository initialization/publication requires separately applicable authorization and Jake's security baseline.

No router/interface/VM edits, live packets, network enumeration, real device data, new chats/schedulers, publication or merge. Preserve DNS/scanner evidence and the Linux SYN gap. Stop new scope at October 6 08:00 America/New_York.
