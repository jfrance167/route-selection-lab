# Decisions

- Linear standard-library containment at small fixed limits: no need for a native trie package, performance benchmark or upstream code copying. This meets the teaching requirements; package count alone is not a security verdict.
- Already-installed fictional entries: vendor preference/metrics are a separate installation problem. Known policy contexts are explicit unsupported reports; all common payload validation still happens first.
- Canonical path identity excludes ID/group: original IPv6 spellings remain provenance, canonical forms determine duplicates and family matching.
- Tie preservation: sorted IDs are reporting order. Explicit complete ECMP groups can report candidates, never a flow-selected next hop. Same-prefix discard/forward is ambiguous; a sole more-specific discard has no fallback.
- Exact-bytes API and stdout-only CLI: application has no custom coercion, output-file alias logic or system/device interfaces. Logical pre-output validation does not make physical stdout transactional.
- Output-error fix: verified Windows closed-pipe result was exit 120 because CPython retried flush at shutdown. After output failure, no further stdout flushing is attempted; regression checks verify exit 2 on both normal and -O runs.
- No standalone Git initialization/publication in this stage. Hosted CodeQL/CI, branch protections, dedicated history/secret scans and repository eligibility were not run/configured. Any authorized owned repository creation must apply Jake's GitHub security baseline.
