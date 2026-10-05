# Security model

Authorized scope: offline fictional installed-route teaching model. No live route collection, packet traffic, router configuration, host/interface/VM changes, publication or merge. No actual devices, identities or employer/client data belong in fixtures.

The public API accepts exact bounded bytes. Raw input bytes and nesting are bounded before decoding JSON objects; duplicate keys, overlong numeric tokens, floats/constants and unsafe/overlong strings are rejected. The complete common schema is validated even for recognized unsupported contexts. Route count, queries, family/data ranges, canonical duplicates and group consistency are bounded and checked. Output is escaped JSON with a final budget, assembled before delivery.

One path does not become two because its ID or ECMP label changes. A declared group is a fixture assertion, not proof of protocol cost or hardware behavior. The model does not verify route advertisements, route authenticity, interface readiness, next-hop recursion, actual flow selection or permission to transmit. No-model-route is not real unreachability.

Application performs no networking, external command execution, address enumeration or operating-system configuration. Tests launch only the fixed owned CLI with fictional fixtures; two fixed-command calls and the subprocess import have narrow explained Bandit exceptions. No shell or third-party programs.

Semantic validation failures produce no partial report. Physical stdout delivery can be partial; short/failed writes return an error. When a pipe fails, the CLI disables further shutdown flushing to preserve error exit 2 rather than CPython's flush-failure exit 120. It does not repair or reopen the receiving pipe. Caller shell redirection has its own overwrite behavior.

Bug reports should use a minimal fictional reproducer and expected/actual model labels. Do not send real routing tables, private identifiers, credentials or captures. No external disclosure workflow is configured.
