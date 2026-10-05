"""Offline fictional installed-route lookup; exact version-1 contract in SCHEMA.md."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys

MAX_INPUT = 65536
MAX_OUTPUT = 262144
CONTEXTS = {"destination_only", "source_policy", "tos_policy", "vendor_route_installation",
            "recursive_next_hop", "flow_hash"}
BLOCKS = tuple(ipaddress.ip_network(n) for n in
               ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


class LabError(ValueError):
    """Invalid/unsupported input representation or output delivery error."""


def _fields(value: object, required: set[str], optional=frozenset()) -> dict:
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - optional:
        raise LabError("invalid, unknown or missing object fields")
    return value


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise LabError("duplicate JSON key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > 10:
        raise LabError("numeric token exceeds 10 characters")
    return int(token)


def _noninteger(token: str) -> None:
    raise LabError("non-integer numbers/constants unsupported")


def _strings(value: object) -> None:
    if isinstance(value, str):
        if len(value) > 128 or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise LabError("string too long or contains controls/surrogates")
    elif isinstance(value, dict):
        for key, child in value.items():
            _strings(key)
            _strings(child)
    elif isinstance(value, list):
        for child in value:
            _strings(child)


def _load(data: bytes) -> dict:
    # Adapted from the completed local DNS lab's reviewed bounded JSON design.
    if type(data) is not bytes or len(data) > MAX_INPUT:
        raise LabError("input must be exact bytes within 65536 bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise LabError("input must be UTF-8") from exc
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 6:
                raise LabError("JSON nesting exceeds 6")
        elif char in "]}":
            depth -= 1
    try:
        result = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                            parse_float=_noninteger, parse_constant=_noninteger)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LabError("invalid JSON") from exc
    _strings(result)
    return result


def _label(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?", value):
        raise LabError("invalid fictional label")
    return value


def _address(value: object):
    if type(value) is not str or "%" in value:
        raise LabError("invalid address syntax")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise LabError("invalid address syntax") from exc
    if address.version == 6 and address.ipv4_mapped is not None:
        raise LabError("mapped IPv6 unsupported")
    if not any(address.version == block.version and address in block for block in BLOCKS):
        raise LabError("address outside documentation ranges")
    return address


def _prefix(value: object):
    if type(value) is not str or value.count("/") != 1 or "%" in value:
        raise LabError("invalid numeric CIDR syntax")
    _, prefix_text = value.split("/")
    if not re.fullmatch(r"0|[1-9][0-9]{0,2}", prefix_text):
        raise LabError("invalid numeric CIDR length")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise LabError("invalid network or host bits set") from exc
    if network.version == 6 and network.network_address.ipv4_mapped is not None:
        raise LabError("mapped IPv6 unsupported")
    if network.prefixlen != 0 and not any(
        network.version == block.version and network.subnet_of(block) for block in BLOCKS
    ):
        raise LabError("nondefault prefix outside documentation ranges")
    return network


def _route(raw: object) -> dict:
    if type(raw) is not dict or type(raw.get("action")) is not str or raw["action"] not in ("forward", "discard"):
        raise LabError("invalid route action")
    required = {"id", "prefix", "action"}
    if raw["action"] == "forward":
        required |= {"next_hop", "egress"}
    route = _fields(raw, required, {"ecmp_group"} if raw["action"] == "forward" else set())
    normalized = {"id": _label(route["id"]), "network": _prefix(route["prefix"]),
                  "action": route["action"], "original_prefix": route["prefix"]}
    if route["action"] == "forward":
        address = _address(route["next_hop"])
        if address.version != normalized["network"].version:
            raise LabError("next hop family differs from route")
        normalized.update(next_hop=str(address), original_next_hop=route["next_hop"],
                          egress=_label(route["egress"]))
        if "ecmp_group" in route:
            normalized["ecmp_group"] = _label(route["ecmp_group"])
    return normalized


def _validate(root: object) -> tuple[str, list[dict], list[dict]]:
    envelope = _fields(root, {"version", "context", "routes", "destinations"})
    if type(envelope["version"]) is not int or envelope["version"] != 1:
        raise LabError("version must be integer 1")
    context = envelope["context"]
    if type(context) is not str or context not in CONTEXTS:
        raise LabError("unknown context")
    for field, maximum in (("routes", 64), ("destinations", 16)):
        if type(envelope[field]) is not list or len(envelope[field]) > maximum:
            raise LabError("invalid array or too many entries")
    routes = [_route(raw) for raw in envelope["routes"]]
    ids, identities, groups, prefixes = set(), set(), {}, {}
    for route in routes:
        network = route["network"]
        identity = (network.version, str(network), route["action"], route.get("next_hop"), route.get("egress"))
        if route["id"] in ids or identity in identities:
            raise LabError("duplicate route ID or canonical path")
        ids.add(route["id"])
        identities.add(identity)
        prefixes.setdefault(str(network), []).append(route)
        if "ecmp_group" in route:
            groups.setdefault(route["ecmp_group"], []).append(route)
    for group, members in groups.items():
        prefix = str(members[0]["network"])
        if len(members) < 2 or any(str(member["network"]) != prefix for member in members):
            raise LabError("ECMP group needs multiple paths at one prefix")
        if any(member.get("ecmp_group") != group for member in prefixes[prefix]):
            raise LabError("incomplete or conflicting ECMP declaration")
    destinations, values = [], set()
    for value in envelope["destinations"]:
        address = _address(value)
        canonical = str(address)
        if canonical in values:
            raise LabError("canonical duplicate destination")
        values.add(canonical)
        destinations.append({"original": value, "canonical": canonical, "address": address})
    return context, sorted(routes, key=lambda route: route["id"]), destinations


def _lookup(routes: list[dict], destination: dict) -> dict:
    address = destination["address"]
    matched = [route for route in routes if route["network"].version == address.version and address in route["network"]]
    longest = max((route["network"].prefixlen for route in matched), default=-1)
    survivors = [route for route in matched if route["network"].prefixlen == longest]
    if not survivors:
        decision = "no_model_route"
    elif len(survivors) == 1:
        decision = "selected_" + survivors[0]["action"]
    elif all(route.get("ecmp_group") == survivors[0].get("ecmp_group") for route in survivors) and "ecmp_group" in survivors[0]:
        decision = "declared_ecmp_candidates"
    else:
        decision = "ambiguous_equal_best"
    trace = []
    for route in routes:
        network = route["network"]
        reason = ("different_family" if network.version != address.version else
                  "does_not_contain" if address not in network else
                  "longest_match" if network.prefixlen == longest else "shorter_match")
        trace.append({"id": route["id"], "reason": reason})
    explanations = {"no_model_route": "No installed fixture prefix matches; live reachability is unknown.",
                    "selected_forward": "One longest fixture path; next-hop usability and actual forwarding unknown.",
                    "selected_discard": "Longest fixture action discards; no shorter-prefix fallback inferred.",
                    "ambiguous_equal_best": "Several longest fixture paths; no tie policy or flow path inferred.",
                    "declared_ecmp_candidates": "Fixture declares equal paths; no packet/flow next hop selected."}
    return {"destination": destination["canonical"], "original_destination": destination["original"],
            "decision": decision, "longest_prefix_length": longest if longest >= 0 else None,
            "survivor_ids": [route["id"] for route in survivors], "trace": trace,
            "actual_flow_path": "unknown", "explanation": explanations[decision]}


def _encode(result: dict) -> bytes:
    encoded = (json.dumps(result, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT:
        raise LabError("serialized output exceeds 262144 bytes")
    return encoded


def analyze(data: bytes) -> dict:
    """Validate bounded exact bytes and classify fictional installed-route lookup.

    Returns a JSON-compatible report; raises LabError before returning on malformed
    input or output-budget failure. Recognized unsupported contexts return no results.
    Does not inspect devices, send packets, enumerate addresses or infer reachability.
    """
    context, routes, destinations = _validate(_load(data))
    report = {"version": 1, "model": "fictional-installed-route-subset", "context": context,
              "status": "supported" if context == "destination_only" else "unsupported_policy",
              "routes": [], "results": []}
    for route in routes:
        report["routes"].append({key: (str(value) if key == "network" else value) for key, value in route.items()})
    if context == "destination_only":
        report["results"] = [_lookup(routes, destination) for destination in destinations]
    else:
        report["reason"] = "Context needs policy/installation/resolution/flow rules outside this model; common payload validated."
    _encode(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="bounded fictional UTF-8 JSON file")
    args = parser.parse_args(argv)
    writing = False
    try:
        with open(args.scenario, "rb") as stream:
            report = analyze(stream.read(MAX_INPUT + 1))
        output = _encode(report)
        writing = True
        if sys.stdout.buffer.write(output) != len(output):
            raise LabError("short output write")
        sys.stdout.buffer.flush()
        return 0 if report["status"] == "supported" else 3
    except (LabError, OSError) as exc:
        if writing:
            # CPython retries flushing stdout at shutdown, replacing exit 2 with 120
            # on a broken pipe. No more output is possible; prevent that second retry.
            sys.stdout = None
        message = str(exc) if isinstance(exc, LabError) else "input/output operation failed"
        print("route-lab: " + message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
