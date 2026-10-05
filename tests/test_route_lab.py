"""Frozen independent route expectations, bounded oracle and CLI errors."""
import io
import json
from pathlib import Path
# Fixed local interpreter/CLI fixture only; no shell, network or third-party execution.
import subprocess  # nosec B404
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import route_lab as lab


def forward(identity="r1", prefix="192.0.2.0/24", hop="192.0.2.1", egress="lab-a", group=None):
    route = {"id": identity, "prefix": prefix, "action": "forward", "next_hop": hop, "egress": egress}
    if group is not None:
        route["ecmp_group"] = group
    return route


def discard(identity="d1", prefix="192.0.2.0/25"):
    return {"id": identity, "prefix": prefix, "action": "discard"}


def document(routes=None, destinations=None, context="destination_only"):
    return {"version": 1, "context": context, "routes": routes if routes is not None else [forward()],
            "destinations": destinations if destinations is not None else ["192.0.2.20"]}


def run(routes=None, destinations=None, context="destination_only"):
    return lab.analyze(json.dumps(document(routes, destinations, context)).encode())


class Semantics(unittest.TestCase):
    def test_fixed_host_nested_boundary(self):
        routes = [forward("r24"), forward("r25", "192.0.2.0/25"), forward("rh", "192.0.2.20/32")]
        rows = run(routes, ["192.0.2.20", "192.0.2.127", "192.0.2.128"])["results"]
        self.assertEqual([row["survivor_ids"] for row in rows], [["rh"], ["r25"], ["r24"]])
        self.assertEqual([row["longest_prefix_length"] for row in rows], [32, 25, 24])

    def test_default_family_isolation(self):
        routes = [forward("v4", "0.0.0.0/0")]
        rows = run(routes, ["198.51.100.20", "2001:db8::1"])["results"]
        self.assertEqual(rows[0]["survivor_ids"], ["v4"])
        self.assertEqual(rows[1]["decision"], "no_model_route")
        self.assertIsNone(rows[1]["longest_prefix_length"])
        self.assertEqual(rows[1]["trace"], [{"id": "v4", "reason": "different_family"}])
        routes.append(forward("v6", "::/0", "2001:db8::2"))
        self.assertEqual(run(routes, ["2001:db8::1"])["results"][0]["survivor_ids"], ["v6"])

    def test_ipv6_host_and_original(self):
        routes = [forward("net", "2001:0DB8::/32", "2001:0DB8::1"),
                  forward("host", "2001:db8::20/128", "2001:db8::2")]
        result = run(routes, ["2001:0DB8:0:0:0:0:0:20"])
        self.assertEqual(result["results"][0]["survivor_ids"], ["host"])
        self.assertEqual(result["results"][0]["destination"], "2001:db8::20")
        self.assertEqual(result["results"][0]["original_destination"], "2001:0DB8:0:0:0:0:0:20")
        self.assertEqual(result["routes"][1]["network"], "2001:db8::/32")
        self.assertEqual(result["routes"][1]["original_prefix"], "2001:0DB8::/32")

    def test_more_specific_discard_no_fallback(self):
        row = run([forward(), discard()])["results"][0]
        self.assertEqual(row["decision"], "selected_discard")
        self.assertEqual(row["survivor_ids"], ["d1"])

    def test_same_prefix_discard_forward_ambiguous(self):
        routes = [forward(), discard(prefix="192.0.2.0/24")]
        self.assertEqual(run(routes)["results"][0]["decision"], "ambiguous_equal_best")

    def test_equal_best_and_input_permutation(self):
        routes = [forward("b", hop="192.0.2.2"), forward("a")]
        first = run(routes)
        self.assertEqual(first, run(list(reversed(routes))))
        self.assertEqual(first["results"][0]["decision"], "ambiguous_equal_best")
        self.assertEqual(first["results"][0]["survivor_ids"], ["a", "b"])
        self.assertEqual(first["results"][0]["actual_flow_path"], "unknown")

    def test_declared_ecmp(self):
        routes = [forward("a", group="g"), forward("b", hop="192.0.2.2", group="g")]
        row = run(routes)["results"][0]
        self.assertEqual(row["decision"], "declared_ecmp_candidates")
        self.assertEqual(row["survivor_ids"], ["a", "b"])
        self.assertEqual(row["actual_flow_path"], "unknown")

    def test_no_match_and_empty(self):
        self.assertEqual(run([], ["192.0.2.20"])["results"][0]["decision"], "no_model_route")
        self.assertEqual(run(destinations=[])["results"], [])
        self.assertEqual(run([], [], "source_policy")["status"], "unsupported_policy")

    def test_trace_categories(self):
        routes = [forward("short", "0.0.0.0/0"), forward("long"),
                  forward("other", "198.51.100.0/24"), forward("v6", "::/0", "2001:db8::1")]
        trace = run(routes)["results"][0]["trace"]
        self.assertEqual({item["id"]: item["reason"] for item in trace},
                         {"short": "shorter_match", "long": "longest_match", "other": "does_not_contain", "v6": "different_family"})

    def test_unsupported_after_full_validation(self):
        for context in lab.CONTEXTS - {"destination_only"}:
            result = run(context=context)
            self.assertEqual(result["status"], "unsupported_policy")
            self.assertEqual(result["results"], [])
            with self.assertRaises(lab.LabError):
                run([forward(prefix="192.0.2.1/24")], context=context)

    def test_forbidden_capabilities_and_determinism(self):
        with patch("socket.socket", side_effect=RuntimeError("forbidden")), patch("socket.getaddrinfo", side_effect=RuntimeError("forbidden")), patch("subprocess.run", side_effect=RuntimeError("forbidden")), patch("ipaddress.IPv4Network.__iter__", side_effect=RuntimeError("enumeration forbidden")), patch("ipaddress.IPv6Network.__iter__", side_effect=RuntimeError("enumeration forbidden")):
            self.assertEqual(run(), run())

    def test_bitmask_oracle(self):
        # Literal documentation-prefix bases; expected masks do not use ipaddress membership.
        for bits, base, lengths in ((32, 0xC0000200, range(24, 33)), (128, 0x20010DB8 << 96, (32, 48, 64, 96, 128))):
            def spelling(value):
                if bits == 32:
                    return ".".join(str((value >> shift) & 255) for shift in (24, 16, 8, 0))
                return ":".join(format((value >> shift) & 65535, "x") for shift in range(112, -1, -16))
            pairs, routes = [], []
            for index, length in enumerate(lengths):
                mask = ((1 << bits) - 1) ^ ((1 << (bits - length)) - 1)
                prefix = base & mask
                pairs.append((prefix, length, mask, f"r{index}"))
                routes.append(forward(f"r{index}", spelling(prefix) + "/" + str(length), spelling(base + 1)))
            for offset in (0, 1, 19, 20, 21, 31, 32, 63, 64, 127, 128, 129, 191, 192, 254, 255):
                address = base + offset
                matches = [(length, identity) for prefix, length, mask, identity in pairs if address & mask == prefix]
                maximum = max(length for length, identity in matches)
                expected = sorted(identity for length, identity in matches if length == maximum)
                self.assertEqual(run(routes, [spelling(address)])["results"][0]["survivor_ids"], expected)


class Boundaries(unittest.TestCase):
    def test_duplicate_identity_independent_of_id_group(self):
        for routes in ([forward("a"), forward("b")], [forward("a", group="g"), forward("b", group="other")],
                       [discard("a"), discard("b")],
                       [forward("a", "::/0", "2001:db8::1"), forward("b", "0:0:0:0:0:0:0:0/0", "2001:0DB8::1")]):
            with self.assertRaises(lab.LabError):
                run(routes)

    def test_group_consistency(self):
        good = [forward("a", group="g"), forward("b", hop="192.0.2.2", group="g")]
        cases = [good[:1], good + [discard(prefix="192.0.2.0/24")], good + [forward("c", hop="192.0.2.3")],
                 [good[0], forward("b", hop="192.0.2.2", group="h")],
                 [good[0], forward("b", "192.0.2.0/25", "192.0.2.2", group="g")]]
        for routes in cases:
            with self.assertRaises(lab.LabError):
                run(routes)

    def test_address_and_network_invalid(self):
        for prefix in ("192.0.2.1/24", "192.0.2.0/024", "192.0.2.0/255.255.255.0", "192.000.2.0/24", "192.0.2.0/33", "10.0.0.0/8", "2001:db8::1/64", "2001:db8::/129", "::ffff:192.0.2.0/120", "2001:db8::%lab/64"):
            with self.subTest(prefix=prefix), self.assertRaises(lab.LabError):
                run([forward(prefix=prefix)])
        for destination in ("10.0.0.1", "2001:db8::1%lab", "::ffff:192.0.2.1", True, {}, "192.0.2.01"):
            with self.assertRaises(lab.LabError):
                run(destinations=[destination])
        with self.assertRaises(lab.LabError):
            run([forward(hop="2001:db8::1")])

    def test_schema_rejections(self):
        for route in ({**forward(), "metric": 10}, {**forward(), "id": "-bad"}, {**discard(), "next_hop": "192.0.2.1"}, {**forward(), "action": []}):
            with self.assertRaises(lab.LabError):
                run([route])
        for change in ({"version": True}, {"context": []}, {"context": "unknown"}, {"extra": 1}, {"routes": {}}, {"destinations": None}, {"routes": [forward()] * 65}, {"destinations": ["192.0.2.1"] * 17}):
            with self.assertRaises(lab.LabError):
                lab.analyze(json.dumps({**document(), **change}).encode())
        with self.assertRaises(lab.LabError):
            run(destinations=["2001:db8::1", "2001:0DB8:0:0:0:0:0:1"])

    def test_json_boundaries_and_exact_api(self):
        class ForeignBytes(bytes):
            pass
        for data in (ForeignBytes(b"{}"), {}, bytearray(b"{}"), b' ' * 65537, b'[' * 7 + b']' * 7,
                     b'{"version":1,"version":1}', b'{"version":12345678901}', b'{"version":1.0}',
                     b'NaN', b'"' + b'a' * 129 + b'"', b'"\\u001b"', b'"\\ud800"', b'\xff', b'\xef\xbb\xbf{}', b'{'):
            with self.assertRaises(lab.LabError):
                lab.analyze(data)

    def test_output_limit_before_api_return(self):
        with patch.object(lab, "MAX_OUTPUT", 2), self.assertRaises(lab.LabError):
            run()

    def test_cli_exits_atomic_errors_and_optimized_child(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scenario.json"
            cases = [(document(), 0), (document(context="source_policy"), 3), (document([forward(prefix="192.0.2.1/24")]), 2)]
            for fixture, expected in cases:
                path.write_text(json.dumps(fixture), encoding="utf-8")
                command = [sys.executable] + (["-O"] if sys.flags.optimize else []) + [str(Path(lab.__file__).resolve()), str(path)]
                # Fixed installed interpreter/script, inert temporary fictional fixture, no shell.
                result = subprocess.run(command, capture_output=True, timeout=10, check=False)  # nosec B603
                self.assertEqual(result.returncode, expected)
                if expected == 2:
                    self.assertEqual(result.stdout, b"")
                else:
                    self.assertEqual(json.loads(result.stdout)["status"], "supported" if expected == 0 else "unsupported_policy")

    def test_short_write_and_io_errors_honest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scenario.json"
            path.write_text(json.dumps(document()), encoding="utf-8")
            output = SimpleNamespace(buffer=SimpleNamespace(write=lambda data: 0))
            with patch("sys.stdout", output), patch("sys.stderr", io.StringIO()) as error:
                self.assertEqual(lab.main([str(path)]), 2)
                self.assertIn("short output write", error.getvalue())
            with patch("sys.stderr", io.StringIO()) as error:
                self.assertEqual(lab.main([str(Path(folder) / "missing")]), 2)
                self.assertNotIn("missing", error.getvalue())

    def test_closed_pipe_exit_is_not_shutdown_flush_120(self):
        cli = str(Path(lab.__file__).resolve())
        example = str(Path(lab.__file__).resolve().parent / "examples" / "lookup.json")
        command = [sys.executable] + (["-O"] if sys.flags.optimize else []) + [cli, example]
        # Fixed owned CLI and fictional example, no shell or external binary.
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:  # nosec B603
            child.stdout.close()
            child.stdout = None
            _, error = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 2)
            self.assertIn(b"input/output operation failed", error)
            self.assertNotIn(b"Exception ignored", error)


if __name__ == "__main__":
    unittest.main()
