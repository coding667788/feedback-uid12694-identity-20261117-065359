import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.audit import load_case, run_audit

ROOT = Path(__file__).resolve().parent.parent


class AuditFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        case, base = load_case(ROOT / "cases.json")
        cls.result = run_audit(case, base, seed=0)

    def violations(self):
        return self.result["violations"]


class TestAcceptanceScenarios(AuditFixture):
    """题面要求的验收场景：双重编码、混合分隔符、空段、大小写与尾点组合。"""

    def identity_violation(self, seed_id):
        for v in self.violations():
            if v["seed_id"] == seed_id and v["mutation"] == "identity":
                return v
        self.fail(f"missing identity violation for {seed_id}")

    def test_double_encoding(self):
        v = self.identity_violation("s-double")
        self.assertEqual(v["raw_display"], "/x/%252e%252e%252fprivate/secret")
        self.assertEqual(v["proxy"]["path"], "/x/%2e%2e%2fprivate/secret")
        self.assertIsNone(v["proxy"]["rule_id"])
        self.assertEqual(v["proxy"]["action"], "public")
        self.assertEqual(v["backend"]["path"], "/private/secret")
        self.assertEqual(v["backend"]["rule_id"], "ZPRIV")
        self.assertEqual(v["backend"]["zone"], "private")

    def test_mixed_separators(self):
        v = self.identity_violation("s-mixed-sep")
        self.assertEqual(v["proxy"]["path"], "/public/..\\private/secret")
        self.assertEqual(v["proxy"]["rule_id"], "PUB")
        self.assertEqual(v["backend"]["path"], "/private/secret")
        self.assertEqual(v["backend"]["zone"], "private")

    def test_empty_segments(self):
        v = self.identity_violation("s-empty")
        self.assertEqual(v["proxy"]["path"], "//private/secret")
        self.assertIsNone(v["proxy"]["rule_id"])
        self.assertEqual(v["backend"]["path"], "/private/secret")
        self.assertEqual(v["backend"]["rule_id"], "ZPRIV")

    def test_case_and_dot_segments(self):
        v = self.identity_violation("s-case-dot")
        self.assertEqual(v["proxy"]["path"], "/PUBLIC/../PRIVATE/secret")
        self.assertIsNone(v["proxy"]["rule_id"])
        self.assertEqual(v["backend"]["path"], "/private/secret")
        self.assertEqual(v["backend"]["zone"], "private")

    def test_file_referenced_seed(self):
        v = self.identity_violation("s-file")
        self.assertEqual(v["backend"]["path"], "/private/secret")
        self.assertEqual(v["backend"]["zone"], "private")

    def test_trailing_dot_is_not_a_vulnerability(self):
        # 尾点保留：'/private/secret.' 两侧都判 private，不得报为越权
        for v in self.violations():
            if v["seed_id"] == "s-trailing-dot" and v["mutation"] == "identity":
                self.fail("trailing-dot seed must not be a violation")

    def test_counterexample_divergence_not_violation(self):
        # 反例：规范化结果不同但授权相同（都 public），只能进 divergences
        matches = [d for d in self.result["divergences"]
                   if d["seed_id"] == "s-counter" and d["mutation"] == "identity"]
        self.assertEqual(len(matches), 1)
        d = matches[0]
        self.assertEqual(d["proxy"]["action"], "public")
        self.assertEqual(d["backend"]["zone"], "public")
        self.assertTrue(d["authorization_equivalent"])
        self.assertNotEqual(d["proxy"]["path"], d["backend"]["path"])
        for v in self.violations():
            self.assertNotEqual(v["seed_id"], "s-counter")


class TestRejections(AuditFixture):
    def test_invalid_utf8_rejected(self):
        hits = [e for e in self.result["rejected"]
                if e["seed_id"] == "s-utf8-bad" and e["mutation"] == "identity"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["proxy_error"], "E_INVALID_UTF8")

    def test_above_root_rejected(self):
        hits = [e for e in self.result["rejected"]
                if e["seed_id"] == "s-above-root" and e["mutation"] == "identity"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["backend_error"], "E_PATH_ABOVE_ROOT")


class TestWitness(AuditFixture):
    def test_summary_counts(self):
        s = self.result["summary"]
        self.assertEqual(s["seeds"], 11)
        self.assertEqual(s["mutations"], 14)
        self.assertEqual(s["candidates"], 154)
        self.assertEqual(s["violations"], 74)
        self.assertEqual(s["rejected"], 28)
        self.assertEqual(s["agreements"], 9)
        self.assertEqual(s["divergences"], 43)

    def test_shortest_witness_is_minimal_by_length_then_bytes(self):
        import base64
        w = self.result["shortest_witness"]
        self.assertIsNotNone(w)
        all_raw = sorted(self.violations(),
                         key=lambda v: (v["length"], base64.b64decode(v["raw_b64"])))
        self.assertEqual(w["raw_b64"], all_raw[0]["raw_b64"])
        self.assertEqual(w["raw_display"], "/PRIVATE/")
        # 缩减后仍构成越权：代理 public、后端 private
        m = w["minimized"]
        self.assertEqual(m["raw_display"], "/PRIVATE")
        self.assertEqual(m["proxy"]["action"], "public")
        self.assertEqual(m["backend"]["zone"], "private")
        self.assertEqual(m["backend"]["rule_id"], "ZPRIV")

    def test_violations_sorted(self):
        import base64
        keys = [(v["length"], base64.b64decode(v["raw_b64"]))
                for v in self.violations()]
        self.assertEqual(keys, sorted(keys))

    def test_witness_carries_full_chains_and_rule_ids(self):
        v = next(v for v in self.violations()
                 if v["seed_id"] == "s-double" and v["mutation"] == "identity")
        proxy_stages = [s["stage"] for s in v["proxy"]["stages"]]
        backend_stages = [s["stage"] for s in v["backend"]["stages"]]
        self.assertEqual(proxy_stages[0], "percent_decode[1/1]")
        self.assertEqual(backend_stages[:2],
                         ["percent_decode[1/2]", "percent_decode[2/2]"])
        self.assertIn("rule_id", v["proxy"])
        self.assertIn("rule_id", v["backend"])
        self.assertIsNotNone(v["backend"]["mapping"])


class TestFixAndNormalRoutes(AuditFixture):
    def test_fix_recommendation(self):
        fix = self.result["fix"]
        self.assertEqual(fix["policies_evaluated"], 72)
        self.assertEqual(fix["passing_count"], 72)
        self.assertTrue(fix["eliminates_all_known_violations"])
        self.assertTrue(fix["preserves_normal_routes"])
        self.assertEqual(fix["recommended"], self.result["policies"]["proxy"])
        self.assertEqual(fix["distance_from_proxy"], 0)

    def test_normal_routes_preserved(self):
        for nr in self.result["normal_routes"]:
            self.assertTrue(nr["preserved"], nr["id"])
        ids = [nr["id"] for nr in self.result["normal_routes"]]
        self.assertEqual(ids, ["n-public", "n-private", "n-admin", "n-slash"])

    def test_longest_prefix_rule_used_for_admin(self):
        nr = next(n for n in self.result["normal_routes"] if n["id"] == "n-admin")
        self.assertEqual(nr["proxy_rule_id"], "PRIVADMIN")


class TestDeterminism(AuditFixture):
    def test_replay_is_deterministic(self):
        case, base = load_case(ROOT / "cases.json")
        again = run_audit(case, base, seed=0)
        self.assertEqual(json.dumps(self.result, sort_keys=True),
                         json.dumps(again, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
