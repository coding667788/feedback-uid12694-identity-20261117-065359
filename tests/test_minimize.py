import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.audit import load_case
from solution.classify import Rule, classify
from solution.minimize import minimize, reductions
from solution.normalize import Policy, normalize

ROOT = Path(__file__).resolve().parent.parent


def _make_checker():
    """用 cases.json 的两套策略构造越权判定函数。"""
    case, _ = load_case(ROOT / "cases.json")
    proxy_policy = Policy.from_dict(case["proxy"]["policy"])
    backend_policy = Policy.from_dict(case["backend"]["policy"])
    proxy_rules = [Rule(r["id"], r["prefix"], r["action"]) for r in case["proxy"]["acl"]]
    backend_rules = [Rule(r["id"], r["prefix"], r["zone"]) for r in case["backend"]["zones"]]

    def is_violation(raw):
        p = normalize(raw, proxy_policy)
        b = normalize(raw, backend_policy)
        if not p["ok"] or not b["ok"]:
            return False
        return (classify(p["path"], proxy_rules, "public")["value"] == "public"
                and classify(b["path"], backend_rules, "private")["value"] == "private")

    return is_violation


class TestMinimize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.is_violation = staticmethod(_make_checker())

    def test_percent_escapes_reduced_to_literals(self):
        raw = b"/x/%2e%2e%2fprivate/secret"
        self.assertTrue(self.is_violation(raw))
        out = minimize(raw, self.is_violation)
        self.assertEqual(out, b"/x/../private/secret")
        self.assertTrue(self.is_violation(out))

    def test_empty_segment_witness_cannot_shrink(self):
        raw = b"//private/secret"
        out = minimize(raw, self.is_violation)
        # 折叠 '//' 会破坏越权结论（代理将匹配 PRIV），故保持原样
        self.assertEqual(out, raw)

    def test_trailing_slash_stripped_when_safe(self):
        raw = b"/PRIVATE/"
        out = minimize(raw, self.is_violation)
        self.assertEqual(out, b"/PRIVATE")
        self.assertTrue(self.is_violation(out))

    def test_reductions_sorted_and_unique(self):
        rs = reductions(b"/a%41%42//b")
        keys = [(len(c), c) for c in rs]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(rs), len(set(rs)))

    def test_minimize_terminates_on_non_violation(self):
        out = minimize(b"/public/index.html", self.is_violation)
        self.assertEqual(out, b"/public/index.html")


if __name__ == "__main__":
    unittest.main()
