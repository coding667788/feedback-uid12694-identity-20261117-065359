import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.audit import load_case
from solution.classify import Rule
from solution.fix import all_policies, suggest_fix
from solution.normalize import Policy

ROOT = Path(__file__).resolve().parent.parent


class TestFix(unittest.TestCase):
    def test_policy_space_size(self):
        self.assertEqual(len(list(all_policies())), 72)

    def test_unification_with_proxy_policy_recommended(self):
        case, _ = load_case(ROOT / "cases.json")
        proxy_policy = Policy.from_dict(case["proxy"]["policy"])
        proxy_rules = [Rule(r["id"], r["prefix"], r["action"]) for r in case["proxy"]["acl"]]
        backend_rules = [Rule(r["id"], r["prefix"], r["zone"]) for r in case["backend"]["zones"]]
        candidates = [b"/x/%252e%252e%252fprivate/secret", b"//private/secret",
                      b"/PRIVATE/", b"/public/index.html"]
        normal = [{"raw_bytes": b"/public/index.html",
                   "expect_proxy": "public", "expect_backend": "public"},
                  {"raw_bytes": b"/private/secret",
                   "expect_proxy": "private", "expect_backend": "private"}]
        report = suggest_fix(proxy_policy, proxy_rules, "public",
                             backend_rules, "public", candidates, normal)
        self.assertEqual(report["policies_evaluated"], 72)
        self.assertEqual(report["recommended"], proxy_policy.as_dict())
        self.assertEqual(report["distance_from_proxy"], 0)
        self.assertTrue(report["eliminates_all_known_violations"])

    def test_no_passing_policy_returns_null(self):
        # 代理无规则默认 public，后端根规则 private：
        # 任何统一策略下每个候选都是越权，无可行修复
        proxy_rules = []
        backend_rules = [Rule("ZROOT", "/", "private")]
        report = suggest_fix(Policy(), proxy_rules, "public",
                             backend_rules, "private", [b"/a"], [])
        self.assertEqual(report["passing_count"], 0)
        self.assertIsNone(report["recommended"])
        self.assertFalse(report["eliminates_all_known_violations"])

    def test_normal_route_violation_filters_policy(self):
        # 构造一条正常路由：期望代理 public；若统一策略把 '/PRIVATE'
        # 折叠大小写后匹配到 private 规则，则该策略不得通过
        proxy_rules = [Rule("P", "/private", "private")]
        backend_rules = [Rule("Z", "/private", "private")]
        normal = [{"raw_bytes": b"/PRIVATE",
                   "expect_proxy": "public", "expect_backend": "public"}]
        report = suggest_fix(Policy(case_insensitive=False),
                             proxy_rules, "public", backend_rules, "public",
                             [b"/PUBLIC"], normal)
        for p in report["passing"]:
            self.assertFalse(p["case_insensitive"])


if __name__ == "__main__":
    unittest.main()
