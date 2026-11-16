import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.classify import Rule, classify

RULES = [
    Rule("PUB", "/public", "public"),
    Rule("PRIV", "/private", "private"),
    Rule("ADMIN", "/private/admin", "private"),
]


class TestClassify(unittest.TestCase):
    def test_longest_prefix_wins(self):
        m = classify("/private/admin/panel", RULES, "public")
        self.assertEqual(m["rule_id"], "ADMIN")

    def test_prefix_match_by_full_segments(self):
        # '/pub' 不是规则，且 '/public' 不能匹配段 'publicity'
        m = classify("/publicity/x", RULES, "public")
        self.assertIsNone(m["rule_id"])
        self.assertEqual(m["value"], "public")

    def test_exact_and_deeper_match(self):
        self.assertEqual(classify("/private", RULES, "public")["rule_id"], "PRIV")
        self.assertEqual(classify("/private/a/b", RULES, "public")["rule_id"], "PRIV")

    def test_default_when_no_match(self):
        m = classify("/other", RULES, "private")
        self.assertIsNone(m["rule_id"])
        self.assertEqual(m["value"], "private")

    def test_root_rule_matches_everything(self):
        rules = [Rule("ROOT", "/", "public"), Rule("PRIV", "/private", "private")]
        self.assertEqual(classify("/anything", rules, "private")["rule_id"], "ROOT")
        self.assertEqual(classify("/private/x", rules, "public")["rule_id"], "PRIV")

    def test_tie_breaks_by_declaration_order(self):
        rules = [Rule("A", "/x", "public"), Rule("B", "/x", "private")]
        self.assertEqual(classify("/x", rules, "private")["rule_id"], "A")

    def test_empty_segment_blocks_match(self):
        # '//private' 的首段为空段，不能匹配 '/private'
        m = classify("//private", RULES, "public")
        self.assertIsNone(m["rule_id"])

    def test_trailing_dot_segment_not_matched(self):
        m = classify("/private./x", RULES, "public")
        self.assertIsNone(m["rule_id"])


if __name__ == "__main__":
    unittest.main()
