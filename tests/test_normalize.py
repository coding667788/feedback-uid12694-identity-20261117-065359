import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.normalize import (E_INVALID_ESCAPE, E_INVALID_UTF8,
                                E_PATH_ABOVE_ROOT, Policy, normalize)


def norm(raw, **kw):
    return normalize(raw, Policy(**kw))


class TestPercentDecode(unittest.TestCase):
    def test_double_decode(self):
        r = norm(b"/x/%252e%252e%252fprivate/secret", percent_decode=2)
        self.assertTrue(r["ok"])
        self.assertEqual(r["path"], "/private/secret")

    def test_single_decode_leaves_second_layer(self):
        r = norm(b"/x/%252e%252e%252fprivate/secret", percent_decode=1,
                 dot_collapse=False)
        self.assertEqual(r["path"], "/x/%2e%2e%2fprivate/secret")

    def test_zero_decode_keeps_escapes(self):
        r = norm(b"/a%2Fb", percent_decode=0)
        self.assertEqual(r["path"], "/a%2Fb")

    def test_incomplete_escape_rejected(self):
        for raw in (b"/a%", b"/a%2", b"/a%zz", b"/%"):
            r = norm(raw, percent_decode=1)
            self.assertFalse(r["ok"], raw)
            self.assertEqual(r["error"], E_INVALID_ESCAPE)

    def test_escape_not_validated_when_decode_zero(self):
        r = norm(b"/a%2", percent_decode=0)
        self.assertTrue(r["ok"])


class TestUtf8(unittest.TestCase):
    def test_invalid_utf8_rejected(self):
        r = norm(b"/public/\xff\xfe")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], E_INVALID_UTF8)

    def test_overlong_rejected(self):
        r = norm(b"/%c0%af", percent_decode=1)  # 过长编码的 '/'
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], E_INVALID_UTF8)

    def test_valid_multibyte(self):
        r = norm("/路径".encode("utf-8"))
        self.assertTrue(r["ok"])
        self.assertEqual(r["path"], "/路径")


class TestSeparatorsAndDots(unittest.TestCase):
    def test_backslash_conversion(self):
        self.assertEqual(norm(b"/a\\b", backslash_separator=True)["path"], "/a/b")
        self.assertEqual(norm(b"/a\\b", backslash_separator=False)["path"], "/a\\b")

    def test_mixed_separators(self):
        r = norm(b"/public/..\\private/secret", backslash_separator=True)
        self.assertEqual(r["path"], "/private/secret")

    def test_empty_segments_dropped_when_collapse(self):
        self.assertEqual(norm(b"//a//b", dot_collapse=True)["path"], "/a/b")

    def test_empty_segments_kept_when_no_collapse(self):
        self.assertEqual(norm(b"//a//b", dot_collapse=False)["path"], "//a//b")

    def test_dot_segments(self):
        self.assertEqual(norm(b"/a/./b")["path"], "/a/b")
        self.assertEqual(norm(b"/a/b/../c")["path"], "/a/c")
        self.assertEqual(norm(b"/a/.")["path"], "/a/")
        self.assertEqual(norm(b"/a/..")["path"], "/")

    def test_above_root_rejected(self):
        for raw in (b"/..", b"/a/../../b", b"/../.."):
            r = norm(raw)
            self.assertFalse(r["ok"], raw)
            self.assertEqual(r["error"], E_PATH_ABOVE_ROOT)

    def test_trailing_dot_preserved(self):
        r = norm(b"/private/secret.")
        self.assertTrue(r["ok"])
        self.assertEqual(r["path"], "/private/secret.")

    def test_trailing_dot_not_a_dot_segment(self):
        # 'b.' 不是点段，折叠后必须保留尾点
        self.assertEqual(norm(b"/a/b./../c")["path"], "/a/c")


class TestCaseAndTrailingSlash(unittest.TestCase):
    def test_case_fold_ascii_only(self):
        r = norm("/ABC路径".encode("utf-8"), case_insensitive=True)
        self.assertEqual(r["path"], "/abc路径")
        self.assertEqual(norm(b"/ABC", case_insensitive=False)["path"], "/ABC")

    def test_trailing_slash_policies(self):
        self.assertEqual(norm(b"/a/", trailing_slash="strip")["path"], "/a")
        self.assertEqual(norm(b"/a", trailing_slash="ensure")["path"], "/a/")
        self.assertEqual(norm(b"/a/", trailing_slash="keep")["path"], "/a/")
        self.assertEqual(norm(b"/", trailing_slash="strip")["path"], "/")


class TestOrderAndMapping(unittest.TestCase):
    def test_fixed_order_percent_before_collapse(self):
        # 先解码出 '..' 再折叠 -> 越根拒绝；若顺序颠倒则不会拒绝
        r = norm(b"/%2e%2e/x", percent_decode=1)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], E_PATH_ABOVE_ROOT)
        r0 = norm(b"/%2e%2e/x", percent_decode=0)
        self.assertTrue(r0["ok"])

    def test_byte_to_char_mapping(self):
        r = norm(b"/%41", percent_decode=1)
        self.assertEqual(r["path"], "/A")
        self.assertEqual(r["mapping"], [[0, 1], [1, 4]])

    def test_synthetic_char_mapping_is_null(self):
        r = norm(b"/a", trailing_slash="ensure")
        self.assertEqual(r["path"], "/a/")
        self.assertIsNone(r["mapping"][-1])

    def test_stage_chain_recorded(self):
        r = norm(b"/%41", percent_decode=1)
        names = [s["stage"] for s in r["stages"]]
        self.assertEqual(names, ["percent_decode[1/1]", "utf8_decode",
                                 "separator", "dot_collapse", "case",
                                 "trailing_slash"])


if __name__ == "__main__":
    unittest.main()
