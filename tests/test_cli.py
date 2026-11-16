import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run_cli(*args):
    return subprocess.run(
        [PY, "-m", "solution", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=120)


class TestCli(unittest.TestCase):
    def test_happy_path(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "result.json"
            proc = run_cli("--input", "cases.json", "--output", str(out))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["schema_version"], 1)
            self.assertEqual(result["summary"]["violations"], 74)
            self.assertIsNotNone(result["shortest_witness"])
            self.assertIn("fix", result)

    def test_seed_replayable(self):
        with tempfile.TemporaryDirectory() as td:
            out1, out2 = Path(td) / "r1.json", Path(td) / "r2.json"
            p1 = run_cli("--input", "cases.json", "--output", str(out1), "--seed", "7")
            p2 = run_cli("--input", "cases.json", "--output", str(out2), "--seed", "7")
            self.assertEqual(p1.returncode, 0, p1.stderr)
            self.assertEqual(p2.returncode, 0, p2.stderr)
            self.assertEqual(out1.read_bytes(), out2.read_bytes())
            self.assertEqual(json.loads(out1.read_text(encoding="utf-8"))["seed"], 7)

    def test_missing_input_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            proc = run_cli("--input", "no_such_file.json",
                           "--output", str(Path(td) / "x.json"))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("E_IO", proc.stderr)

    def test_invalid_json_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            proc = run_cli("--input", str(bad), "--output", str(Path(td) / "x.json"))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("E_SCHEMA", proc.stderr)

    def test_unknown_mutation_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            case = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
            case["mutations"] = ["identity", "nope"]
            cf = Path(td) / "cases.json"
            cf.write_text(json.dumps(case), encoding="utf-8")
            proc = run_cli("--input", str(cf), "--output", str(Path(td) / "x.json"))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("E_UNKNOWN_MUTATION", proc.stderr)

    def test_bad_policy_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            case = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
            case["proxy"]["policy"]["percent_decode"] = 5
            cf = Path(td) / "cases.json"
            cf.write_text(json.dumps(case), encoding="utf-8")
            proc = run_cli("--input", str(cf), "--output", str(Path(td) / "x.json"))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("E_BAD_POLICY", proc.stderr)


if __name__ == "__main__":
    unittest.main()
