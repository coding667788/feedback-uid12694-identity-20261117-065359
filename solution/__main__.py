"""CLI 入口：python -m solution --input cases.json --output result.json [--seed N]

退出码：0 = 审计完成（是否发现越权属于数据，不影响退出码）；
       2 = 输入用例错误（E_SCHEMA / E_IO / E_UNKNOWN_MUTATION / E_BAD_POLICY）；
       3 = 未预期的内部错误。
"""

from __future__ import annotations

import argparse
import json
import sys

from .audit import load_case, run_audit
from .errors import CaseError


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="solution",
        description="离线路由审计器：反向代理/后端路径规范化差异的越权差分检测")
    parser.add_argument("--input", required=True, help="cases.json 路径")
    parser.add_argument("--output", required=True, help="result.json 输出路径")
    parser.add_argument("--seed", type=int, default=0,
                        help="重放种子（仅记录在结果中；审计过程本身完全确定）")
    args = parser.parse_args(argv)

    try:
        case, base_dir = load_case(args.input)
        result = run_audit(case, base_dir, seed=args.seed)
    except CaseError as exc:
        print(f"error[{exc.code}]: {exc.detail}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - 防御性兜底
        print(f"error[E_INTERNAL]: {exc}", file=sys.stderr)
        return 3

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write("\n")
    except OSError as exc:
        print(f"error[E_IO]: cannot write {args.output}: {exc}", file=sys.stderr)
        return 2

    s = result["summary"]
    print(f"candidates={s['candidates']} violations={s['violations']} "
          f"divergences={s['divergences']} agreements={s['agreements']} "
          f"rejected={s['rejected']}")
    if result["shortest_witness"]:
        w = result["shortest_witness"]
        print(f"shortest witness: {w['raw_display']!r} "
              f"(proxy rule={w['proxy']['rule_id']} -> public, "
              f"backend rule={w['backend']['rule_id']} -> private)")
    rec = result["fix"]["recommended"]
    print(f"fix recommended: {rec if rec else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
