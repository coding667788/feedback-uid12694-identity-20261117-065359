"""统一策略修复建议。

枚举全部有限策略组合（3 x 2 x 2 x 2 x 3 = 72 种），逐一验证：
  a) 消除全部已知越权：把两侧都换成该统一策略后，已评估的全部候选请求
     中不再存在“代理判 public 且后端落入 private”（任一侧拒绝视为安全）；
  b) 保留正常路由集合：每条正常路由在统一策略下，代理动作与后端区域
     仍等于声明的期望值。
通过两项验证的策略按（与代理现策略的差异维度数, 策略元组字典序）排序，
取首个为推荐项；无通过项时 recommended 为 null。
"""

from __future__ import annotations

from itertools import product

from .classify import classify
from .normalize import PERCENT_DECODE_CHOICES, TRAILING_SLASH_CHOICES, Policy, normalize


def all_policies():
    for pd, bs, dc, ci, ts in product(
            PERCENT_DECODE_CHOICES, (False, True), (False, True),
            (False, True), TRAILING_SLASH_CHOICES):
        yield Policy(pd, bs, dc, ci, ts)


def _distance(a: Policy, b: Policy) -> int:
    return sum(x != y for x, y in zip(a.key(), b.key()))


def _violation_under(policy, raw, proxy_rules, proxy_default,
                     backend_rules, backend_default):
    pres = normalize(raw, policy)
    if not pres["ok"]:
        return False
    bres = normalize(raw, policy)
    if not bres["ok"]:
        return False
    pa = classify(pres["path"], proxy_rules, proxy_default)["value"]
    bz = classify(bres["path"], backend_rules, backend_default)["value"]
    return pa == "public" and bz == "private"


def _preserves_normal(policy, normal_routes, proxy_rules, proxy_default,
                      backend_rules, backend_default):
    for nr in normal_routes:
        pres = normalize(nr["raw_bytes"], policy)
        bres = normalize(nr["raw_bytes"], policy)
        if not pres["ok"] or not bres["ok"]:
            return False
        if classify(pres["path"], proxy_rules, proxy_default)["value"] != nr["expect_proxy"]:
            return False
        if classify(bres["path"], backend_rules, backend_default)["value"] != nr["expect_backend"]:
            return False
    return True


def suggest_fix(proxy_policy, proxy_rules, proxy_default,
                backend_rules, backend_default,
                candidates_raw, normal_routes):
    """返回修复建议报告字典。candidates_raw 为全部已评估候选的原始字节。"""
    evaluated = 0
    passing = []
    for pol in all_policies():
        evaluated += 1
        eliminates = not any(
            _violation_under(pol, raw, proxy_rules, proxy_default,
                             backend_rules, backend_default)
            for raw in candidates_raw)
        if not eliminates:
            continue
        if not _preserves_normal(pol, normal_routes, proxy_rules, proxy_default,
                                 backend_rules, backend_default):
            continue
        passing.append(pol)
    passing.sort(key=lambda p: (_distance(p, proxy_policy), p.key()))
    recommended = passing[0] if passing else None
    return {
        "policies_evaluated": evaluated,
        "passing_count": len(passing),
        "passing": [p.as_dict() for p in passing],
        "recommended": recommended.as_dict() if recommended else None,
        "distance_from_proxy": _distance(recommended, proxy_policy) if recommended else None,
        "eliminates_all_known_violations": recommended is not None,
        "preserves_normal_routes": recommended is not None,
        "checked_candidates": len(candidates_raw),
        "checked_normal_routes": len(normal_routes),
    }
