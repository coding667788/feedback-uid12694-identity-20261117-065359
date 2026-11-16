"""差分审计主流程。

输入：两套显式路径转换规则（代理侧 policy+ACL，后端侧 policy+区域规则）
与请求样本（种子）。枚举 种子 x 声明变换 的有限组合，对每个候选：
  - 两侧分别规范化并分类；
  - 代理判 public 且后端落入 private -> violation（越权见证）；
  - 两侧均接受但规范化路径不同 -> divergence（分歧；授权可能等价，作为反例保留）；
  - 两侧均接受且路径相同 -> agreement；
  - 任一侧拒绝 -> rejected（记录错误码，视为安全）。
随后对每个越权见证做缩减，并按 (字节长度, 字节序) 选出最短见证；
最后枚举统一策略空间给出修复建议。
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from .classify import Rule, classify
from .errors import E_BAD_POLICY, E_IO, E_SCHEMA, E_UNKNOWN_MUTATION, CaseError
from .fix import suggest_fix
from .minimize import minimize
from .mutations import MUTATIONS
from .normalize import Policy, normalize

ACTIONS = ("public", "private")


# ---------------------------------------------------------------- 输入装载

def _load_raw_bytes(entry, base_dir):
    if "raw" in entry:
        return entry["raw"].encode("utf-8")
    if "raw_b64" in entry:
        try:
            return base64.b64decode(entry["raw_b64"], validate=True)
        except Exception as exc:
            raise CaseError(E_SCHEMA, f"entry {entry.get('id')!r}: bad raw_b64: {exc}")
    if "file" in entry:
        p = (base_dir / entry["file"]).resolve()
        try:
            return p.read_bytes()
        except OSError as exc:
            raise CaseError(E_IO, f"entry {entry.get('id')!r}: cannot read {p}: {exc}")
    raise CaseError(E_SCHEMA, f"entry {entry.get('id')!r}: need one of raw/raw_b64/file")


def _load_rules(items, value_key, section):
    rules = []
    for it in items:
        if not isinstance(it, dict) or not it.get("id") or not it.get("prefix"):
            raise CaseError(E_SCHEMA, f"{section}: rule needs id and prefix")
        value = it.get(value_key)
        if value not in ACTIONS:
            raise CaseError(E_SCHEMA, f"{section}: rule {it['id']!r} needs {value_key} in {ACTIONS}")
        try:
            rules.append(Rule(it["id"], it["prefix"], value))
        except ValueError as exc:
            raise CaseError(E_SCHEMA, f"{section}: {exc}")
    return rules


def _load_policy(d, section):
    try:
        return Policy.from_dict(d or {})
    except (ValueError, TypeError) as exc:
        raise CaseError(E_BAD_POLICY, f"{section}: {exc}")


def load_case(path):
    """读取并校验 cases.json，返回 (case_dict, base_dir)。失败抛 CaseError。"""
    p = Path(path)
    try:
        case = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CaseError(E_IO, f"cannot read {p}: {exc}")
    except json.JSONDecodeError as exc:
        raise CaseError(E_SCHEMA, f"invalid JSON in {p}: {exc}")
    if not isinstance(case, dict):
        raise CaseError(E_SCHEMA, "top level must be an object")
    if case.get("version") != 1:
        raise CaseError(E_SCHEMA, "version must be 1")
    for side in ("proxy", "backend"):
        if not isinstance(case.get(side), dict):
            raise CaseError(E_SCHEMA, f"missing section {side!r}")
    if not isinstance(case.get("seeds"), list) or not case["seeds"]:
        raise CaseError(E_SCHEMA, "seeds must be a non-empty list")
    mutations = case.get("mutations", ["identity"])
    if not isinstance(mutations, list) or not mutations:
        raise CaseError(E_SCHEMA, "mutations must be a non-empty list")
    for name in mutations:
        if name not in MUTATIONS:
            raise CaseError(E_UNKNOWN_MUTATION, f"unknown mutation {name!r}")
    normal = case.get("normal_routes", [])
    if not isinstance(normal, list):
        raise CaseError(E_SCHEMA, "normal_routes must be a list")
    for nr in normal:
        if nr.get("expect_proxy") not in ACTIONS or nr.get("expect_backend") not in ACTIONS:
            raise CaseError(E_SCHEMA, f"normal route {nr.get('id')!r}: bad expectations")
    return case, p.resolve().parent


# ---------------------------------------------------------------- 单侧评估

def _side_eval(raw, policy, rules, default, value_key):
    res = normalize(raw, policy)
    if not res["ok"]:
        return {"ok": False, "error": res["error"], "detail": res["detail"],
                "stages": res["stages"]}
    m = classify(res["path"], rules, default)
    return {"ok": True, "path": res["path"], value_key: m["value"],
            "rule_id": m["rule_id"], "matched_prefix": m["matched_prefix"],
            "stages": res["stages"], "mapping": res["mapping"]}


def _display(raw: bytes) -> str:
    return raw.decode("utf-8", "backslashreplace")


# ---------------------------------------------------------------- 主流程

def run_audit(case, base_dir, seed=0):
    proxy_policy = _load_policy(case["proxy"].get("policy"), "proxy.policy")
    backend_policy = _load_policy(case["backend"].get("policy"), "backend.policy")
    proxy_rules = _load_rules(case["proxy"].get("acl", []), "action", "proxy.acl")
    backend_rules = _load_rules(case["backend"].get("zones", []), "zone", "backend.zones")
    proxy_default = case["proxy"].get("default_action", "private")
    backend_default = case["backend"].get("default_zone", "private")
    if proxy_default not in ACTIONS or backend_default not in ACTIONS:
        raise CaseError(E_SCHEMA, "default_action/default_zone must be public|private")

    seeds = [(s.get("id", f"seed-{i}"), _load_raw_bytes(s, base_dir))
             for i, s in enumerate(case["seeds"])]
    mutation_names = list(case.get("mutations", ["identity"]))
    normal_routes = [{"id": nr.get("id", f"normal-{i}"),
                      "raw_bytes": _load_raw_bytes(nr, base_dir),
                      "expect_proxy": nr["expect_proxy"],
                      "expect_backend": nr["expect_backend"]}
                     for i, nr in enumerate(case.get("normal_routes", []))]

    def is_violation(raw):
        pres = normalize(raw, proxy_policy)
        if not pres["ok"]:
            return False
        bres = normalize(raw, backend_policy)
        if not bres["ok"]:
            return False
        pa = classify(pres["path"], proxy_rules, proxy_default)["value"]
        bz = classify(bres["path"], backend_rules, backend_default)["value"]
        return pa == "public" and bz == "private"

    violations, divergences, rejected = [], [], []
    agreements = 0
    candidates_raw = []

    for sid, seed_raw in seeds:
        for mname in mutation_names:
            raw = MUTATIONS[mname](seed_raw)
            candidates_raw.append(raw)
            proxy = _side_eval(raw, proxy_policy, proxy_rules, proxy_default, "action")
            backend = _side_eval(raw, backend_policy, backend_rules, backend_default, "zone")
            if not proxy["ok"] or not backend["ok"]:
                rejected.append({
                    "seed_id": sid, "mutation": mname,
                    "raw_display": _display(raw),
                    "proxy_error": None if proxy["ok"] else proxy["error"],
                    "backend_error": None if backend["ok"] else backend["error"],
                    "detail": (proxy.get("detail") or backend.get("detail")),
                })
                continue
            if proxy["action"] == "public" and backend["zone"] == "private":
                violations.append({
                    "seed_id": sid, "mutation": mname, "raw": raw,
                    "proxy": proxy, "backend": backend,
                })
            elif proxy["path"] != backend["path"]:
                divergences.append({
                    "seed_id": sid, "mutation": mname,
                    "raw_display": _display(raw),
                    "proxy": {"path": proxy["path"], "action": proxy["action"],
                              "rule_id": proxy["rule_id"]},
                    "backend": {"path": backend["path"], "zone": backend["zone"],
                                "rule_id": backend["rule_id"]},
                    "authorization_equivalent":
                        not (proxy["action"] == "public" and backend["zone"] == "private"),
                })
            else:
                agreements += 1

    # 越权见证：缩减 + 按 (字节长度, 字节序) 排序
    violations.sort(key=lambda v: (len(v["raw"]), v["raw"]))
    violation_entries = []
    for v in violations:
        raw = v["raw"]
        min_raw = minimize(raw, is_violation)
        min_proxy = _side_eval(min_raw, proxy_policy, proxy_rules, proxy_default, "action")
        min_backend = _side_eval(min_raw, backend_policy, backend_rules, backend_default, "zone")
        violation_entries.append({
            "seed_id": v["seed_id"],
            "mutation": v["mutation"],
            "raw_b64": base64.b64encode(raw).decode("ascii"),
            "raw_display": _display(raw),
            "length": len(raw),
            "proxy": v["proxy"],
            "backend": v["backend"],
            "minimized": {
                "raw_b64": base64.b64encode(min_raw).decode("ascii"),
                "raw_display": _display(min_raw),
                "length": len(min_raw),
                "proxy": min_proxy,
                "backend": min_backend,
            },
        })

    shortest = violation_entries[0] if violation_entries else None

    # 正常路由在当前两套策略下的实际表现
    normal_report = []
    for nr in normal_routes:
        proxy = _side_eval(nr["raw_bytes"], proxy_policy, proxy_rules, proxy_default, "action")
        backend = _side_eval(nr["raw_bytes"], backend_policy, backend_rules, backend_default, "zone")
        actual_proxy = proxy.get("action") if proxy["ok"] else None
        actual_backend = backend.get("zone") if backend["ok"] else None
        normal_report.append({
            "id": nr["id"],
            "raw_display": _display(nr["raw_bytes"]),
            "expect_proxy": nr["expect_proxy"],
            "expect_backend": nr["expect_backend"],
            "actual_proxy": actual_proxy,
            "actual_backend": actual_backend,
            "proxy_rule_id": proxy.get("rule_id") if proxy["ok"] else None,
            "backend_rule_id": backend.get("rule_id") if backend["ok"] else None,
            "preserved": actual_proxy == nr["expect_proxy"]
                         and actual_backend == nr["expect_backend"],
        })

    fix = suggest_fix(proxy_policy, proxy_rules, proxy_default,
                      backend_rules, backend_default,
                      candidates_raw, normal_routes)

    return {
        "schema_version": 1,
        "seed": seed,
        "policies": {"proxy": proxy_policy.as_dict(),
                     "backend": backend_policy.as_dict()},
        "summary": {
            "seeds": len(seeds),
            "mutations": len(mutation_names),
            "candidates": len(candidates_raw),
            "violations": len(violation_entries),
            "divergences": len(divergences),
            "agreements": agreements,
            "rejected": len(rejected),
        },
        "shortest_witness": shortest,
        "violations": violation_entries,
        "divergences": divergences,
        "rejected": rejected,
        "normal_routes": normal_report,
        "fix": fix,
    }
