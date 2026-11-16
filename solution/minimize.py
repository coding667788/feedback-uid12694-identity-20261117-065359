"""见证缩减：在保持“代理判 public 且后端落入 private”这一越权结论的前提下，
确定性地收缩候选输入。每轮尝试一组候选缩减，采纳第一个仍然构成越权
且按 (字节长度, 字节序) 更小的结果，直到收敛。长度单调不增且每步严格
减小，故必然终止；无随机性，可重放。
"""

from __future__ import annotations

import re

_HEX_RE = re.compile(rb"%[0-9A-Fa-f]{2}")


def reductions(raw: bytes):
    """生成候选缩减集合，按 (长度, 字节序) 升序返回。"""
    outs = []
    # 1) 将 %XX 解码为可打印 ASCII 字面字节（语义由调用方重新验证）
    i = 0
    n = len(raw)
    while i + 2 <= n - 1:
        if raw[i] == 0x25:
            try:
                val = int(raw[i + 1:i + 3], 16)
            except ValueError:
                i += 1
                continue
            if 0x20 <= val <= 0x7E:
                outs.append(raw[:i] + bytes([val]) + raw[i + 3:])
            i += 3
        else:
            i += 1
    # 2) 折叠重复斜杠 '//' -> '/'
    idx = raw.find(b"//")
    while idx != -1:
        outs.append(raw[:idx] + raw[idx + 1:])
        idx = raw.find(b"//", idx + 1)
    # 3) 去掉尾斜杠
    if n > 1 and raw.endswith(b"/"):
        outs.append(raw[:-1])
    # 4) 转义十六进制统一小写（长度不变，字节序更小）
    lowered = _HEX_RE.sub(lambda mo: b"%" + mo.group(0)[1:].lower(), raw)
    if lowered != raw:
        outs.append(lowered)
    return sorted(set(outs), key=lambda c: (len(c), c))


def minimize(raw: bytes, is_violation, max_rounds=64) -> bytes:
    """迭代收缩；is_violation(candidate) 负责重新验证越权结论。"""
    cur = raw
    for _ in range(max_rounds):
        nxt = None
        for cand in reductions(cur):
            if (len(cand), cand) < (len(cur), cur) and is_violation(cand):
                nxt = cand
                break
        if nxt is None:
            break
        cur = nxt
    return cur
