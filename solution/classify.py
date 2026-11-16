"""基于完整路径段的最长前缀访问规则匹配。

规则前缀视为“已规范化”的字面路径（直接按 '/' 切分段），
与规范化后的路径按完整段逐一比较：前缀 '/pub' 不会匹配段 'public'。
最长（段数最多）的匹配规则胜出；段数相同则先声明的规则胜出；
无匹配时回落到该侧配置的默认动作。
"""

from __future__ import annotations


class Rule:
    def __init__(self, rid, prefix, value):
        if not isinstance(prefix, str) or not prefix.startswith("/"):
            raise ValueError(f"rule {rid!r}: prefix must be an absolute path")
        self.id = rid
        self.prefix = prefix
        self.value = value
        self.segments = () if prefix == "/" else tuple(prefix.split("/")[1:])

    def as_dict(self):
        return {"id": self.id, "prefix": self.prefix, "value": self.value}


def classify(path, rules, default):
    """返回 {'rule_id', 'value', 'matched_prefix'}；无匹配时 rule_id 为 None。"""
    segs = path.split("/")[1:] if path.startswith("/") else path.split("/")
    best = None
    for r in rules:
        pre = list(r.segments)
        if len(pre) <= len(segs) and segs[:len(pre)] == pre:
            if best is None or len(pre) > len(best.segments):
                best = r
    if best is None:
        return {"rule_id": None, "value": default, "matched_prefix": None}
    return {"rule_id": best.id, "value": best.value, "matched_prefix": best.prefix}
