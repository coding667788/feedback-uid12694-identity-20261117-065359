"""作用于请求种子的有限声明式变换库（bytes -> bytes，全部确定性）。

cases.json 通过 "mutations" 列表声明启用哪些变换；审计器枚举
种子 x 变换 的有限组合作为候选请求。这些变换模拟客户端/中间设备
对同一路径的各种等价或混淆写法。
"""

from __future__ import annotations

import re

_HEX_RE = re.compile(rb"%[0-9A-Fa-f]{2}")
_UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")


def _enc_byte(b):
    return b"%%%02X" % b


def m_identity(raw):
    return raw


def m_encode_all_once(raw):
    """对非 unreserved 字节整体做一遍百分号编码。"""
    out = bytearray()
    for b in raw:
        if b in _UNRESERVED:
            out.append(b)
        else:
            out += _enc_byte(b)
    return bytes(out)


def m_encode_path_specials(raw):
    """仅编码路径敏感字符 % / \\ . 。"""
    out = bytearray()
    for b in raw:
        if b in b"%/\\.":
            out += _enc_byte(b)
        else:
            out.append(b)
    return bytes(out)


def m_double_encode(raw):
    """把已有 '%' 再编码为 %25（双重编码）。"""
    return raw.replace(b"%", b"%25")


def m_swap_backslash(raw):
    return raw.replace(b"/", b"\\")


def m_mixed_separators(raw):
    """交替使用 '/' 与 '\\' 作为分隔符。"""
    out = bytearray()
    k = 0
    for b in raw:
        if b == 0x2F:
            out.append(0x5C if k % 2 else 0x2F)
            k += 1
        else:
            out.append(b)
    return bytes(out)


def m_case_flip(raw):
    """ASCII 字母大小写互换。"""
    out = bytearray()
    for b in raw:
        if 0x41 <= b <= 0x5A:
            out.append(b + 0x20)
        elif 0x61 <= b <= 0x7A:
            out.append(b - 0x20)
        else:
            out.append(b)
    return bytes(out)


def m_append_slash(raw):
    return raw + b"/"


def m_strip_slash(raw):
    return raw[:-1] if len(raw) > 1 and raw.endswith(b"/") else raw


def m_insert_empty_segment(raw):
    """在根之后插入一个空段（'/a' -> '//a'）。"""
    if raw.startswith(b"/"):
        return b"/" + raw
    return raw.replace(b"/", b"//", 1) if b"/" in raw else b"/" + raw


def m_append_trailing_dot(raw):
    """给最后一段追加尾点。"""
    return raw + b"."


def m_dot_wrap(raw):
    """在根之后插入 '/.' 段。"""
    return b"/./" + raw[1:] if raw.startswith(b"/") else b"/./" + raw


def m_upper_hex(raw):
    return _HEX_RE.sub(lambda mo: mo.group(0).upper(), raw)


def m_lower_hex(raw):
    return _HEX_RE.sub(lambda mo: b"%" + mo.group(0)[1:].lower(), raw)


MUTATIONS = {
    "identity": m_identity,
    "encode_all_once": m_encode_all_once,
    "encode_path_specials": m_encode_path_specials,
    "double_encode": m_double_encode,
    "swap_backslash": m_swap_backslash,
    "mixed_separators": m_mixed_separators,
    "case_flip": m_case_flip,
    "append_slash": m_append_slash,
    "strip_slash": m_strip_slash,
    "insert_empty_segment": m_insert_empty_segment,
    "append_trailing_dot": m_append_trailing_dot,
    "dot_wrap": m_dot_wrap,
    "upper_hex": m_upper_hex,
    "lower_hex": m_lower_hex,
}
