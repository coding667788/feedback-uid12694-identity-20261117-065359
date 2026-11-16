"""路径规范化流水线。

固定顺序（不可调换）：
  1. 百分号解码（0/1/2 遍，逐遍重扫；不完整或非法转义明确拒绝）
  2. UTF-8 严格解码（非法序列明确拒绝）
  3. 分隔符转换（可选：反斜杠视为分隔符）
  4. 点段折叠（可选：丢弃内部空段与 '.'，解析 '..'；越过根目录明确拒绝；
     路径尾点即名字末尾的 '.' 不属于点段，原样保留）
  5. 大小写（可选：仅 ASCII A-Z 折叠为小写，保证一对一映射）
  6. 尾斜杠策略（keep / strip / ensure）

每个阶段都保留“原始字节区间 -> 规范化字符”的映射：
最终路径中每个字符携带 [start, end)（原字节偏移，半开区间），
由流水线合成的字符（如 ensure 追加的 '/'）映射为 null。
"""

from __future__ import annotations

E_INVALID_ESCAPE = "E_INVALID_ESCAPE"    # 百分号转义不完整或含非十六进制字符
E_INVALID_UTF8 = "E_INVALID_UTF8"        # UTF-8 严格解码失败
E_PATH_ABOVE_ROOT = "E_PATH_ABOVE_ROOT"  # '..' 越过根目录

_HEX_BYTES = set(b"0123456789abcdefABCDEF")  # int 集合

TRAILING_SLASH_CHOICES = ("keep", "strip", "ensure")
PERCENT_DECODE_CHOICES = (0, 1, 2)


class NormalizeError(Exception):
    def __init__(self, code, detail, offset=None):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.offset = offset


class Policy:
    """一侧（代理或后端）的规范化策略。五个维度即全部可调项。"""

    __slots__ = ("percent_decode", "backslash_separator", "dot_collapse",
                 "case_insensitive", "trailing_slash")

    def __init__(self, percent_decode=1, backslash_separator=False,
                 dot_collapse=True, case_insensitive=False, trailing_slash="keep"):
        if percent_decode not in PERCENT_DECODE_CHOICES:
            raise ValueError("percent_decode must be one of 0, 1, 2")
        if trailing_slash not in TRAILING_SLASH_CHOICES:
            raise ValueError("trailing_slash must be keep|strip|ensure")
        self.percent_decode = int(percent_decode)
        self.backslash_separator = bool(backslash_separator)
        self.dot_collapse = bool(dot_collapse)
        self.case_insensitive = bool(case_insensitive)
        self.trailing_slash = str(trailing_slash)

    def key(self):
        return (self.percent_decode, self.backslash_separator, self.dot_collapse,
                self.case_insensitive, self.trailing_slash)

    def as_dict(self):
        return {
            "percent_decode": self.percent_decode,
            "backslash_separator": self.backslash_separator,
            "dot_collapse": self.dot_collapse,
            "case_insensitive": self.case_insensitive,
            "trailing_slash": self.trailing_slash,
        }

    @classmethod
    def from_dict(cls, d):
        allowed = {"percent_decode", "backslash_separator", "dot_collapse",
                   "case_insensitive", "trailing_slash"}
        unknown = sorted(set(d) - allowed)
        if unknown:
            raise ValueError(f"unknown policy fields: {unknown}")
        return cls(**d)

    def __eq__(self, other):
        return isinstance(other, Policy) and self.key() == other.key()

    def __hash__(self):
        return hash(self.key())

    def __repr__(self):
        return f"Policy{self.key()!r}"


class _A:
    """一个中间字符/字节，携带其在原始输入字节中的来源区间 [s, e)。"""
    __slots__ = ("v", "s", "e")

    def __init__(self, v, s, e):
        self.v = v  # 字节阶段为 int(0..255)，字符阶段为 str(单字符)
        self.s = s
        self.e = e


def _stage(name, output, notes):
    return {"stage": name, "output": output, "notes": list(notes)}


def _bdisp(atoms):
    return "".join(chr(a.v) if 0x20 <= a.v < 0x7F else f"\\x{a.v:02x}" for a in atoms)


def _cdisp(chars):
    return "".join(a.v for a in chars)


def _percent_pass(atoms):
    """单遍百分号解码。'%' 后必须紧跟两个十六进制字符，否则拒绝。"""
    out, notes = [], []
    i, n = 0, len(atoms)
    while i < n:
        a = atoms[i]
        if a.v == 0x25:  # '%'
            if i + 2 > n - 1:
                raise NormalizeError(E_INVALID_ESCAPE, "incomplete percent escape", a.s)
            h1, h2 = atoms[i + 1], atoms[i + 2]
            if h1.v not in _HEX_BYTES or h2.v not in _HEX_BYTES:
                raise NormalizeError(E_INVALID_ESCAPE, "invalid percent escape", a.s)
            val = int(chr(h1.v) + chr(h2.v), 16)
            out.append(_A(val, a.s, h2.e))
            notes.append(f"offset {a.s}: %{chr(h1.v)}{chr(h2.v)} -> 0x{val:02x}")
            i += 3
        else:
            out.append(a)
            i += 1
    return out, notes


def _utf8_decode(atoms):
    """严格 UTF-8 解码；拒绝截断序列、非法续字节、过长编码、代理区与超界码点。"""
    out, notes = [], []
    i, n = 0, len(atoms)
    while i < n:
        b0 = atoms[i].v
        if b0 < 0x80:
            out.append(_A(chr(b0), atoms[i].s, atoms[i].e))
            i += 1
            continue
        if 0xC2 <= b0 <= 0xDF:
            need, cp = 1, b0 & 0x1F
        elif 0xE0 <= b0 <= 0xEF:
            need, cp = 2, b0 & 0x0F
        elif 0xF0 <= b0 <= 0xF4:
            need, cp = 3, b0 & 0x07
        else:
            raise NormalizeError(E_INVALID_UTF8, f"invalid lead byte 0x{b0:02x}", atoms[i].s)
        if i + need > n - 1:
            raise NormalizeError(E_INVALID_UTF8, "truncated multi-byte sequence", atoms[i].s)
        parts = atoms[i:i + need + 1]
        for k in range(1, need + 1):
            v = parts[k].v
            if not (0x80 <= v <= 0xBF):
                raise NormalizeError(E_INVALID_UTF8,
                                     f"invalid continuation byte 0x{v:02x}", parts[k].s)
            cp = (cp << 6) | (v & 0x3F)
        if (need == 1 and cp < 0x80) or (need == 2 and cp < 0x800) \
                or (need == 3 and cp < 0x10000):
            raise NormalizeError(E_INVALID_UTF8, "overlong encoding", parts[0].s)
        if 0xD800 <= cp <= 0xDFFF or cp > 0x10FFFF:
            raise NormalizeError(E_INVALID_UTF8, f"invalid code point U+{cp:04X}", parts[0].s)
        out.append(_A(chr(cp), parts[0].s, parts[-1].e))
        notes.append(f"offset {parts[0].s}: {need + 1} bytes -> U+{cp:04X}")
        i += need + 1
    return out, notes


def _dot_collapse(chars):
    """点段折叠：丢弃内部空段与 '.'，解析 '..'；越根拒绝；尾点（如 'b.'）保留。"""
    notes = []
    # 切分为 token：('slash', atom) 或 ('seg', [atoms])；相邻 '//' 之间补一个空段 token
    tokens, buf = [], []
    prev_slash = False
    for a in chars:
        if a.v == "/":
            if buf:
                tokens.append(("seg", buf))
                buf = []
            elif prev_slash:
                tokens.append(("seg", []))
            tokens.append(("slash", a))
            prev_slash = True
        else:
            buf.append(a)
            prev_slash = False
    if buf:
        tokens.append(("seg", buf))

    out = []
    drop_next_slash = False
    m = len(tokens)
    for ti, tok in enumerate(tokens):
        last = ti == m - 1
        if tok[0] == "slash":
            if drop_next_slash:
                drop_next_slash = False
                continue
            out.append(tok)
            continue
        text = "".join(a.v for a in tok[1])
        if text == "" or text == ".":
            notes.append(f"dropped {'empty' if text == '' else '.'} segment")
            if out and out[-1][0] == "slash":
                out.pop()
            else:
                drop_next_slash = True
            if last and (not out or out[-1][0] != "slash"):
                out.append(("slash", _A("/", None, None)))
            continue
        if text == "..":
            idx = None
            for k in range(len(out) - 1, -1, -1):
                if out[k][0] == "seg":
                    idx = k
                    break
            if idx is None:
                raise NormalizeError(E_PATH_ABOVE_ROOT, "'..' segment escapes above root")
            del out[idx]
            if idx < len(out) and out[idx][0] == "slash":
                del out[idx]
            elif idx - 1 >= 0 and out[idx - 1][0] == "slash":
                del out[idx - 1]
            notes.append("resolved '..' segment")
            if last:
                if not out or out[-1][0] != "slash":
                    out.append(("slash", _A("/", None, None)))
            else:
                drop_next_slash = True
            continue
        out.append(tok)

    new_chars = []
    for tok in out:
        if tok[0] == "slash":
            new_chars.append(tok[1])
        else:
            new_chars.extend(tok[1])
    return new_chars, notes


def normalize(raw: bytes, policy: Policy) -> dict:
    """按固定顺序执行规范化，返回完整转换链与映射；失败时返回错误码。"""
    stages = []
    atoms = [_A(b, i, i + 1) for i, b in enumerate(raw)]
    try:
        # 1) 百分号解码
        if policy.percent_decode == 0:
            stages.append(_stage("percent_decode", _bdisp(atoms),
                                 ["skipped: percent_decode=0"]))
        for p in range(policy.percent_decode):
            atoms, notes = _percent_pass(atoms)
            stages.append(_stage(f"percent_decode[{p + 1}/{policy.percent_decode}]",
                                 _bdisp(atoms), notes or ["no escapes"]))
        # 2) UTF-8 解码
        chars, notes = _utf8_decode(atoms)
        stages.append(_stage("utf8_decode", _cdisp(chars), notes or ["all ASCII"]))
        # 3) 分隔符转换
        if policy.backslash_separator:
            cnt = 0
            for a in chars:
                if a.v == "\\":
                    a.v = "/"
                    cnt += 1
            stages.append(_stage("separator", _cdisp(chars),
                                 [f"converted {cnt} backslash(es) to '/'"]
                                 if cnt else ["no backslash present"]))
        else:
            stages.append(_stage("separator", _cdisp(chars),
                                 ["skipped: backslash_separator=false"]))
        # 4) 点段折叠
        if policy.dot_collapse:
            chars, notes = _dot_collapse(chars)
            stages.append(_stage("dot_collapse", _cdisp(chars),
                                 notes or ["nothing to collapse"]))
        else:
            stages.append(_stage("dot_collapse", _cdisp(chars),
                                 ["skipped: dot_collapse=false"]))
        # 5) 大小写
        if policy.case_insensitive:
            cnt = 0
            for a in chars:
                if "A" <= a.v <= "Z":
                    a.v = a.v.lower()
                    cnt += 1
            stages.append(_stage("case", _cdisp(chars),
                                 [f"lowered {cnt} ASCII letter(s)"]
                                 if cnt else ["no ASCII uppercase present"]))
        else:
            stages.append(_stage("case", _cdisp(chars),
                                 ["skipped: case_insensitive=false"]))
        # 6) 尾斜杠
        if policy.trailing_slash == "strip":
            if len(chars) > 1 and chars[-1].v == "/":
                chars.pop()
                notes = ["stripped trailing '/'"]
            else:
                notes = ["no trailing slash to strip"]
        elif policy.trailing_slash == "ensure":
            if not chars or chars[-1].v != "/":
                chars.append(_A("/", None, None))
                notes = ["appended synthetic trailing '/'"]
            else:
                notes = ["trailing slash already present"]
        else:
            notes = ["kept as-is"]
        stages.append(_stage("trailing_slash", _cdisp(chars), notes))

        path = "".join(a.v for a in chars)
        segs = path.split("/")
        return {
            "ok": True,
            "path": path,
            "segments": segs,
            "match_segments": segs[1:] if path.startswith("/") else segs,
            "mapping": [[a.s, a.e] if a.s is not None else None for a in chars],
            "stages": stages,
            "error": None,
            "detail": None,
        }
    except NormalizeError as e:
        detail = e.detail if e.offset is None else f"{e.detail} (byte offset {e.offset})"
        return {
            "ok": False,
            "path": None,
            "segments": None,
            "match_segments": None,
            "mapping": None,
            "stages": stages,
            "error": e.code,
            "detail": detail,
        }
