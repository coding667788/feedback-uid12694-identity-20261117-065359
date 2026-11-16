# 离线路由审计器（路径规范化差异的越权差分检测）

针对反向代理与后端之间**路径归一化差异**的离线审计工具。输入两套显式路径
转换规则（代理侧、后端侧）与请求样本，枚举有限的变换组合，找出“代理判为
public 而后端落入 private”的最短越权见证，给出见证缩减结果与统一策略修复
建议。纯标准库实现，Python 3.12，无 Docker、无外部服务，全部操作局限在
项目目录内。

## 运行

```bash
python -m solution --input cases.json --output result.json
python -m unittest discover -s tests -v
```

可选参数 `--seed N`（默认 0）：仅作为重放种子记录在输出中；审计过程本身
完全确定，同一输入必然产生逐字节相同的输出。

退出码：

| 退出码 | 含义 |
|---|---|
| 0 | 审计完成（是否发现越权属于数据，不影响退出码） |
| 2 | 输入用例错误（E_SCHEMA / E_IO / E_UNKNOWN_MUTATION / E_BAD_POLICY） |
| 3 | 未预期的内部错误（E_INTERNAL） |

## 目录结构

```
solution/            源代码包
  __main__.py        CLI 入口
  normalize.py       固定顺序的规范化流水线（保留字节->字符映射）
  classify.py        完整路径段的最长前缀规则匹配
  mutations.py       作用于种子的有限声明式变换库
  audit.py           差分审计主流程
  minimize.py        见证缩减
  fix.py             统一策略修复建议（枚举 72 种策略并验证）
  errors.py          输入侧错误码
cases.json           样例输入（覆盖全部验收场景）
samples/             被 cases.json 引用的样例（文本种子 + 非法 UTF-8 二进制）
tests/               自动化测试（断言具体结果/状态/证据）
result.json          样例输出（由上述命令生成）
```

## 规范化流水线（normalize）

五个可调维度，除此之外无其他规则项：

| 维度 | 取值 |
|---|---|
| `percent_decode` | 0 / 1 / 2（百分号解码遍数） |
| `backslash_separator` | true / false（反斜杠是否视为分隔符） |
| `dot_collapse` | true / false（点段折叠） |
| `case_insensitive` | true / false（大小写是否敏感） |
| `trailing_slash` | keep / strip / ensure（尾斜杠策略） |

变换按**固定顺序**执行，不可调换：

1. **百分号解码**：逐遍重扫；`%` 后不是两个十六进制字符即拒绝
   （`E_INVALID_ESCAPE`）。`percent_decode=0` 时不校验转义。
2. **UTF-8 严格解码**：截断序列、非法续字节、过长编码、代理区与超界码点
   均拒绝（`E_INVALID_UTF8`）。
3. **分隔符转换**：开启时把 `\` 改写为 `/`。
4. **点段折叠**：开启时丢弃内部空段与 `.` 段、解析 `..`；`..` 越过根目录
   拒绝（`E_PATH_ABOVE_ROOT`）。**路径尾点保留**：`b.` 这类名字末尾的点
   不是点段，原样保留。尾部的 `.`/`..` 解析后保留尾斜杠（`/a/.` → `/a/`）。
5. **大小写**：开启时仅折叠 ASCII `A-Z`（保证一对一映射）。
6. **尾斜杠**：`strip` 去掉根以外的尾 `/`；`ensure` 追加合成的 `/`；
   `keep` 不动。

**映射**：最终路径中每个字符携带其在原始输入字节中的来源区间
`[start, end)`；流水线合成的字符（如 `ensure` 追加的 `/`）映射为 `null`。
结果中 `mapping` 与最终路径逐字符对齐，每个阶段同时在 `stages` 中记录
输出与备注，构成完整转换链。

## 规则匹配（classify）

- 规则前缀视为**已规范化**的字面路径，按 `/` 切段后与规范化路径按
  **完整路径段**逐一比较：`/pub` 不匹配段 `public`，`//private` 的首个
  空段会阻断 `/private` 的匹配。
- 段数最多的规则胜出（最长前缀）；段数相同则先声明的胜出；无匹配回落到
  该侧默认动作（`default_action` / `default_zone`）。

## 差分审计（audit）

对 `种子 × mutations` 的有限组合逐一评估：

| 结果 | 判定 |
|---|---|
| `violation` | 两侧均接受，且代理判 `public`、后端落入 `private` |
| `divergence` | 两侧均接受但规范化路径不同，且非越权（反例归此类） |
| `agreement` | 两侧均接受且路径相同 |
| `rejected` | 任一侧拒绝（记录错误码；拒绝视为安全，不计越权） |

**最短见证**：先按 (字节长度, 字节序) 对全部越权候选排序取最小者
（`shortest_witness`），再对每个见证做**缩减**（`minimized`）：尝试把
`%XX` 解码为可打印字面量、折叠 `//`、去尾斜杠、转义十六进制小写化，
仅采纳**重新验证后仍构成越权**且更小的候选，迭代至收敛。越权证据必须
是两侧分类结论的真实分歧（带各自命中的规则 ID 与完整转换链），不接受
仅字符串不同。

## 修复建议（fix）

枚举全部 3×2×2×2×3 = **72** 种统一策略，逐一验证：

1. **消除全部已知越权**：两侧都改用该策略后，已评估的全部候选中不再
   出现“代理 public 且后端 private”（任一侧拒绝视为安全）；
2. **保留正常路由集合**：每条 `normal_routes` 在统一策略下，代理动作与
   后端区域仍等于声明的期望值。

通过两项验证的策略按（与代理现策略的差异维度数, 策略元组序）排序，取
首个为 `recommended`；无通过项时 `recommended` 为 `null`。

## cases.json 输入 schema

```jsonc
{
  "version": 1,                      // 必填，固定为 1
  "proxy": {
    "policy": { /* 五个维度，缺省用 normalize 默认值 */ },
    "acl": [ {"id": "PUB", "prefix": "/public", "action": "public"} ],
    "default_action": "public"       // public|private，缺省 private
  },
  "backend": {
    "policy": { /* 同上 */ },
    "zones": [ {"id": "ZPRIV", "prefix": "/private", "zone": "private"} ],
    "default_zone": "public"         // public|private，缺省 private
  },
  "seeds": [                         // 非空；三种形式任选
    {"id": "s1", "raw": "/a/%2e"},   // 字面字符串（按 UTF-8 编码为字节）
    {"id": "s2", "raw_b64": "L2E="}, // base64 原始字节
    {"id": "s3", "file": "samples/seed_file.txt"}  // 项目内文件（文本或二进制）
  ],
  "mutations": ["identity", "double_encode"],  // 缺省 ["identity"]
  "normal_routes": [                 // 可空
    {"id": "n1", "raw": "/public/index.html",
     "expect_proxy": "public", "expect_backend": "public"}
  ]
}
```

可用变换名（`solution/mutations.py`）：`identity`、`encode_all_once`、
`encode_path_specials`、`double_encode`、`swap_backslash`、
`mixed_separators`、`case_flip`、`append_slash`、`strip_slash`、
`insert_empty_segment`、`append_trailing_dot`、`dot_wrap`、`upper_hex`、
`lower_hex`。

## result.json 输出 schema

```jsonc
{
  "schema_version": 1,
  "seed": 0,
  "policies": {"proxy": {...}, "backend": {...}},
  "summary": {"seeds": 11, "mutations": 14, "candidates": 154,
              "violations": 74, "divergences": 43, "agreements": 9,
              "rejected": 28},
  "shortest_witness": { /* 见下，无越权时为 null */ },
  "violations": [ {
      "seed_id", "mutation", "raw_b64", "raw_display", "length",
      "proxy":   {"ok", "path", "action", "rule_id", "matched_prefix",
                  "stages": [...], "mapping": [...]},
      "backend": {"ok", "path", "zone", "rule_id", ...},
      "minimized": {"raw_b64", "raw_display", "length",
                    "proxy": {...完整链...}, "backend": {...完整链...}}
  } ],                               // 按 (字节长度, 字节序) 升序
  "divergences": [ {"seed_id", "mutation", "raw_display",
                    "proxy": {"path", "action", "rule_id"},
                    "backend": {"path", "zone", "rule_id"},
                    "authorization_equivalent": true} ],
  "rejected": [ {"seed_id", "mutation", "raw_display",
                 "proxy_error", "backend_error", "detail"} ],
  "normal_routes": [ {"id", "expect_proxy", "expect_backend",
                      "actual_proxy", "actual_backend",
                      "proxy_rule_id", "backend_rule_id", "preserved"} ],
  "fix": {"policies_evaluated": 72, "passing_count": 72,
          "passing": [...], "recommended": {...} | null,
          "distance_from_proxy": 0,
          "eliminates_all_known_violations": true,
          "preserves_normal_routes": true,
          "checked_candidates": 154, "checked_normal_routes": 4}
}
```

## 错误码一览

| 错误码 | 层面 | 含义 |
|---|---|---|
| `E_INVALID_ESCAPE` | 候选（数据） | 百分号转义不完整或含非十六进制字符 |
| `E_INVALID_UTF8` | 候选（数据） | UTF-8 严格解码失败 |
| `E_PATH_ABOVE_ROOT` | 候选（数据） | `..` 越过根目录 |
| `E_SCHEMA` | 输入（退出码 2） | cases.json 结构或字段非法 |
| `E_IO` | 输入（退出码 2） | 输入文件或引用样例读取失败 |
| `E_UNKNOWN_MUTATION` | 输入（退出码 2） | 声明了不存在的变换名 |
| `E_BAD_POLICY` | 输入（退出码 2） | 策略字段非法 |
| `E_INTERNAL` | 运行（退出码 3） | 未预期的内部错误 |

## 样例对验收场景的覆盖

| 场景 | 种子 | 现象 |
|---|---|---|
| 双重编码 | `s-double` | 代理解 1 遍看到 `%2e%2e%2f`，后端解 2 遍得到 `../` 并落入 `/private` |
| 混合分隔符 | `s-mixed-sep` | 代理不折叠 `\`，后端视为分隔符后解析 `..` |
| 空段 | `s-empty` | `//private/secret`：代理首段为空不匹配，后端折叠空段后命中 |
| 大小写 + 点段 | `s-case-dot` | 代理大小写敏感且不折叠，后端折叠并小写化后命中 |
| 尾点保留（非漏洞） | `s-trailing-dot` | `/private/secret.` 两侧都判 private，不产生越权 |
| 反例（授权等价） | `s-counter` | 规范化结果不同但都判 public，只进 divergences |
| 越根拒绝 | `s-above-root` | 后端 `E_PATH_ABOVE_ROOT`，记 rejected |
| 非法 UTF-8 | `s-utf8-bad`（二进制样例） | `E_INVALID_UTF8`，记 rejected |
| 文件引用种子 | `s-file` | 引用 `samples/seed_file.txt` |

## 设计说明（题面未指明处的取舍）

- 规则前缀按“已规范化”字面路径处理，不再经过流水线；
- 大小写折叠仅 ASCII，保证映射一对一；
- 点段折叠开启时同时丢弃**内部**空段（`//a//b` → `/a/b`），尾部空段
  （尾斜杠）保留给尾斜杠策略处理；
- 任一侧拒绝即视为安全，不计越权；
- 最短见证按“种子经声明变换后的原始字节”的 (长度, 字节序) 排序；
  缩减是在此之上进一步收缩，缩减结果单独报告；
- 审计全程无随机性，`--seed` 仅作重放标记记录。
