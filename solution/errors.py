"""输入侧（cases.json）错误码。

规范化阶段的逐候选错误码（E_INVALID_ESCAPE / E_INVALID_UTF8 / E_PATH_ABOVE_ROOT）
定义在 normalize.py 中，作为数据记录在结果里，不会中断审计。
下列错误码属于输入/装载错误，CLI 以退出码 2 终止。
"""

E_SCHEMA = "E_SCHEMA"                # cases.json 结构或字段非法
E_IO = "E_IO"                        # 输入文件或引用样例读取失败
E_UNKNOWN_MUTATION = "E_UNKNOWN_MUTATION"  # 声明了变换库中不存在的变换名
E_BAD_POLICY = "E_BAD_POLICY"        # 规范化策略字段非法


class CaseError(Exception):
    """输入用例错误：携带稳定错误码，CLI 捕获后以退出码 2 结束。"""

    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
