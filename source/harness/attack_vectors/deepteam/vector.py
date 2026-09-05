"""deepteam как модуль-вектор (обёртка софта): движок tool_wrappers/deepteam -> наш report_std.

is_wrapper=True -> входит в a-all, выпадает из a-all-nowrapper. Зовётся a-deepteam.
Наводит deepteam на цель через callback-файл; симулятор/судья — наш OpenRouter.
"""

from .._toolbase import ToolVector
from ...tool_wrappers.deepteam import DeepteamWrapper


class DeepteamVector(ToolVector):
    name = "deepteam"
    title = "deepteam — red-team агентских уязвимостей (внешняя тула)"
    taxonomy = {"owasp_asi": "Excessive Agency / Tool Misuse", "owasp_llm": "LLM06 Excessive Agency"}
    hypotheses = ("H-deepteam-agentic",)
    WRAPPER = DeepteamWrapper
    ARG_KEYS = ("attacks_per_vuln", "simulator", "evaluation", "simulator_temperature",
                "caller_cus", "timeout_s", "llm_report", "skip_clean")
