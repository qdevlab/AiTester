"""llamator как модуль-вектор (обёртка софта): движок tool_wrappers/llamator -> наш report_std.

is_wrapper=True -> входит в a-all, выпадает из a-all-nowrapper. Зовётся a-llamator.
У llamator нет CLI -> движок гоняет раннер-скрипт в .venv-llamator (adapters/llamator_runner.py).
Red-team чата: system_prompt_leakage / sycophancy / logical_inconsistencies.
"""

from .._toolbase import ToolVector
from ...tool_wrappers.llamator import LlamatorWrapper


class LlamatorVector(ToolVector):
    name = "llamator"
    title = "llamator — red-team чата: leak/sycophancy/logic (внешний атакующий модуль)"
    taxonomy = {"owasp_asi": "System Prompt Leakage / Manipulation",
                "owasp_llm": "LLM07 System Prompt Leakage"}
    hypotheses = ("H-llamator-chat",)
    WRAPPER = LlamatorWrapper
    ARG_KEYS = ("attacker", "attacker_temperature", "caller_cus",
                "timeout_s", "llm_report", "skip_clean")
